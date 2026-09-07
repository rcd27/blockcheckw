use crate::error::BlockcheckError;
use crate::firewall::nft::{NftBatch, NftRun, OwnedTable, OwnedTableMarker};
use crate::network::dns::is_ipv4;
use crate::nfqws2::dispatch::Dispatch;
use crate::nfqws2::mark::DESYNC_MARK;
use crate::nfqws2::run::Ready;
use tracing::warn;

/// Validate and join IPs for nftables set. Rejects malformed IPs to prevent nft injection.
///
/// Пустое множество тоже отвергаем: `ip daddr {  }` (пустые фигурные скобки) —
/// синтаксическая ошибка nft, а не пустое множество. Без этой проверки отказ
/// был бы парс-фейлом в чужом бинаре вместо внятной типизированной ошибки.
fn validate_ip_set(ips: &[String]) -> Result<String, BlockcheckError> {
    if ips.is_empty() {
        return Err(BlockcheckError::Nftables {
            command: "validate ip set".to_string(),
            stderr: "empty IP set: nft would reject `{ }` as a syntax error".to_string(),
        });
    }
    for ip in ips {
        if !is_ipv4(ip) {
            return Err(BlockcheckError::Nftables {
                command: "validate ip set".to_string(),
                stderr: format!("invalid IPv4 address: {ip}"),
            });
        }
    }
    Ok(ips.join(", "))
}

const CHAIN_POSTNAT: &str = "postnat";
const CHAIN_PREDEFRAG: &str = "predefrag";
const CHAIN_PRENAT: &str = "prenat";

pub async fn prepare_table<R: NftRun>(
    runner: &R,
    name: &str,
) -> Result<OwnedTable, BlockcheckError> {
    let leading = vec![
        format!("add table inet {name}"),
        format!("delete table inet {name}"),
    ];

    let desync = format!("0x{DESYNC_MARK:08X}");
    let trailing = vec![
        format!("add chain inet {name} {CHAIN_POSTNAT} {{ type filter hook postrouting priority 102; }}"),
        format!("add chain inet {name} {CHAIN_PREDEFRAG} {{ type filter hook output priority -402; }}"),
        format!("add rule inet {name} {CHAIN_PREDEFRAG} meta nfproto ipv4 mark and {desync} != 0 notrack"),
        format!("add chain inet {name} {CHAIN_PRENAT} {{ type filter hook prerouting priority -102; }}"),
        format!("add rule inet {name} {CHAIN_PRENAT} icmp type time-exceeded ct mark and {desync} != 0 drop"),
        format!("add rule inet {name} {CHAIN_PRENAT} icmp type time-exceeded ct state invalid drop"),
    ];

    OwnedTable::create_with(runner, name, leading, trailing).await
}

pub async fn apply_dispatch<R: NftRun>(
    runner: &R,
    table: &OwnedTable,
    ready: &Ready,
    d: &Dispatch,
    ips: &[String],
) -> Result<(), BlockcheckError> {
    if ready.queue() != d.queue {
        return Err(BlockcheckError::QueueWitnessMismatch {
            witnessed: ready.queue().get(),
            requested: d.queue.get(),
        });
    }
    let ip_set = validate_ip_set(ips)?;
    let t = table.name();
    let (q, port) = (d.queue.get(), d.dport);
    runner
        .run(NftBatch::from_lines(vec![
            format!(
                "add rule inet {t} {CHAIN_POSTNAT} meta nfproto ipv4 tcp dport {port} \
                 mark and 0x{:08X} == 0 mark and 0x{:08X} == 0x{:08X} ip daddr {{ {ip_set} }} \
                 ct mark set mark or 0x{:08X} queue num {q}",
                d.out.require_clear, d.out.require_set, d.out.require_set, d.out.ct_set_or
            ),
            format!(
                "add rule inet {t} {CHAIN_PRENAT} meta nfproto ipv4 tcp sport {port} \
                 tcp flags & (syn | ack) == (syn | ack) ct mark and 0x{:08X} == 0x{:08X} \
                 ip saddr {{ {ip_set} }} meta mark set ct mark and 0x{:08X} queue num {q}",
                d.inc.ct_require_set, d.inc.ct_require_set, d.inc.mark_from_ct_and
            ),
        ]))
        .await
}

pub async fn drop_table<R: NftRun>(runner: &R, marker: &OwnedTableMarker) {
    let _ = runner.run(marker.drop_batch()).await;
}

pub async fn remove_dispatch<R: NftRun>(runner: &R, table: &OwnedTable) {
    let t = table.name();
    let desync = format!("0x{DESYNC_MARK:08X}");
    if let Err(e) = runner
        .run(NftBatch::from_lines(vec![
            format!("flush chain inet {t} {CHAIN_POSTNAT}"),
            format!("flush chain inet {t} {CHAIN_PRENAT}"),
            format!("add rule inet {t} {CHAIN_PRENAT} icmp type time-exceeded ct mark and {desync} != 0 drop"),
            format!("add rule inet {t} {CHAIN_PRENAT} icmp type time-exceeded ct state invalid drop"),
        ]))
        .await
    {
        warn!(table = t, error = %e, "remove_dispatch failed: dispatch rules for the previous plan may still be in the ruleset");
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use crate::firewall::nft::testing::RecordingNft;
    use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};

    async fn rendered(dport: u16) -> Vec<String> {
        let nft = RecordingNft::default();
        let table = OwnedTable::create(&nft, "bcw_test").await.unwrap();
        // Три профиля, не один: дисциплина «два правила на весь план, а не
        // на профиль» иначе не отличима от «два правила на один профиль» —
        // e2e-двойник (`tests/e2e_infra.rs::nft_dispatch_add_remove_rules_on_real_kernel`)
        // тоже строит план из трёх.
        let plan = Plan::from_strategies(
            &FilterMark::granted(),
            QueueNum::new(200),
            &[
                vec!["--a".to_string()],
                vec!["--b".to_string()],
                vec!["--c".to_string()],
            ],
        );
        let ready = Ready::witnessed(QueueNum::new(200));
        apply_dispatch(
            &nft,
            &table,
            &ready,
            &plan.dispatch(dport),
            &["1.2.3.4".to_string()],
        )
        .await
        .unwrap();
        nft.commands()
    }

    /// Два правила на весь план — вместо K цепочек и 2K элементов карт.
    #[tokio::test]
    async fn dispatch_is_exactly_two_rules() {
        let cmds = rendered(443).await;
        let rules: Vec<&String> = cmds.iter().filter(|c| c.starts_with("add rule")).collect();
        assert_eq!(rules.len(), 2, "{cmds:?}");
    }

    /// Ловушка §4 на уровне отрендеренного правила: маска обязана быть 0x2000FFFF.
    #[tokio::test]
    async fn the_incoming_rule_restores_the_mark_under_the_safe_mask() {
        let cmds = rendered(443).await;
        assert!(
            cmds.iter()
                .any(|c| c.contains("meta mark set ct mark and 0x2000FFFF")),
            "{cmds:?}"
        );
    }

    /// ct mark выводится из марки пакета — значит правил на профиль не нужно.
    #[tokio::test]
    async fn the_outgoing_rule_derives_ct_mark_from_the_packet_mark() {
        let cmds = rendered(443).await;
        assert!(
            cmds.iter()
                .any(|c| c.contains("ct mark set mark or 0x10000000")),
            "{cmds:?}"
        );
    }

    /// Карт и цепочек воркеров больше не существует — вместе с гонкой #66.
    /// Проверяет именно `prepare_table`: карты создавала она, а не
    /// `apply_dispatch`, у которого их отродясь не было.
    #[tokio::test]
    async fn no_vmaps_and_no_per_worker_chains_remain() {
        let nft = RecordingNft::default();
        let table = prepare_table(&nft, "bcw_test").await.unwrap();
        let plan = Plan::from_strategies(
            &FilterMark::granted(),
            QueueNum::new(200),
            &[vec!["--a".to_string()]],
        );
        let ready = Ready::witnessed(QueueNum::new(200));
        apply_dispatch(
            &nft,
            &table,
            &ready,
            &plan.dispatch(443),
            &["1.2.3.4".to_string()],
        )
        .await
        .unwrap();

        for c in nft.commands() {
            assert!(!c.contains("add map"), "осталась карта: {c}");
            assert!(!c.contains("qmap"), "остался vmap: {c}");
            assert!(
                !c.contains("wp_") && !c.contains("wi_"),
                "осталась цепочка: {c}"
            );
        }
    }

    #[tokio::test]
    async fn remove_dispatch_flushes_and_leaves_exactly_two_icmp_rules() {
        let nft = RecordingNft::default();
        let table = prepare_table(&nft, "bcw_test").await.unwrap();
        let plan = Plan::from_strategies(
            &FilterMark::granted(),
            QueueNum::new(200),
            &[vec!["--a".to_string()]],
        );
        let ready = Ready::witnessed(QueueNum::new(200));
        apply_dispatch(
            &nft,
            &table,
            &ready,
            &plan.dispatch(443),
            &["1.2.3.4".to_string()],
        )
        .await
        .unwrap();

        remove_dispatch(&nft, &table).await;

        let txs = nft.transactions();
        let last = txs.last().expect("remove_dispatch отправил транзакцию");
        let lines = last.lines();
        assert!(
            lines
                .iter()
                .any(|c| c == &format!("flush chain inet bcw_test {CHAIN_POSTNAT}")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|c| c == &format!("flush chain inet bcw_test {CHAIN_PRENAT}")),
            "{lines:?}"
        );
        let icmp: Vec<&String> = lines
            .iter()
            .filter(|c| c.contains("icmp type time-exceeded"))
            .collect();
        assert_eq!(icmp.len(), 2, "{lines:?}");
    }

    /// Мусорный IP не должен доехать до nft.
    #[tokio::test]
    async fn malformed_ips_are_rejected_before_reaching_nft() {
        let nft = RecordingNft::default();
        let table = OwnedTable::create(&nft, "bcw_test").await.unwrap();
        let plan = Plan::from_strategies(
            &FilterMark::granted(),
            QueueNum::new(200),
            &[vec!["--a".to_string()]],
        );
        let ready = Ready::witnessed(QueueNum::new(200));
        let bad = vec!["1.2.3.4; drop table inet fw4".to_string()];
        assert!(
            apply_dispatch(&nft, &table, &ready, &plan.dispatch(443), &bad)
                .await
                .is_err()
        );
        assert!(
            nft.commands().iter().all(|c| !c.starts_with("add rule")),
            "мусорный IP не должен доехать до nft ни в одном правиле"
        );
    }

    /// Свидетельство, выданное одной очереди, не годится правилам для другой:
    /// слушатель был бы, но не там, и порт ушёл бы в дроп целиком.
    #[tokio::test]
    async fn a_witness_for_another_queue_is_refused() {
        let nft = RecordingNft::default();
        let table = OwnedTable::create(&nft, "bcw_test").await.unwrap();
        let plan = Plan::from_strategies(
            &FilterMark::granted(),
            QueueNum::new(200),
            &[vec!["--a".to_string()]],
        );
        let ready_for_another = Ready::witnessed(QueueNum::new(201));
        let err = apply_dispatch(
            &nft,
            &table,
            &ready_for_another,
            &plan.dispatch(443),
            &["1.2.3.4".to_string()],
        )
        .await
        .expect_err("свидетельство чужой очереди обязано быть отвергнуто");
        assert!(matches!(err, BlockcheckError::QueueWitnessMismatch { .. }));
        assert_eq!(
            nft.transactions().len(),
            1,
            "отвергнутая заявка не должна породить вторую транзакцию — \
             только та, что создала таблицу"
        );
    }
}

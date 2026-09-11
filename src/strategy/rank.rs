// Strategy ranking.
//
// If coverage metadata is present (from universal scan), strategies are sorted
// by coverage descending first — a strategy that works on 9/10 domains is more
// valuable than a simpler one that works on 1/10.
//
// Within the same coverage (or without coverage), strategies are sorted by
// structural simplicity: fewer desync actions → fewer repeats →
// single-stage before multi-stage.

use super::generator::TaggedStrategy;
use crate::pipeline::fate::{Admits, Fate};

/// Sort tagged strategies: coverage descending, then simplicity ascending.
pub fn sort_by_simplicity(strategies: &mut [TaggedStrategy]) {
    strategies.sort_by(|a, b| {
        // Higher coverage first
        b.coverage.cmp(&a.coverage).then_with(|| {
            let aj = a.args.join(" ");
            let bj = b.args.join(" ");
            simplicity_key(&aj).cmp(&simplicity_key(&bj))
        })
    });
}

/// Строка для ранжирования (спека §6-тер): частота полной доставки, медиана доли,
/// круг судеб (побочная ось — только она даёт `Mirage`), прежний структурный ключ.
#[derive(Debug, Clone)]
pub struct Ranked {
    /// (сколько раз доставка была полной, из скольких мерили) — `passes_ok`/`passes_total`.
    /// `(0, 0)` — не мерили вовсе; такая строка в ранг попадать не должна (см.
    /// `observed_at_all` в `pipeline/check.rs`), но `delivery_rate` не паникует и на ней.
    pub full_delivery: (usize, usize),
    /// `None` — эталона объёма нет, доли не существует (спека §6-тер, решение 2).
    pub median_share: Option<f64>,
    pub admits: Admits,
    pub simplicity: (usize, u32, bool),
}

/// Ступень круга — чем уже и лучше круг, тем ниже число. Несуженный круг НЕ равен
/// плохому: он равен «не знаем», и потому стоит ниже доказанного `Good`, но выше
/// доказанного `Mirage`.
fn step(admits: Admits) -> u8 {
    match admits.0 {
        [Fate::Good] => 0,
        [Fate::Grinding] => 1,
        circle if circle.contains(&Fate::Good) => 2, // не сузили
        [Fate::Mirage] => 3,
        [Fate::Trap] => 4,
        [Fate::Dead] => 5,
        _other => 6,
    }
}

/// Частота полной доставки как число: `M/M` больше, чем `2/3`. `0/0` («не мерили»)
/// читается как `0.0` — ниже всякого измеренного — а не как деление на ноль.
fn delivery_rate((ok, total): (usize, usize)) -> f64 {
    if total == 0 {
        0.0
    } else {
        ok as f64 / total as f64
    }
}

/// Ключ доли для сравнения: отсутствующая доля (нет эталона объёма) не смеет
/// обогнать измеренную — она ложится в самый низ, а не теряется как «равная нулю».
fn share_key(share: Option<f64>) -> f64 {
    share.unwrap_or(f64::NEG_INFINITY)
}

/// Порядок по судьбе (спека §6-тер): частота полной доставки ↓, медиана доли ↓,
/// ступень круга ↑ (`step`, не меняется), простота ↑ тай-брейкером.
pub fn sort_by_fate(rows: &mut [Ranked]) {
    rows.sort_by(fate_order);
}

/// Сравнение двух строк — то же, что в [`sort_by_fate`], но пригодное для сортировки
/// чужого вектора, где ранг едет рядом со своей полезной нагрузкой.
pub fn fate_order(a: &Ranked, b: &Ranked) -> std::cmp::Ordering {
    delivery_rate(b.full_delivery)
        .partial_cmp(&delivery_rate(a.full_delivery))
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| {
            share_key(b.median_share)
                .partial_cmp(&share_key(a.median_share))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| step(a.admits).cmp(&step(b.admits)))
        .then_with(|| a.simplicity.cmp(&b.simplicity))
}

/// Sort key: (action_count, max_repeats, is_multi_stage). Lower = simpler.
pub fn simplicity_key(joined: &str) -> (usize, u32, bool) {
    (
        count_desync_actions(joined),
        parse_max_repeats(joined),
        is_multi_stage(joined),
    )
}

fn count_desync_actions(joined: &str) -> usize {
    joined.matches("--lua-desync=").count()
}

fn parse_max_repeats(joined: &str) -> u32 {
    joined
        .split(':')
        .filter_map(|part| part.strip_prefix("repeats="))
        .filter_map(|val| val.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
}

fn is_multi_stage(joined: &str) -> bool {
    joined.contains("--payload=empty") && joined.contains("--out-range=")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Protocol;

    fn tagged(s: &str) -> TaggedStrategy {
        TaggedStrategy {
            protocol: Protocol::HttpsTls12,
            args: s.split_whitespace().map(String::from).collect(),
            coverage: 1,
        }
    }

    #[test]
    fn simple_before_complex() {
        let mut strategies = vec![
            // Complex: 3 actions + multi-stage
            tagged("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=5:repeats=1 --lua-desync=fakedsplit:pos=midsld:ip_ttl=5:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"),
            // Simple: 1 action, no repeats
            tagged("--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:tcp_ts=-1000"),
        ];

        sort_by_simplicity(&mut strategies);
        assert!(
            strategies[0].args.join(" ").contains("tcp_ts=-1000"),
            "simple should come first"
        );
    }

    #[test]
    fn low_repeats_before_high() {
        let mut strategies = vec![
            tagged("--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=260"),
            tagged("--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1"),
        ];

        sort_by_simplicity(&mut strategies);
        assert!(
            strategies[0].args.join(" ").contains("repeats=1"),
            "low repeats should come first"
        );
    }

    #[test]
    fn single_stage_before_multi_stage() {
        let mut strategies = vec![
            tagged("--payload=tls_client_hello --lua-desync=fake:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"),
            tagged("--payload=tls_client_hello --lua-desync=fake:repeats=1"),
        ];

        sort_by_simplicity(&mut strategies);
        assert!(
            !strategies[0].args.join(" ").contains("--payload=empty"),
            "single-stage should come first"
        );
    }

    fn ranked(admits: &'static [Fate], full_delivery: (usize, usize)) -> Ranked {
        Ranked {
            full_delivery,
            median_share: None,
            admits: Admits(admits),
            simplicity: (1, 0, false),
        }
    }

    #[test]
    fn частота_полной_доставки_сильнее_ступени_круга() {
        // M/M выше, чем 2/3 (спека §6-тер) — даже если её круг хуже.
        let mut rows = vec![
            ranked(&[Fate::Grinding], (2, 3)),
            ranked(&[Fate::Good], (3, 3)),
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].full_delivery, (3, 3));
    }

    #[test]
    fn нулевая_частота_не_паникует_и_идёт_последней() {
        let mut rows = vec![ranked(&[Fate::Good], (0, 0)), ranked(&[Fate::Good], (1, 1))];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].full_delivery, (1, 1));
    }

    #[test]
    fn при_равной_частоте_решает_медиана_доли() {
        let mut rows = vec![
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(0.4),
                admits: Admits(&[Fate::Good]),
                simplicity: (1, 0, false),
            },
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(0.9),
                admits: Admits(&[Fate::Good]),
                simplicity: (1, 0, false),
            },
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].median_share, Some(0.9));
    }

    #[test]
    fn отсутствующая_доля_не_обгоняет_измеренную() {
        // Нет эталона объёма — доли не существует (решение 2 спеки §6-тер), и такая
        // строка не смеет выглядеть лучше строки с честно измеренной долей.
        let mut rows = vec![
            Ranked {
                full_delivery: (3, 3),
                median_share: None,
                admits: Admits(&[Fate::Good]),
                simplicity: (1, 0, false),
            },
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(0.1),
                admits: Admits(&[Fate::Good]),
                simplicity: (1, 0, false),
            },
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].median_share, Some(0.1));
    }

    #[test]
    fn при_равной_частоте_и_доле_решает_ступень_круга() {
        let mut rows = vec![
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(1.0),
                admits: Admits(&[Fate::Grinding]),
                simplicity: (1, 0, false),
            },
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(1.0),
                admits: Admits(&[Fate::Good]),
                simplicity: (1, 0, false),
            },
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].admits.0, [Fate::Good].as_slice());
    }

    #[test]
    fn mirage_не_поднимается_выше_ничего_живого_при_равной_частоте() {
        let mut rows = vec![
            ranked(&[Fate::Mirage], (3, 3)),
            ranked(&[Fate::Grinding], (3, 3)),
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].admits.0, [Fate::Grinding].as_slice());
    }

    #[test]
    fn при_равной_частоте_доле_и_ступени_решает_простота() {
        let mut rows = vec![
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(1.0),
                admits: Admits(&[Fate::Good]),
                simplicity: (3, 20, true),
            },
            Ranked {
                full_delivery: (3, 3),
                median_share: Some(1.0),
                admits: Admits(&[Fate::Good]),
                simplicity: (1, 0, false),
            },
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].simplicity, (1, 0, false));
    }
}

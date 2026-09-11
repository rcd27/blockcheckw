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

/// Строка для ранжирования: круг судеб, чем заплачено, и прежний структурный ключ.
#[derive(Debug, Clone)]
pub struct Ranked {
    pub admits: Admits,
    pub waited_ms: u64,
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

/// Порядок по судьбе: ступень круга, затем ожидание, затем прежняя простота.
pub fn sort_by_fate(rows: &mut [Ranked]) {
    rows.sort_by(fate_order);
}

/// Сравнение двух строк — то же, что в [`sort_by_fate`], но пригодное для сортировки
/// чужого вектора, где ранг едет рядом со своей полезной нагрузкой.
pub fn fate_order(a: &Ranked, b: &Ranked) -> std::cmp::Ordering {
    step(a.admits)
        .cmp(&step(b.admits))
        .then_with(|| a.waited_ms.cmp(&b.waited_ms))
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

    fn ranked(admits: &'static [Fate], waited_ms: u64) -> Ranked {
        Ranked {
            admits: Admits(admits),
            waited_ms,
            simplicity: (1, 0, false),
        }
    }

    #[test]
    fn good_идёт_выше_grinding() {
        let mut rows = vec![ranked(&[Fate::Grinding], 100), ranked(&[Fate::Good], 5_000)];
        sort_by_fate(&mut rows);
        // Даже если Good ждал дольше: судьба сильнее темпа.
        assert_eq!(rows[0].admits.0, [Fate::Good].as_slice());
    }

    #[test]
    fn внутри_grinding_порядок_задаёт_ожидание() {
        let mut rows = vec![
            ranked(&[Fate::Grinding], 5_000),
            ranked(&[Fate::Grinding], 900),
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].waited_ms, 900);
    }

    #[test]
    fn несуженный_круг_ниже_суженного_до_good() {
        let mut rows = vec![
            ranked(&[Fate::Mirage, Fate::Grinding, Fate::Good], 100),
            ranked(&[Fate::Good], 100),
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].admits.0, [Fate::Good].as_slice());
    }

    #[test]
    fn mirage_не_поднимается_выше_ничего_живого() {
        let mut rows = vec![
            ranked(&[Fate::Mirage], 10),
            ranked(&[Fate::Grinding], 9_000),
        ];
        sort_by_fate(&mut rows);
        // Заглушка, отданная мгновенно, — не лучше настоящего ресурса, добытого долго.
        assert_eq!(rows[0].admits.0, [Fate::Grinding].as_slice());
    }

    #[test]
    fn при_равной_судьбе_и_равном_ожидании_решает_простота() {
        let mut rows = vec![
            Ranked {
                admits: Admits(&[Fate::Good]),
                waited_ms: 100,
                simplicity: (3, 20, true),
            },
            Ranked {
                admits: Admits(&[Fate::Good]),
                waited_ms: 100,
                simplicity: (1, 0, false),
            },
        ];
        sort_by_fate(&mut rows);
        assert_eq!(rows[0].simplicity, (1, 0, false));
    }
}

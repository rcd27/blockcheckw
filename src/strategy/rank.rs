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

/// Sort key: (action_count, max_repeats, is_multi_stage). Lower = simpler.
fn simplicity_key(joined: &str) -> (usize, u32, bool) {
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
}

// Strategy ranking — no subjective scoring.
//
// Strategies are sorted by structural simplicity (fewer actions, fewer
// repeats, no multi-stage). This is a deterministic ordering, not a
// quality judgement — actual quality assessment is deferred to the
// AI strategy selector (see TICKET-ai-strategy-selector.md).

pub struct StrategyScore {
    pub strategy_args: Vec<String>,
}

/// Sort strategies by structural simplicity: fewer desync actions first,
/// then fewer repeats, then no multi-stage before multi-stage.
pub fn rank_strategies(strategies: &[Vec<String>]) -> Vec<StrategyScore> {
    let mut indexed: Vec<(usize, &Vec<String>)> = strategies.iter().enumerate().collect();
    indexed.sort_by(|(_, a), (_, b)| {
        let aj = a.join(" ");
        let bj = b.join(" ");
        sort_key(&aj).cmp(&sort_key(&bj))
    });
    indexed
        .into_iter()
        .map(|(_, s)| StrategyScore {
            strategy_args: s.clone(),
        })
        .collect()
}

/// Sort key: (action_count, repeats, is_multi_stage). Lower = simpler.
fn sort_key(joined: &str) -> (usize, u32, bool) {
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
    let mut max_repeats = 0u32;
    for part in joined.split(':') {
        if let Some(val) = part.strip_prefix("repeats=") {
            if let Ok(n) = val.parse::<u32>() {
                max_repeats = max_repeats.max(n);
            }
        }
    }
    max_repeats
}

fn is_multi_stage(joined: &str) -> bool {
    joined.contains("--payload=empty") && joined.contains("--out-range=")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn ranking_simple_before_complex() {
        let strategies = vec![
            // Complex: 3 actions + multi-stage
            args("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=5:repeats=1 --lua-desync=fakedsplit:pos=midsld:ip_ttl=5:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"),
            // Simple: 1 action, no repeats
            args("--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:tcp_ts=-1000"),
        ];

        let ranked = rank_strategies(&strategies);
        assert_eq!(
            ranked[0].strategy_args, strategies[1],
            "simple should come first"
        );
    }

    #[test]
    fn ranking_low_repeats_before_high() {
        let strategies = vec![
            args("--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=260"),
            args("--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1"),
        ];

        let ranked = rank_strategies(&strategies);
        assert_eq!(
            ranked[0].strategy_args, strategies[1],
            "low repeats should come first"
        );
    }
}

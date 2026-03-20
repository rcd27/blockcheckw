// Strategy scoring and ranking.
//
// Strategies are ranked by practical value for the end user who already
// ran a scan on their hardware. Every strategy in the list WORKS — the
// question is which one is the best to deploy on a resource-constrained
// router.
//
// Two dimensions, equally weighted:
//   Performance (50%) — fewer packets = less load on router
//   Simplicity  (50%) — fewer components = more reliable, easier to debug

pub struct StrategyScore {
    pub strategy_args: Vec<String>,
    pub total: u32,
    pub performance: u32,
    pub simplicity: u32,
    pub stars: u8,
}

pub fn score_strategy(args: &[String]) -> StrategyScore {
    let joined = args.join(" ");

    let performance = score_performance(&joined);
    let simplicity = score_simplicity(&joined);

    let total = (performance as f64 * 0.50 + simplicity as f64 * 0.50) as u32;

    let stars = if total >= 80 {
        3
    } else if total >= 50 {
        2
    } else {
        1
    };

    StrategyScore {
        strategy_args: args.to_vec(),
        total,
        performance,
        simplicity,
        stars,
    }
}

pub fn rank_strategies(strategies: &[Vec<String>]) -> Vec<StrategyScore> {
    let mut scored: Vec<StrategyScore> = strategies.iter().map(|s| score_strategy(s)).collect();
    scored.sort_by(|a, b| b.total.cmp(&a.total));
    scored
}

// --- Performance (50%) ---
// Fewer packets = better for low-power routers.
// repeats=1 is best, high repeats or multi-stage is worst.

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

fn score_performance(joined: &str) -> u32 {
    let repeats = parse_max_repeats(joined);
    let multi = is_multi_stage(joined);

    match (repeats, multi) {
        (r, true) if r > 1 => 10,   // multi-stage + high repeats = worst
        (r, _) if r > 100 => 10,    // extreme repeats
        (r, _) if r > 20 => 30,     // high repeats
        (_, true) => 40,             // multi-stage with pktmod limiter
        (r, _) if r > 1 => 60,      // moderate repeats
        _ => 100,                    // repeats=0 or 1, no multi-stage
    }
}

// --- Simplicity (50%) ---
// Fewer desync actions = simpler, more reliable, easier to debug.

fn count_desync_actions(joined: &str) -> usize {
    joined.matches("--lua-desync=").count()
}

fn score_simplicity(joined: &str) -> u32 {
    let actions = count_desync_actions(joined);
    let multi = is_multi_stage(joined);

    match (actions, multi) {
        (a, true) if a >= 4 => 10,  // 4+ actions + multi-stage
        (a, true) if a >= 3 => 20,  // 3 actions + multi-stage
        (a, false) if a >= 4 => 30, // 4+ actions
        (a, false) if a >= 3 => 50, // 3 actions
        (_, true) => 50,            // 2 actions + multi-stage
        (2, false) => 80,           // 2 actions
        _ => 100,                   // 1 action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn simple_strategy_scores_high() {
        let s = score_strategy(&args(
            "--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:tcp_ts=-1000"
        ));
        assert_eq!(s.simplicity, 100); // 1 action
        assert_eq!(s.performance, 100); // no repeats
        assert_eq!(s.total, 100);
        assert_eq!(s.stars, 3);
    }

    #[test]
    fn multi_stage_scores_lower() {
        let s = score_strategy(&args(
            "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=5:repeats=1 --lua-desync=multisplit:pos=host+1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"
        ));
        assert_eq!(s.simplicity, 20); // 3 actions + multi-stage
        assert_eq!(s.performance, 40); // multi-stage
        assert_eq!(s.stars, 1);
    }

    #[test]
    fn high_repeats_score_low() {
        let s = score_strategy(&args(
            "--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=260"
        ));
        assert_eq!(s.performance, 10); // extreme repeats
        assert_eq!(s.simplicity, 100); // 1 action
    }

    #[test]
    fn two_actions_moderate() {
        let s = score_strategy(&args(
            "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=1 --lua-desync=multisplit:pos=1,midsld"
        ));
        assert_eq!(s.simplicity, 80); // 2 actions
        assert_eq!(s.performance, 100); // repeats=1
        assert_eq!(s.total, 90);
        assert_eq!(s.stars, 3);
    }

    #[test]
    fn ranking_simple_beats_complex() {
        let strategies = vec![
            // Complex: 3 actions + multi-stage + high repeats
            args("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=5:repeats=1 --lua-desync=fakedsplit:pos=midsld:ip_ttl=5:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"),
            // Simple: 1 action, no repeats
            args("--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:tcp_ts=-1000"),
        ];

        let ranked = rank_strategies(&strategies);
        assert!(ranked[0].total > ranked[1].total, "simple should rank higher");
        assert_eq!(ranked[0].strategy_args, strategies[1]);
    }
}

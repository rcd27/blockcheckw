// Strategy scoring and ranking.
//
// Four dimensions (0..100 each), weighted into a total score:
//   Compatibility (40%) — no fooling > autottl > ttl > tcp fooling
//   Simplicity    (25%) — fewer desync actions = better
//   Universality  (20%) — no TTL dependency > autottl > fixed ttl
//   Performance   (15%) — no repeats/multi-stage > repeats > multi-stage

/// TCP fooling indicators in strategy args.
const TCP_FOOLINGS: &[&str] = &[
    "tcp_md5", "badsum", "tcp_seq=", "tcp_ack=", "tcp_ts=",
    "tcp_flags_unset=", "tcp_flags_set=",
];

pub struct StrategyScore {
    pub strategy_args: Vec<String>,
    pub total: u32,
    pub compatibility: u32,
    pub simplicity: u32,
    pub universality: u32,
    pub performance: u32,
    pub stars: u8,
    pub tags: Vec<&'static str>,
}

pub fn score_strategy(args: &[String]) -> StrategyScore {
    let joined = args.join(" ");

    let compatibility = score_compatibility(&joined);
    let simplicity = score_simplicity(&joined);
    let universality = score_universality(&joined);
    let performance = score_performance(&joined);

    let total = (compatibility as f64 * 0.40
        + simplicity as f64 * 0.25
        + universality as f64 * 0.20
        + performance as f64 * 0.15) as u32;

    let stars = if total >= 75 {
        3
    } else if total >= 45 {
        2
    } else {
        1
    };

    let mut tags = Vec::new();
    if compatibility == 100 {
        tags.push("universal");
    }
    if compatibility <= 20 {
        tags.push("tcp fooling, may fail on some networks");
    }
    if universality <= 30 {
        tags.push("TTL-dependent (hop count specific)");
    }
    if simplicity <= 40 {
        tags.push("multi-stage, complex");
    }
    if performance <= 40 {
        tags.push("high packet overhead");
    }

    StrategyScore {
        strategy_args: args.to_vec(),
        total,
        compatibility,
        simplicity,
        universality,
        performance,
        stars,
        tags,
    }
}

pub fn rank_strategies(strategies: &[Vec<String>]) -> Vec<StrategyScore> {
    let mut scored: Vec<StrategyScore> = strategies.iter().map(|s| score_strategy(s)).collect();
    scored.sort_by(|a, b| b.total.cmp(&a.total));
    scored
}

// --- Dimension scorers ---

fn has_tcp_fooling(joined: &str) -> bool {
    TCP_FOOLINGS.iter().any(|f| joined.contains(f))
}

fn score_compatibility(joined: &str) -> u32 {
    if has_tcp_fooling(joined) {
        20
    } else if joined.contains("ip_autottl=") {
        70
    } else if joined.contains("ip_ttl=") {
        50
    } else {
        100
    }
}

fn count_desync_actions(joined: &str) -> usize {
    joined.matches("--lua-desync=").count()
}

fn is_multi_stage(joined: &str) -> bool {
    joined.contains("--payload=empty") && joined.contains("--out-range=")
}

fn score_simplicity(joined: &str) -> u32 {
    let actions = count_desync_actions(joined);
    let multi = is_multi_stage(joined);

    match (actions, multi) {
        (a, true) if a >= 3 => 20,
        (a, false) if a >= 3 => 40,
        (_, true) => 40,
        (2, false) => 70,
        _ => 100, // 0 or 1 action, no multi-stage
    }
}

fn score_universality(joined: &str) -> u32 {
    if joined.contains("ip_ttl=") && !joined.contains("ip_autottl=") {
        // fixed TTL — check it's not just pktmod:ip_ttl=1 (limiter, not fooling)
        // We look for ip_ttl= that is NOT preceded by pktmod:
        let has_real_ttl = joined.split("--lua-desync=").any(|part| {
            part.contains("ip_ttl=") && !part.starts_with("pktmod:")
        });
        if has_real_ttl {
            return 30;
        }
    }
    if joined.contains("ip_autottl=") {
        return 60;
    }
    100
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

fn score_performance(joined: &str) -> u32 {
    let repeats = parse_max_repeats(joined);
    let multi = is_multi_stage(joined);

    if repeats > 100 || (repeats > 1 && multi) {
        20
    } else if repeats > 20 || multi {
        40
    } else if repeats >= 2 {
        70
    } else {
        100
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn test_http_basic_high_score() {
        let s = score_strategy(&args("--payload=http_req --lua-desync=http_unixeol"));
        assert_eq!(s.compatibility, 100);
        assert_eq!(s.simplicity, 100);
        assert_eq!(s.universality, 100);
        assert_eq!(s.performance, 100);
        assert_eq!(s.total, 100);
        assert_eq!(s.stars, 3);
        assert!(s.tags.contains(&"universal"));
    }

    #[test]
    fn test_multisplit_no_fooling() {
        let s = score_strategy(&args("--payload=http_req --lua-desync=multisplit:pos=method+2"));
        assert_eq!(s.compatibility, 100);
        assert_eq!(s.universality, 100);
        assert_eq!(s.stars, 3);
    }

    #[test]
    fn test_fake_with_fixed_ttl() {
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_ttl=6:repeats=1"
        ));
        assert_eq!(s.compatibility, 50);
        assert_eq!(s.universality, 30);
        assert!(s.tags.contains(&"TTL-dependent (hop count specific)"));
        assert_eq!(s.stars, 2);
    }

    #[test]
    fn test_fake_with_autottl() {
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_autottl=-4,3-20:repeats=1"
        ));
        assert_eq!(s.compatibility, 70);
        assert_eq!(s.universality, 60);
        // total = 70*0.4 + 100*0.25 + 60*0.2 + 100*0.15 = 80 → 3 stars
        assert_eq!(s.stars, 3);
    }

    #[test]
    fn test_tcp_md5_fooling() {
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5:repeats=1"
        ));
        assert_eq!(s.compatibility, 20);
        assert!(s.tags.contains(&"tcp fooling, may fail on some networks"));
    }

    #[test]
    fn test_multi_stage_tcp_md5() {
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5:repeats=1 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5"
        ));
        assert_eq!(s.compatibility, 20);
        assert_eq!(s.simplicity, 40); // 2 desync actions + multi-stage
        assert!(s.tags.contains(&"tcp fooling, may fail on some networks"));
        assert!(s.tags.contains(&"multi-stage, complex"));
        assert_eq!(s.stars, 1);
    }

    #[test]
    fn test_high_repeats() {
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=tcpseg:pos=0,method+2:ip_id=rnd:repeats=260"
        ));
        assert_eq!(s.performance, 20);
        assert!(s.tags.contains(&"high packet overhead"));
    }

    #[test]
    fn test_pktmod_ttl_not_counted_as_real_ttl() {
        // multi-stage with pktmod:ip_ttl=1 should NOT count as fixed TTL
        // unless there's also a real ip_ttl= in another action
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_autottl=-1,3-20:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"
        ));
        // Should be autottl, not fixed TTL
        assert_eq!(s.universality, 60);
    }

    #[test]
    fn test_ranking_order() {
        let strategies = vec![
            args("--payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5:repeats=1 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5"),
            args("--payload=http_req --lua-desync=http_unixeol"),
            args("--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_ttl=6:repeats=1"),
            args("--payload=http_req --lua-desync=multisplit:pos=method+2"),
        ];

        let ranked = rank_strategies(&strategies);

        // http_unixeol and multisplit should be top (both score 100)
        assert_eq!(ranked[0].total, 100);
        assert_eq!(ranked[1].total, 100);
        // fake with TTL should be next
        assert!(ranked[2].total > ranked[3].total, "fake_ttl ({}) should score higher than tcp_md5 ({})", ranked[2].total, ranked[3].total);
        // tcp_md5 multi-stage should be last
        assert!(ranked[3].total < 45);
    }

    #[test]
    fn test_seqovl_with_drop() {
        // seqovl + drop = 2 desync actions
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop"
        ));
        assert_eq!(s.simplicity, 70); // 2 desync actions
        assert_eq!(s.compatibility, 100); // no fooling
    }

    #[test]
    fn test_three_desync_actions_multi_stage() {
        let s = score_strategy(&args(
            "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_ttl=5:repeats=1 --lua-desync=multisplit:pos=method+2 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"
        ));
        assert_eq!(s.simplicity, 20); // 3 actions + multi-stage
    }
}

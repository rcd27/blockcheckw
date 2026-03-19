use std::sync::Arc;

use console::style;

use crate::config::{CoreConfig, Protocol};
use crate::error::TaskResult;
use crate::pipeline::runner::{run_parallel, StrategyResult};
use crate::ui::ScanScreen;

/// Configuration for verification passes.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Number of verification passes (0 = skip verification)
    pub passes: usize,
    /// Minimum passes required to consider a strategy verified
    pub min_passes: usize,
    /// curl --max-time for verification (stricter than scan)
    pub curl_max_time: String,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            passes: 3,
            min_passes: 3,
            curl_max_time: "3".to_string(),
        }
    }
}

/// Per-strategy pass/fail tally across all verification passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyTally {
    pub strategy_args: Vec<String>,
    pub pass_count: usize,
    pub fail_count: usize,
}

/// Overall verification result.
#[derive(Debug)]
pub struct VerificationSummary {
    pub total_candidates: usize,
    pub verified_count: usize,
    pub required_passes: usize,
    pub total_passes: usize,
    pub tallies: Vec<StrategyTally>,
    pub verified: Vec<Vec<String>>,
    /// If strict verification yielded 0 results, auto-relax finds the best
    /// non-zero threshold. None if strict already found results or all tallies are 0/N.
    pub relaxed: Option<RelaxedResult>,
}

/// Strategies found by lowering the verification threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaxedResult {
    pub actual_min: usize,
    pub strategies: Vec<Vec<String>>,
}

/// Count pass/fail per strategy across N verification passes.
///
/// `pass_outcomes[pass_idx][strategy_idx]` = true if strategy succeeded in that pass.
pub fn tally_results(
    candidates: &[Vec<String>],
    pass_outcomes: &[Vec<bool>],
) -> Vec<StrategyTally> {
    candidates
        .iter()
        .enumerate()
        .map(|(strat_idx, args)| {
            let pass_count = pass_outcomes
                .iter()
                .filter(|pass| pass.get(strat_idx).copied().unwrap_or(false))
                .count();
            let fail_count = pass_outcomes.len() - pass_count;
            StrategyTally {
                strategy_args: args.clone(),
                pass_count,
                fail_count,
            }
        })
        .collect()
}

/// Keep only strategies with pass_count >= min_passes.
pub fn filter_verified(
    tallies: &[StrategyTally],
    min_passes: usize,
) -> Vec<Vec<String>> {
    tallies
        .iter()
        .filter(|t| t.pass_count >= min_passes)
        .map(|t| t.strategy_args.clone())
        .collect()
}

/// When strict verification yields 0 results, find the best relaxed threshold.
///
/// Tries min_passes-1, min_passes-2, ..., 1 and returns the first threshold
/// that produces any results. Returns None if even 1/N gives nothing.
pub fn find_relaxed(
    tallies: &[StrategyTally],
    min_passes: usize,
) -> Option<RelaxedResult> {
    for threshold in (1..min_passes).rev() {
        let strategies = filter_verified(tallies, threshold);
        if !strategies.is_empty() {
            return Some(RelaxedResult {
                actual_min: threshold,
                strategies,
            });
        }
    }
    None
}

/// Map run_parallel results (arbitrary order) back to candidate order.
///
/// For each candidate, checks if there's a matching StrategyResult with Success.
/// Missing results default to false.
fn extract_outcomes(
    candidates: &[Vec<String>],
    results: &[StrategyResult],
) -> Vec<bool> {
    candidates
        .iter()
        .map(|args| {
            results
                .iter()
                .any(|r| r.strategy_args == *args && matches!(r.result, TaskResult::Success { .. }))
        })
        .collect()
}

/// Run N verification passes on candidate strategies, return tally and filtered results.
pub async fn run_verification(
    config: &CoreConfig,
    domain: &str,
    protocol: Protocol,
    candidates: &[Vec<String>],
    ips: &[String],
    verify_config: &VerifyConfig,
    screen: &mut ScanScreen,
) -> VerificationSummary {
    let verify_core = Arc::new(CoreConfig {
        curl_max_time: verify_config.curl_max_time.clone(),
        ..config.clone()
    });

    let mut all_outcomes: Vec<Vec<bool>> = Vec::with_capacity(verify_config.passes);

    for pass in 1..=verify_config.passes {
        screen.println(&format!(
            "  {} pass {}/{}",
            style("verify").bold(),
            pass,
            verify_config.passes,
        ));

        screen.begin_progress(candidates.len() as u64);

        let (results, _stats) = run_parallel(
            &verify_core,
            domain,
            protocol,
            candidates,
            ips,
            Some(screen.multi()),
            Some(screen.pb()),
        )
        .await;

        screen.finish_progress();

        let outcomes = extract_outcomes(candidates, &results);
        all_outcomes.push(outcomes);
    }

    let tallies = tally_results(candidates, &all_outcomes);
    let verified = filter_verified(&tallies, verify_config.min_passes);

    let relaxed = if verified.is_empty() {
        find_relaxed(&tallies, verify_config.min_passes)
    } else {
        None
    };

    VerificationSummary {
        total_candidates: candidates.len(),
        verified_count: verified.len(),
        required_passes: verify_config.min_passes,
        total_passes: verify_config.passes,
        tallies,
        verified,
        relaxed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{CurlVerdictAvailable, TaskResult};
    use crate::pipeline::runner::StrategyResult;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ── tally_results ──────────────────────────────────────────

    #[test]
    fn tally_all_pass() {
        let candidates = vec![args("--a"), args("--b")];
        let outcomes = vec![
            vec![true, true],
            vec![true, true],
            vec![true, true],
        ];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies.len(), 2);
        assert_eq!(tallies[0].pass_count, 3);
        assert_eq!(tallies[0].fail_count, 0);
        assert_eq!(tallies[1].pass_count, 3);
        assert_eq!(tallies[1].fail_count, 0);
    }

    #[test]
    fn tally_mixed() {
        let candidates = vec![args("--a"), args("--b"), args("--c")];
        let outcomes = vec![
            vec![true, true, false],
            vec![true, false, true],
            vec![true, true, false],
        ];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies[0], StrategyTally { strategy_args: args("--a"), pass_count: 3, fail_count: 0 });
        assert_eq!(tallies[1], StrategyTally { strategy_args: args("--b"), pass_count: 2, fail_count: 1 });
        assert_eq!(tallies[2], StrategyTally { strategy_args: args("--c"), pass_count: 1, fail_count: 2 });
    }

    #[test]
    fn tally_all_fail() {
        let candidates = vec![args("--a")];
        let outcomes = vec![
            vec![false],
            vec![false],
            vec![false],
        ];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies[0].pass_count, 0);
        assert_eq!(tallies[0].fail_count, 3);
    }

    #[test]
    fn tally_empty_candidates() {
        let candidates: Vec<Vec<String>> = vec![];
        let outcomes: Vec<Vec<bool>> = vec![vec![], vec![], vec![]];
        let tallies = tally_results(&candidates, &outcomes);
        assert!(tallies.is_empty());
    }

    #[test]
    fn tally_single_pass() {
        let candidates = vec![args("--a"), args("--b")];
        let outcomes = vec![vec![true, false]];
        let tallies = tally_results(&candidates, &outcomes);
        assert_eq!(tallies[0].pass_count, 1);
        assert_eq!(tallies[0].fail_count, 0);
        assert_eq!(tallies[1].pass_count, 0);
        assert_eq!(tallies[1].fail_count, 1);
    }

    // ── filter_verified ────────────────────────────────────────

    #[test]
    fn filter_strict_3_of_3() {
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 3, fail_count: 0 },
            StrategyTally { strategy_args: args("--b"), pass_count: 2, fail_count: 1 },
            StrategyTally { strategy_args: args("--c"), pass_count: 3, fail_count: 0 },
        ];
        let verified = filter_verified(&tallies, 3);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0], args("--a"));
        assert_eq!(verified[1], args("--c"));
    }

    #[test]
    fn filter_relaxed_2_of_3() {
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 3, fail_count: 0 },
            StrategyTally { strategy_args: args("--b"), pass_count: 2, fail_count: 1 },
            StrategyTally { strategy_args: args("--c"), pass_count: 1, fail_count: 2 },
        ];
        let verified = filter_verified(&tallies, 2);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0], args("--a"));
        assert_eq!(verified[1], args("--b"));
    }

    #[test]
    fn filter_none_pass() {
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 1, fail_count: 2 },
        ];
        let verified = filter_verified(&tallies, 3);
        assert!(verified.is_empty());
    }

    #[test]
    fn filter_zero_threshold() {
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 0, fail_count: 3 },
        ];
        let verified = filter_verified(&tallies, 0);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0], args("--a"));
    }

    // ── extract_outcomes ───────────────────────────────────────

    #[test]
    fn extract_matches_by_args() {
        let candidates = vec![args("--a"), args("--b"), args("--c")];
        let results = vec![
            StrategyResult {
                strategy_args: args("--c"),
                result: TaskResult::Success {
                    verdict: CurlVerdictAvailable,
                    strategy_args: args("--c"),
                },
            },
            StrategyResult {
                strategy_args: args("--a"),
                result: TaskResult::Success {
                    verdict: CurlVerdictAvailable,
                    strategy_args: args("--a"),
                },
            },
            StrategyResult {
                strategy_args: args("--b"),
                result: TaskResult::Failed {
                    verdict: crate::network::curl::CurlVerdict::Unavailable { curl_exit_code: 7 },
                },
            },
        ];
        let outcomes = extract_outcomes(&candidates, &results);
        assert_eq!(outcomes, vec![true, false, true]);
    }

    #[test]
    fn extract_missing_result() {
        let candidates = vec![args("--a")];
        let results: Vec<StrategyResult> = vec![];
        let outcomes = extract_outcomes(&candidates, &results);
        assert_eq!(outcomes, vec![false]);
    }

    // ── VerifyConfig default ───────────────────────────────────

    #[test]
    fn verify_config_defaults() {
        let cfg = VerifyConfig::default();
        assert_eq!(cfg.passes, 3);
        assert_eq!(cfg.min_passes, 3);
        assert_eq!(cfg.curl_max_time, "3");
    }

    // ── find_relaxed ───────────────────────────────────────────

    #[test]
    fn relaxed_finds_best_threshold() {
        // strict=3, но --a набрала 2/3, --b 1/3
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 2, fail_count: 1 },
            StrategyTally { strategy_args: args("--b"), pass_count: 1, fail_count: 2 },
        ];
        let result = find_relaxed(&tallies, 3).unwrap();
        assert_eq!(result.actual_min, 2);
        assert_eq!(result.strategies, vec![args("--a")]);
    }

    #[test]
    fn relaxed_all_zero() {
        // все 0/3 — даже relaxed не поможет
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 0, fail_count: 3 },
        ];
        assert!(find_relaxed(&tallies, 3).is_none());
    }

    #[test]
    fn relaxed_falls_to_one() {
        // только 1/3 — порог опустится до 1
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 1, fail_count: 2 },
        ];
        let result = find_relaxed(&tallies, 3).unwrap();
        assert_eq!(result.actual_min, 1);
        assert_eq!(result.strategies, vec![args("--a")]);
    }

    #[test]
    fn relaxed_not_needed_when_min_is_one() {
        // min_passes=1 — relaxed не вызывается (нечего понижать)
        let tallies = vec![
            StrategyTally { strategy_args: args("--a"), pass_count: 0, fail_count: 3 },
        ];
        assert!(find_relaxed(&tallies, 1).is_none());
    }
}

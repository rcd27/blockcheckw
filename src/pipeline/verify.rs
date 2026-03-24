use std::sync::Arc;

use console::style;

use crate::config::{CoreConfig, Protocol};
use crate::error::TaskResult;
use crate::network::http_client::DATA_TRANSFER_MIN_BYTES;
use crate::pipeline::runner::{run_parallel, RunParams, StrategyResult};
use crate::pipeline::worker_task::HttpTestMode;
use crate::ui::Console;

/// Configuration for verification passes.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Number of verification passes (0 = skip verification)
    pub passes: usize,
    /// Minimum passes required to consider a strategy verified
    pub min_passes: usize,
    /// Request timeout in seconds for verification (stricter than scan)
    pub request_timeout: u64,
    /// Data transfer validation config
    pub data_transfer: DataTransferConfig,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            passes: 3,
            min_passes: 3,
            request_timeout: 3,
            data_transfer: DataTransferConfig::default(),
        }
    }
}

/// Configuration for data transfer validation phase.
#[derive(Debug, Clone)]
pub struct DataTransferConfig {
    /// Enable data transfer validation (GET request after HEAD passes)
    pub enabled: bool,
    /// Request timeout in seconds for data transfer test (longer than HEAD)
    pub request_timeout: u64,
    /// Minimum bytes that must be downloaded for a strategy to pass
    pub min_bytes: u64,
}

impl Default for DataTransferConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            request_timeout: 8,
            min_bytes: DATA_TRANSFER_MIN_BYTES,
        }
    }
}

/// Summary of data transfer validation results.
#[derive(Debug)]
pub struct DataTransferSummary {
    pub tested: usize,
    pub passed: usize,
    pub timeout: String,
    pub min_bytes: u64,
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
    /// Data transfer validation results (None if skipped).
    pub data_transfer_results: Option<DataTransferSummary>,
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
pub fn filter_verified(tallies: &[StrategyTally], min_passes: usize) -> Vec<Vec<String>> {
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
pub fn find_relaxed(tallies: &[StrategyTally], min_passes: usize) -> Option<RelaxedResult> {
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
fn extract_outcomes(candidates: &[Vec<String>], results: &[StrategyResult]) -> Vec<bool> {
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
/// If data_transfer is enabled, runs an additional GET-based pass after HEAD passes.
pub async fn run_verification(
    config: &CoreConfig,
    domain: &str,
    protocol: Protocol,
    candidates: &[Vec<String>],
    ips: &[String],
    verify_config: &VerifyConfig,
    screen: &mut Console,
) -> VerificationSummary {
    let verify_core = Arc::new(CoreConfig {
        request_timeout: verify_config.request_timeout,
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

        screen.begin_progress_with_prefix(
            candidates.len() as u64,
            &format!("Verify {protocol} [{pass}/{}]", verify_config.passes),
        );

        let (results, _stats) = run_parallel(RunParams {
            config: &verify_core,
            domain,
            protocol,
            strategies: candidates,
            ips,
            multi: Some(screen.multi()),
            external_pb: Some(screen.pb()),
            mode: HttpTestMode::Standard,
            deadline: None,
        })
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

    // Data transfer validation: only for HTTPS, only for strategies that passed HEAD
    let dt_config = &verify_config.data_transfer;
    let is_https = matches!(protocol, Protocol::HttpsTls12 | Protocol::HttpsTls13);

    let (final_verified, final_relaxed, dt_summary) = if dt_config.enabled && is_https {
        // Pick strategies to test: verified first, fall back to relaxed
        let dt_candidates = if !verified.is_empty() {
            &verified
        } else if let Some(ref r) = relaxed {
            &r.strategies
        } else {
            // Nothing passed HEAD — skip data transfer
            return VerificationSummary {
                total_candidates: candidates.len(),
                verified_count: verified.len(),
                required_passes: verify_config.min_passes,
                total_passes: verify_config.passes,
                tallies,
                verified,
                relaxed,
                data_transfer_results: None,
            };
        };

        screen.println(&format!(
            "  {} data transfer check: {} strategies, GET {}s timeout, min {}B",
            style("verify").bold(),
            dt_candidates.len(),
            dt_config.request_timeout,
            dt_config.min_bytes,
        ));

        screen.begin_progress_with_prefix(
            dt_candidates.len() as u64,
            &format!("Data transfer {protocol}"),
        );

        let dt_core = Arc::new(CoreConfig {
            request_timeout: dt_config.request_timeout,
            ..config.clone()
        });

        let (dt_results, _dt_stats) = run_parallel(RunParams {
            config: &dt_core,
            domain,
            protocol,
            strategies: dt_candidates,
            ips,
            multi: Some(screen.multi()),
            external_pb: Some(screen.pb()),
            mode: HttpTestMode::DataTransfer {
                min_bytes: dt_config.min_bytes,
            },
            deadline: None,
        })
        .await;

        screen.finish_progress();

        let dt_passed: Vec<Vec<String>> = dt_results
            .iter()
            .filter(|r| matches!(r.result, TaskResult::Success { .. }))
            .map(|r| r.strategy_args.clone())
            .collect();

        let summary = DataTransferSummary {
            tested: dt_candidates.len(),
            passed: dt_passed.len(),
            timeout: format!("{}s", dt_config.request_timeout),
            min_bytes: dt_config.min_bytes,
        };

        if !verified.is_empty() {
            // Data transfer filters verified strategies
            (dt_passed, None, Some(summary))
        } else {
            // Data transfer filters relaxed strategies
            let new_relaxed = if dt_passed.is_empty() {
                relaxed.clone()
            } else {
                Some(RelaxedResult {
                    actual_min: relaxed.as_ref().map(|r| r.actual_min).unwrap_or(0),
                    strategies: dt_passed,
                })
            };
            (vec![], new_relaxed, Some(summary))
        }
    } else {
        (verified, relaxed, None)
    };

    VerificationSummary {
        total_candidates: candidates.len(),
        verified_count: final_verified.len(),
        required_passes: verify_config.min_passes,
        total_passes: verify_config.passes,
        tallies,
        verified: final_verified,
        relaxed: final_relaxed,
        data_transfer_results: dt_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{HttpVerdictAvailable, TaskResult};
    use crate::pipeline::runner::StrategyResult;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ── tally_results ──────────────────────────────────────────

    #[test]
    fn tally_all_pass() {
        let candidates = vec![args("--a"), args("--b")];
        let outcomes = vec![vec![true, true], vec![true, true], vec![true, true]];
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
        assert_eq!(
            tallies[0],
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 3,
                fail_count: 0
            }
        );
        assert_eq!(
            tallies[1],
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 2,
                fail_count: 1
            }
        );
        assert_eq!(
            tallies[2],
            StrategyTally {
                strategy_args: args("--c"),
                pass_count: 1,
                fail_count: 2
            }
        );
    }

    #[test]
    fn tally_all_fail() {
        let candidates = vec![args("--a")];
        let outcomes = vec![vec![false], vec![false], vec![false]];
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
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 3,
                fail_count: 0,
            },
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 2,
                fail_count: 1,
            },
            StrategyTally {
                strategy_args: args("--c"),
                pass_count: 3,
                fail_count: 0,
            },
        ];
        let verified = filter_verified(&tallies, 3);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0], args("--a"));
        assert_eq!(verified[1], args("--c"));
    }

    #[test]
    fn filter_relaxed_2_of_3() {
        let tallies = vec![
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 3,
                fail_count: 0,
            },
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 2,
                fail_count: 1,
            },
            StrategyTally {
                strategy_args: args("--c"),
                pass_count: 1,
                fail_count: 2,
            },
        ];
        let verified = filter_verified(&tallies, 2);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0], args("--a"));
        assert_eq!(verified[1], args("--b"));
    }

    #[test]
    fn filter_none_pass() {
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 1,
            fail_count: 2,
        }];
        let verified = filter_verified(&tallies, 3);
        assert!(verified.is_empty());
    }

    #[test]
    fn filter_zero_threshold() {
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 0,
            fail_count: 3,
        }];
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
                    verdict: HttpVerdictAvailable,
                    strategy_args: args("--c"),
                },
            },
            StrategyResult {
                strategy_args: args("--a"),
                result: TaskResult::Success {
                    verdict: HttpVerdictAvailable,
                    strategy_args: args("--a"),
                },
            },
            StrategyResult {
                strategy_args: args("--b"),
                result: TaskResult::Failed {
                    verdict: crate::network::http_client::HttpVerdict::Unavailable {
                        reason: "connection refused".to_string(),
                    },
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
        assert_eq!(cfg.request_timeout, 3);
    }

    // ── find_relaxed ───────────────────────────────────────────

    #[test]
    fn relaxed_finds_best_threshold() {
        // strict=3, но --a набрала 2/3, --b 1/3
        let tallies = vec![
            StrategyTally {
                strategy_args: args("--a"),
                pass_count: 2,
                fail_count: 1,
            },
            StrategyTally {
                strategy_args: args("--b"),
                pass_count: 1,
                fail_count: 2,
            },
        ];
        let result = find_relaxed(&tallies, 3).unwrap();
        assert_eq!(result.actual_min, 2);
        assert_eq!(result.strategies, vec![args("--a")]);
    }

    #[test]
    fn relaxed_all_zero() {
        // все 0/3 — даже relaxed не поможет
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 0,
            fail_count: 3,
        }];
        assert!(find_relaxed(&tallies, 3).is_none());
    }

    #[test]
    fn relaxed_falls_to_one() {
        // только 1/3 — порог опустится до 1
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 1,
            fail_count: 2,
        }];
        let result = find_relaxed(&tallies, 3).unwrap();
        assert_eq!(result.actual_min, 1);
        assert_eq!(result.strategies, vec![args("--a")]);
    }

    #[test]
    fn relaxed_not_needed_when_min_is_one() {
        // min_passes=1 — relaxed не вызывается (нечего понижать)
        let tallies = vec![StrategyTally {
            strategy_args: args("--a"),
            pass_count: 0,
            fail_count: 3,
        }];
        assert!(find_relaxed(&tallies, 1).is_none());
    }
}

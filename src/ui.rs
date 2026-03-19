use console::{style, Emoji, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

pub static CHECKMARK: Emoji<'_, '_> = Emoji("✓ ", "+ ");
pub static CROSS: Emoji<'_, '_> = Emoji("✗ ", "x ");
pub static ARROW: Emoji<'_, '_> = Emoji("→ ", "-> ");
pub static WARN: Emoji<'_, '_> = Emoji("⚠ ", "! ");

/// Section header: `=== title ===` in bold cyan
pub fn section(title: &str) -> String {
    format!("{}", style(format!("=== {title} ===")).bold().cyan())
}

/// Verdict for available protocol: green checkmark
pub fn verdict_available(protocol: &str, detail: &str) -> String {
    format!(
        "  {}{}: {}",
        CHECKMARK,
        style(protocol).green(),
        style(detail).green()
    )
}

/// Verdict for blocked protocol: red cross
pub fn verdict_blocked(protocol: &str, detail: &str) -> String {
    format!(
        "  {}{}: {}",
        CROSS,
        style(protocol).red(),
        style(format!("BLOCKED ({detail})")).red()
    )
}

/// Verdict for warning (suspicious redirect, etc): yellow warning
pub fn verdict_warning(protocol: &str, detail: &str) -> String {
    format!(
        "  {}{}: {}",
        WARN,
        style(protocol).yellow(),
        style(detail).yellow()
    )
}

/// "Blocked protocols: HTTP, ..." in red bold
pub fn blocked_list(protocols: &str) -> String {
    format!(
        "{} {}",
        style("Blocked protocols:").red().bold(),
        style(protocols).red().bold()
    )
}

/// Summary: N working strategies found — green bold
pub fn summary_found(protocol: &str, count: usize) -> String {
    format!(
        "  {}{}: {}",
        CHECKMARK,
        style(protocol).green().bold(),
        style(format!("{count} working strategies found")).green().bold()
    )
}

/// Summary: N unstable strategies found — yellow bold
pub fn summary_found_unstable(protocol: &str, count: usize) -> String {
    format!(
        "  {}{}: {}",
        WARN,
        style(protocol).yellow().bold(),
        style(format!("{count} unstable strategies found")).yellow().bold()
    )
}

/// Summary: no working strategies found — red
pub fn summary_no_strategies(protocol: &str) -> String {
    format!(
        "  {}{}: {}",
        CROSS,
        style(protocol).red(),
        style("no working strategies found").red()
    )
}

/// Summary: working without bypass — green
pub fn summary_available(protocol: &str) -> String {
    format!(
        "  {}{}: {}",
        CHECKMARK,
        style(protocol).green(),
        style("working without bypass").green()
    )
}

/// Strategy line: `    → nfqws2 args` in cyan
pub fn strategy_line(args: &str) -> String {
    format!("    {}nfqws2 {}", ARROW, style(args).cyan())
}

/// Stats line: `completed: N | success: N | ...`
pub fn stats_line(
    completed: usize,
    successes: usize,
    failures: usize,
    errors: usize,
    elapsed_secs: f64,
    throughput: f64,
) -> String {
    format!(
        "  completed: {} | success: {} | failed: {} | errors: {} | {:.1}s ({:.1} strat/sec)",
        completed,
        style(successes).green(),
        failures,
        if errors > 0 {
            style(errors).red().to_string()
        } else {
            errors.to_string()
        },
        elapsed_secs,
        throughput,
    )
}

/// Relaxed summary header: "  no strategies passed 3/3, showing best at 2/3 (unstable):"
pub fn verify_relaxed_header(required: usize, passes: usize, actual_min: usize, count: usize) -> String {
    format!(
        "  {} {}/{}, showing {} best at {}/{} ({}):",
        style("no strategies passed").yellow(),
        required,
        passes,
        style(count).yellow().bold(),
        actual_min,
        passes,
        style("unstable").yellow().bold(),
    )
}

/// Verification summary: "  verified: 8/12 strategies (3/3 passes each)"
pub fn verify_summary_line(verified: usize, total: usize, required: usize, passes: usize) -> String {
    format!(
        "  {}: {}/{} strategies ({}/{} passes each)",
        style("verified").bold(),
        style(verified).green().bold(),
        total,
        required,
        passes,
    )
}

/// Per-strategy tally: "    ✓ nfqws2 --args: 3/3" or "    ✗ nfqws2 --args: 1/3"
pub fn verify_tally_line(tally: &crate::pipeline::verify::StrategyTally, required: usize) -> String {
    let args_str = tally.strategy_args.join(" ");
    let total = tally.pass_count + tally.fail_count;
    let ratio = format!("{}/{}", tally.pass_count, total);
    if tally.pass_count >= required {
        format!(
            "    {}nfqws2 {}: {}",
            CHECKMARK,
            style(&args_str).cyan(),
            style(ratio).green(),
        )
    } else {
        format!(
            "    {}nfqws2 {}: {}",
            CROSS,
            style(&args_str).dim(),
            style(ratio).red(),
        )
    }
}

/// DNS info line for the status bar.
/// Format: `  DNS: domain → ip1, ip2 (via method) | spoofing: clean`
pub fn dns_info_line(
    domain: &str,
    ips: &[String],
    method: &str,
    spoof_result: &Option<crate::network::dns::DnsSpoofResult>,
) -> String {
    let spoof_status = match spoof_result {
        Some(crate::network::dns::DnsSpoofResult::Clean) => format!("{CHECKMARK}clean"),
        Some(crate::network::dns::DnsSpoofResult::Spoofed { .. }) => format!("{WARN}spoofed!"),
        Some(crate::network::dns::DnsSpoofResult::CheckFailed { .. }) => format!("{WARN}check failed"),
        None => "n/a".to_string(),
    };
    format!(
        "  DNS: {} {} {} (via {}) | spoofing: {}",
        domain,
        ARROW,
        ips.join(", "),
        method,
        spoof_status,
    )
}

/// Top strategies header: `=== Top strategies for HTTP (5 of 24) ===`
pub fn top_strategies_header(protocol: &str, count: usize, total: usize) -> String {
    format!(
        "{}",
        style(format!("=== Top strategies for {protocol} ({count} of {total}) ==="))
            .bold()
            .cyan()
    )
}

/// Ranked strategy line with stars and tags.
/// ```text
///   #1 ★★★ nfqws2 args
///          (universal, minimal overhead)
/// ```
pub fn ranked_strategy_line(rank: usize, score: &crate::strategy::rank::StrategyScore) -> String {
    let stars = match score.stars {
        3 => "★★★",
        2 => "★★☆",
        _ => "★☆☆",
    };

    let star_styled = match score.stars {
        3 => style(stars).green().bold().to_string(),
        2 => style(stars).yellow().bold().to_string(),
        _ => style(stars).red().bold().to_string(),
    };

    let args_str = score.strategy_args.join(" ");
    let mut line = format!(
        "  #{:<2} {} nfqws2 {}",
        rank,
        star_styled,
        style(&args_str).cyan(),
    );

    if !score.tags.is_empty() {
        line.push_str(&format!(
            "\n         ({})",
            style(score.tags.join(", ")).dim()
        ));
    }

    line
}

/// Layout manager for scan output. Ensures all text goes through `MultiProgress`
/// so progress bars and vanilla output never interleave.
/// When no TTY is detected, falls back to plain println.
pub struct ScanScreen {
    multi: MultiProgress,
    divider_bar: Option<ProgressBar>,
    pb: Option<ProgressBar>,
    info_bars: Vec<ProgressBar>,
    is_tty: bool,
}

impl Default for ScanScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanScreen {
    pub fn new() -> Self {
        let is_tty = Term::stderr().is_term();
        let multi = if is_tty {
            MultiProgress::new()
        } else {
            MultiProgress::with_draw_target(indicatif::ProgressDrawTarget::hidden())
        };
        Self {
            multi,
            divider_bar: None,
            pb: None,
            info_bars: Vec::new(),
            is_tty,
        }
    }

    /// Print a line above the progress bar (or just to stdout if no bar active).
    pub fn println(&self, msg: &str) {
        if self.is_tty {
            let _ = self.multi.println(msg);
        } else {
            println!("{msg}");
        }
    }

    /// Print an empty line.
    pub fn newline(&self) {
        if self.is_tty {
            let _ = self.multi.println("");
        } else {
            println!();
        }
    }

    /// Add a fixed info line that stays below the progress bar.
    /// Multiple lines can be added (ISP, DNS, etc).
    pub fn add_info_line(&mut self, msg: &str) {
        let bar = self.multi.add(ProgressBar::new(0));
        bar.set_style(ProgressStyle::with_template("{msg}").unwrap());
        bar.set_message(format!("{}", style(msg).dim()));
        bar.tick();
        self.info_bars.push(bar);
    }

    /// Clear and remove all info bars.
    pub fn finish_info(&mut self) {
        for bar in self.info_bars.drain(..) {
            bar.finish_and_clear();
        }
    }

    /// Create divider + progress bar and add both to `MultiProgress`.
    /// If an info_bar exists, inserts divider and pb before it so info stays at the bottom.
    pub fn begin_progress(&mut self, total: u64) {
        let width = Term::stdout().size().1 as usize;

        let divider = ProgressBar::new(0);
        let pb = ProgressBar::new(total);

        // Add to MultiProgress first, then configure — indicatif needs the draw
        // target set up before set_message/enable_steady_tick take effect.
        let (divider, pb) = if let Some(first_info) = self.info_bars.first() {
            (
                self.multi.insert_before(first_info, divider),
                self.multi.insert_before(first_info, pb),
            )
        } else {
            (self.multi.add(divider), self.multi.add(pb))
        };

        divider.set_style(ProgressStyle::with_template("{msg}").unwrap());
        divider.set_message(format!("{}", style("─".repeat(width)).dim()));

        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({per_sec}, ETA {eta})"
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        self.divider_bar = Some(divider);
        self.pb = Some(pb);
    }

    /// Finish and clear both the progress bar and the divider.
    /// The info_bar remains visible.
    pub fn finish_progress(&mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
        if let Some(div) = self.divider_bar.take() {
            div.finish_and_clear();
        }
    }

    /// Access the underlying `MultiProgress` (for `run_parallel`).
    pub fn multi(&self) -> &MultiProgress {
        &self.multi
    }

    /// Access the progress bar (for `run_parallel`). Panics if not started.
    pub fn pb(&self) -> &ProgressBar {
        self.pb.as_ref().expect("progress bar not started")
    }
}

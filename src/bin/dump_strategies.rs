//! Dump all generated strategies for a given protocol, one per line.
//! Usage: cargo run --bin dump_strategies -- [http|tls12|tls13]

use blockcheckw::config::Protocol;
use blockcheckw::strategy::generator::{generate_strategies, phase_counts};

fn main() {
    let proto = std::env::args().nth(1).unwrap_or_else(|| "tls12".into());
    let protocol = match proto.as_str() {
        "http" => Protocol::Http,
        "tls12" => Protocol::HttpsTls12,
        "tls13" => Protocol::HttpsTls13,
        _ => {
            eprintln!("Usage: dump_strategies [http|tls12|tls13]");
            std::process::exit(1);
        }
    };

    // Print phase counts to stderr
    let phases = phase_counts(protocol);
    for (name, count) in &phases {
        eprintln!("# {name}: {count}");
    }
    let total: usize = phases.iter().map(|(_, c)| c).sum();
    eprintln!("# TOTAL: {total}");

    // Print strategies to stdout
    for strategy in generate_strategies(protocol) {
        println!("{}", strategy.join(" "));
    }
}

//! Dump all loaded strategies for a given protocol, one per line.
//! Usage: cargo run --bin dump_strategies -- [http|tls12|tls13]

use blockcheckw::config::Protocol;
use blockcheckw::strategy::generator::generate_strategies;

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

    let strategies = generate_strategies(protocol);
    eprintln!("# {proto}: {} strategies", strategies.len());

    for strategy in strategies {
        println!("{}", strategy.join(" "));
    }
}

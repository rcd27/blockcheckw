//! Dump all loaded strategies for a given protocol, one per line.
//! Usage: cargo run --bin dump_strategies -- [http|tls12|tls13|quic]

use blockcheckw::config::Protocol;
use blockcheckw::strategy::generator::generate_strategies;

fn main() {
    let proto = std::env::args().nth(1).unwrap_or_else(|| "tls12".into());
    let protocol = match Protocol::all()
        .into_iter()
        .find(|p| p.cli_name() == proto.as_str())
    {
        Some(p) => p,
        None => {
            eprintln!("Usage: dump_strategies [http|tls12|tls13|quic]");
            std::process::exit(1);
        }
    };

    let strategies = generate_strategies(protocol);
    eprintln!("# {proto}: {} strategies", strategies.len());

    for strategy in strategies {
        println!("{}", strategy.join(" "));
    }
}

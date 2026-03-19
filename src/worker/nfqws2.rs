use crate::config::CoreConfig;
use crate::error::BlockcheckError;
use crate::system::process::BackgroundProcess;

/// Build nfqws2 command-line arguments (pure function, testable without root).
fn build_nfqws2_args(config: &CoreConfig, qnum: u16, strategy_args: &[String]) -> Vec<String> {
    let uid_arg = format!("--uid={}:{}", config.nfqws2_uid, config.nfqws2_gid);
    let qnum_arg = format!("--qnum={qnum}");
    let fwmark_arg = format!("--fwmark=0x{:08X}", crate::config::DESYNC_MARK);
    let lua_lib = format!(
        "--lua-init=@{}/lua/zapret-lib.lua",
        config.zapret_base
    );
    let lua_antidpi = format!(
        "--lua-init=@{}/lua/zapret-antidpi.lua",
        config.zapret_base
    );

    let mut args = vec![
        config.nfqws2_path.clone(),
        uid_arg,
        qnum_arg,
        fwmark_arg,
        lua_lib,
        lua_antidpi,
    ];
    args.extend_from_slice(strategy_args);
    args
}

/// Start nfqws2 as a background process with given queue number and strategy arguments.
pub fn start_nfqws2(
    config: &CoreConfig,
    qnum: u16,
    strategy_args: &[String],
) -> Result<BackgroundProcess, BlockcheckError> {
    let cmd_owned = build_nfqws2_args(config, qnum, strategy_args);
    let cmd_refs: Vec<&str> = cmd_owned.iter().map(|s| s.as_str()).collect();

    BackgroundProcess::spawn(&cmd_refs).map_err(|e| BlockcheckError::Nfqws2Start {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfqws2_args_include_uid() {
        let config = CoreConfig::default();
        let args = build_nfqws2_args(&config, 200, &["--dpi-desync=fake".into()]);
        assert!(
            args.iter().any(|a| a.starts_with("--uid=")),
            "nfqws2 args must include --uid"
        );
    }

    #[test]
    fn nfqws2_args_uid_default_value() {
        let config = CoreConfig::default();
        let args = build_nfqws2_args(&config, 200, &[]);
        let uid_arg = args.iter().find(|a| a.starts_with("--uid=")).unwrap();
        assert_eq!(uid_arg, "--uid=1:3003");
    }

    #[test]
    fn nfqws2_args_include_strategy() {
        let config = CoreConfig::default();
        let strategy = vec!["--dpi-desync=fake".to_string(), "--ttl=5".to_string()];
        let args = build_nfqws2_args(&config, 200, &strategy);
        assert!(args.contains(&"--dpi-desync=fake".to_string()));
        assert!(args.contains(&"--ttl=5".to_string()));
    }

    #[test]
    fn nfqws2_args_order() {
        let config = CoreConfig::default();
        let args = build_nfqws2_args(&config, 200, &["--test".into()]);
        // nfqws2_path should be first (argv[0])
        assert!(args[0].contains("nfqws2"));
        // --uid should come before --qnum
        let uid_pos = args.iter().position(|a| a.starts_with("--uid=")).unwrap();
        let qnum_pos = args.iter().position(|a| a.starts_with("--qnum=")).unwrap();
        assert!(uid_pos < qnum_pos, "--uid should come before --qnum");
    }
}

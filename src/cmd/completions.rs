pub fn generate_completions(shell: clap_complete::Shell, cmd: &mut clap::Command) {
    clap_complete::generate(shell, cmd, "blockcheckw", &mut std::io::stdout());
}

pub fn install_completions(shell: clap_complete::Shell, cmd: &mut clap::Command) {
    use std::fs;
    use std::path::PathBuf;

    let (dir, filename) = match shell {
        clap_complete::Shell::Bash => {
            let user_dir = dirs_for_bash();
            (user_dir, "blockcheckw".to_string())
        }
        clap_complete::Shell::Zsh => {
            let dir = zsh_completions_dir().unwrap_or_else(|| {
                eprintln!("Could not determine zsh completions directory.");
                eprintln!("Print to stdout instead: blockcheckw completions zsh");
                std::process::exit(1);
            });
            (dir, "_blockcheckw".to_string())
        }
        clap_complete::Shell::Fish => {
            let home = std::env::var("HOME").unwrap_or_default();
            let dir = PathBuf::from(home).join(".config/fish/completions");
            (dir, "blockcheckw.fish".to_string())
        }
        _ => {
            eprintln!("--install is not supported for {shell}. Print to stdout instead:");
            eprintln!("  blockcheckw completions {shell}");
            std::process::exit(1);
        }
    };

    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("Failed to create {}: {e}", dir.display());
        std::process::exit(1);
    }

    let path = dir.join(&filename);
    let mut buf = Vec::new();
    clap_complete::generate(shell, cmd, "blockcheckw", &mut buf);

    match fs::write(&path, &buf) {
        Ok(()) => {
            eprintln!("Completions installed to {}", path.display());
            match shell {
                clap_complete::Shell::Bash => {
                    eprintln!("Restart your shell or run: source {}", path.display());
                }
                clap_complete::Shell::Zsh => {
                    eprintln!("Restart your shell or run: autoload -Uz compinit && compinit");
                }
                clap_complete::Shell::Fish => {
                    eprintln!("Completions will be loaded automatically on next shell start.");
                }
                _ => {}
            }
        }
        Err(e) => {
            eprintln!("Failed to write {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

pub fn detect_shell() -> Option<clap_complete::Shell> {
    let shell_env = std::env::var("SHELL").ok()?;
    let shell_name = std::path::Path::new(&shell_env).file_name()?.to_str()?;
    match shell_name {
        "bash" | "ash" | "sh" => Some(clap_complete::Shell::Bash),
        "zsh" => Some(clap_complete::Shell::Zsh),
        "fish" => Some(clap_complete::Shell::Fish),
        "elvish" => Some(clap_complete::Shell::Elvish),
        "pwsh" | "powershell" => Some(clap_complete::Shell::PowerShell),
        _ => None,
    }
}

fn dirs_for_bash() -> std::path::PathBuf {
    use std::path::PathBuf;
    let system = PathBuf::from("/etc/bash_completion.d");
    if system.is_dir() {
        let test_file = system.join(".blockcheckw_write_test");
        if std::fs::write(&test_file, "").is_ok() {
            let _ = std::fs::remove_file(&test_file);
            return system;
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".local/share/bash-completion/completions")
}

fn zsh_completions_dir() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let candidates = [
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".zfunc")),
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".local/share/zsh/site-functions")),
        Some(PathBuf::from("/usr/local/share/zsh/site-functions")),
        Some(PathBuf::from("/usr/share/zsh/site-functions")),
    ];

    for dir in candidates.iter().flatten() {
        if dir.is_dir() {
            let test = dir.join(".blockcheckw_write_test");
            if std::fs::write(&test, "").is_ok() {
                let _ = std::fs::remove_file(&test);
                return Some(dir.clone());
            }
        }
    }

    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".local/share/zsh/site-functions"))
}

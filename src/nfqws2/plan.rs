use std::path::PathBuf;

use crate::nfqws2::mark::{ProfileMark, DESYNC_MARK};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueNum(u16);

impl QueueNum {
    pub fn new(n: u16) -> Self {
        QueueNum(n)
    }
    pub fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct Env {
    pub binary: PathBuf,
    pub lua: Vec<PathBuf>,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug)]
pub struct FilterMark(());

impl FilterMark {
    /// Единственный производственный конструктор — вызывать только после
    /// реальной проверки `--help`. См. `capability::grant_from_help`.
    pub(crate) fn evidenced() -> Self {
        FilterMark(())
    }

    /// Только для тестов внутри крейта: тестовый ярлык на месте настоящей
    /// проверки `grant_from_help`. В боевой сборке не существует вовсе.
    #[cfg(test)]
    pub(crate) fn granted() -> Self {
        FilterMark(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub mark: ProfileMark,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    queue: QueueNum,
    profiles: Vec<Profile>,
}

impl Plan {
    /// Стратегии → профили с марками 1..=N.
    ///
    /// Стратегий больше `PROFILE_MASK` быть не может — марка не влезет; вызывающий
    /// режет корпус на планы по `profiles_per_instance`, который заведомо меньше.
    pub fn from_strategies(
        _witness: &FilterMark,
        queue: QueueNum,
        strategies: &[Vec<String>],
    ) -> Self {
        let profiles = strategies
            .iter()
            .enumerate()
            .map(|(i, args)| Profile {
                mark: ProfileMark::new((i + 1) as u16)
                    .expect("индекс профиля начинается с единицы"),
                args: args.clone(),
            })
            .collect();
        Plan { queue, profiles }
    }

    /// План из одной стратегии — короткий путь для вызывающих, у которых уже
    /// есть готовый `&[String]` (`check.rs`, `test_runner.rs`) и которым не
    /// нужно заворачивать его в `&Vec<String>` только ради
    /// `std::slice::from_ref` под `from_strategies`.
    pub fn from_one(_witness: &FilterMark, queue: QueueNum, args: &[String]) -> Self {
        Plan {
            queue,
            profiles: vec![Profile {
                mark: ProfileMark::new(1).expect("единица — валидный индекс профиля"),
                args: args.to_vec(),
            }],
        }
    }

    pub fn queue(&self) -> QueueNum {
        self.queue
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// Командная строка процесса.
    ///
    /// `--new` РАЗДЕЛЯЕТ профили: первый профиль движок создаёт сам при старте,
    /// и общая секция принадлежит именно ему. Поставить `--new` перед первым
    /// значило бы завести профиль без `--filter-mark`, у которого
    /// `filter_mark_mask = 0` — он матчит любой пакет и выигрывает как первый.
    pub fn argv(&self, env: &Env) -> Vec<String> {
        let mut argv = vec![
            env.binary.to_string_lossy().into_owned(),
            format!("--uid={}:{}", env.uid, env.gid),
            format!("--qnum={}", self.queue.get()),
            format!("--fwmark=0x{DESYNC_MARK:08X}"),
        ];
        argv.extend(
            env.lua
                .iter()
                .map(|p| format!("--lua-init=@{}", p.to_string_lossy())),
        );

        for (i, profile) in self.profiles.iter().enumerate() {
            if i > 0 {
                argv.push("--new".to_string());
            }
            argv.push(profile.mark.filter_arg());
            argv.extend(profile.args.iter().cloned());
        }
        argv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env {
            binary: "/opt/zapret2/binaries/linux-x86_64/nfqws2".into(),
            lua: vec![
                "/opt/zapret2/lua/zapret-lib.lua".into(),
                "/opt/zapret2/lua/zapret-antidpi.lua".into(),
            ],
            uid: 65534,
            gid: 65534,
        }
    }

    fn plan_of(strategies: &[&str]) -> Plan {
        let owned: Vec<Vec<String>> = strategies
            .iter()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .collect();
        Plan::from_strategies(&FilterMark::granted(), QueueNum::new(200), &owned)
    }

    /// `--new` РАЗДЕЛЯЕТ профили, а не открывает их: первый профиль неявный.
    #[test]
    fn new_separates_profiles_so_there_are_k_minus_one() {
        let argv = plan_of(&["--a", "--b", "--c"]).argv(&env());
        assert_eq!(argv.iter().filter(|a| *a == "--new").count(), 2);
    }

    /// САМЫЙ ДОРОГОЙ ОТКАЗ. Профиль без `--filter-mark` имеет filter_mark_mask = 0,
    /// то есть матчит ЛЮБОЙ пакет, и как первый в списке выигрывает всегда —
    /// ни одна стратегия не применилась бы, при полном молчании движка.
    #[test]
    fn the_first_profile_carries_a_filter_mark() {
        let argv = plan_of(&["--a", "--b"]).argv(&env());
        let first_new = argv.iter().position(|a| a == "--new").expect("есть --new");
        assert!(
            argv[..first_new]
                .iter()
                .any(|a| a.starts_with("--filter-mark=")),
            "до первого --new обязан стоять --filter-mark: {argv:?}"
        );
    }

    #[test]
    fn every_profile_gets_its_own_mark_and_args_in_order() {
        let argv = plan_of(&["--a", "--b", "--c"]).argv(&env());
        let joined = argv.join(" ");
        assert!(joined.contains("--filter-mark=1/0xFFFF --a"), "{joined}");
        assert!(
            joined.contains("--new --filter-mark=2/0xFFFF --b"),
            "{joined}"
        );
        assert!(
            joined.contains("--new --filter-mark=3/0xFFFF --c"),
            "{joined}"
        );
    }

    /// Общие флаги — по одному разу и ДО первого --new (иначе уедут в профиль).
    #[test]
    fn global_flags_appear_once_before_the_first_profile_separator() {
        let argv = plan_of(&["--a", "--b"]).argv(&env());
        let first_new = argv.iter().position(|a| a == "--new").expect("есть --new");
        for prefix in ["--uid=", "--qnum=", "--fwmark=", "--lua-init=@"] {
            let all = argv.iter().filter(|a| a.starts_with(prefix)).count();
            let before = argv[..first_new]
                .iter()
                .filter(|a| a.starts_with(prefix))
                .count();
            let expected = if prefix == "--lua-init=@" { 2 } else { 1 };
            assert_eq!(all, expected, "{prefix} встречается {all} раз");
            assert_eq!(before, expected, "{prefix} должен стоять до первого --new");
        }
        assert_eq!(argv[0], "/opt/zapret2/binaries/linux-x86_64/nfqws2");
        assert!(argv.contains(&format!("--fwmark=0x{DESYNC_MARK:08X}")));
    }

    #[test]
    fn a_single_profile_plan_has_no_separator_at_all() {
        let argv = plan_of(&["--a"]).argv(&env());
        assert!(!argv.iter().any(|a| a == "--new"));
        assert!(argv.contains(&"--filter-mark=1/0xFFFF".to_string()));
    }

    #[test]
    fn marks_are_numbered_from_one_and_are_distinct() {
        let plan = plan_of(&["--a", "--b", "--c"]);
        let marks: Vec<u16> = plan.profiles().iter().map(|p| p.mark.index()).collect();
        assert_eq!(marks, vec![1, 2, 3]);
    }

    /// Связка с `CoreConfig::MAX_PROFILES_PER_INSTANCE` (`config.rs`), которую
    /// до этого теста стерегла только арифметика `validate_parallelism`, а не
    /// настоящее построение плана: разъедись они — валидатор пропускал бы
    /// значение, на котором `Plan::from_strategies` падает паникой на
    /// `.expect` (индекс `PROFILE_MASK + 1` как `u16` даёт ноль,
    /// `ProfileMark::new(0)` — `None`).
    ///
    /// `nfqws2` не смеет знать про `crate::config` (см. doc-комментарий
    /// `nfqws2::mod`), поэтому здесь берётся `PROFILE_MASK` напрямую — по
    /// определению `config.rs` это то же самое число
    /// (`MAX_PROFILES_PER_INSTANCE = PROFILE_MASK as usize`).
    #[test]
    fn a_plan_at_the_mark_ceiling_does_not_panic_and_the_last_mark_is_65535() {
        use crate::nfqws2::mark::PROFILE_MASK;

        let ceiling = PROFILE_MASK as usize;
        let strategies: Vec<Vec<String>> = (0..ceiling).map(|_| vec!["--a".to_string()]).collect();

        let plan = Plan::from_strategies(&FilterMark::granted(), QueueNum::new(200), &strategies);

        assert_eq!(plan.profiles().len(), ceiling);
        let last_mark = plan.profiles().last().expect("план непуст").mark.index();
        assert_eq!(last_mark, 65535);
        assert_eq!(u32::from(last_mark), PROFILE_MASK);
    }
}

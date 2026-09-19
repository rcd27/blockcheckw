//! Движок обязан умереть вместе с родителем — в том числе по `SIGKILL`, по которому не
//! отрабатывает НИ ОДИН хук.
//!
//! Почему это не покрывалось прежними тестами: уборка держится на обработчиках
//! `SIGINT`/`SIGTERM` и на `panic`-хуке (`cmd/mod.rs`), плюс `kill_on_drop` у ребёнка. Все
//! три — код, исполняемый умирающим процессом, а `SIGKILL` не даёт исполнить ничего. Продукт
//! третьего невода шлёт именно `SIGKILL` (подбор, переживший заказчика, держит линию зря), и
//! тогда на очереди остаётся `nfqws2`, а в ядре — наша таблица: продукт слепнет, а трафик
//! человека встаёт целиком. Час отладки, и не единожды.
//!
//! Root не нужен: роль движка играет `sleep`, роль подборщика — сам тестовый бинарь,
//! перезапущенный с переменной окружения.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Переменная, которой тестовый бинарь объявляет себе, что он — «родитель».
const ROLE: &str = "BCW_ORPHAN_ROLE";

/// Строка-договор между ролями: родитель печатает её, тест читает.
const PID_PREFIX: &str = "CHILD_PID=";

/// Жив ли процесс. Сигнал 0 — проверка доставки без доставки.
fn alive(pid: i32) -> bool {
    // SAFETY: `kill` с сигналом 0 ничего не доставляет, только проверяет право и существование.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[tokio::test]
async fn a_spawned_engine_dies_with_its_parent_even_on_sigkill() {
    // Роль родителя: спавнить ребёнка тем же кодом, каким это делает пайплайн, назвать его
    // pid и ждать смерти от чужой руки.
    if std::env::var(ROLE).as_deref() == Ok("parent") {
        let child = blockcheckw::system::process::BackgroundProcess::spawn(&["sleep", "30"])
            .expect("ребёнок запущен");
        println!("{PID_PREFIX}{}", child.pid().expect("pid ребёнка"));
        use std::io::Write;
        std::io::stdout()
            .flush()
            .expect("pid обязан доехать до читателя");
        tokio::time::sleep(Duration::from_secs(60)).await;
        return;
    }

    let mut parent = Command::new(std::env::current_exe().expect("путь к тестовому бинарю"))
        .args([
            "--exact",
            "a_spawned_engine_dies_with_its_parent_even_on_sigkill",
            "--nocapture",
        ])
        .env(ROLE, "parent")
        .stdout(Stdio::piped())
        .spawn()
        .expect("родитель запущен");

    let child_pid = {
        let stdout = parent.stdout.take().expect("stdout родителя");
        let mut lines = BufReader::new(stdout).lines();
        loop {
            let line = lines
                .next()
                .expect("родитель обязан назвать pid ребёнка")
                .expect("строка читается");
            if let Some(pid) = line.trim().strip_prefix(PID_PREFIX) {
                break pid.parse::<i32>().expect("pid — число");
            }
        }
    };

    assert!(
        alive(child_pid),
        "ребёнок обязан быть жив, пока жив родитель"
    );

    // SAFETY: убиваем процесс, который сами же и запустили.
    unsafe { libc::kill(parent.id() as i32, libc::SIGKILL) };
    let _ = parent.wait();

    let deadline = Instant::now() + Duration::from_secs(2);
    while alive(child_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }

    let survived = alive(child_pid);
    if survived {
        // SAFETY: прибираем за собой, иначе `sleep 30` переживёт сам тест — ровно та беда,
        // которую тест и описывает.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
    }
    assert!(
        !survived,
        "ребёнок пережил SIGKILL родителя: PR_SET_PDEATHSIG не поставлен, \
         и на боевой коробке на его месте остался бы nfqws2 на занятой очереди"
    );
}

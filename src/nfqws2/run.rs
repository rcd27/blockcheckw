use std::time::Duration;

use crate::nfqws2::capability::{classify_stderr, grant_from_help, StartFailure};
use crate::nfqws2::error::Error;
use crate::nfqws2::plan::{Env, FilterMark, Plan, QueueNum};
use crate::nfqws2::ready::{queue_bound, PROCFS_PATH};
use crate::system::process::BackgroundProcess;

/// Сколько ждать биндинга очереди. Щедро: на mipsel с UPX распаковка дольше.
pub const READY_TIMEOUT_MS: u64 = 2_000;
const READY_POLL_MS: u64 = 2;
const SMOKE_QUEUE_POLL_MS: u64 = 5;

/// Сколько ждать ответа `--help`. Команда мгновенная — щедрый потолок нужен
/// только чтобы не зависнуть намертво, если бинарь застрял (чужая
/// архитектура, битый статик-линк, что угодно).
const PROBE_TIMEOUT_MS: u64 = 2_000;
const PROBE_POLL_MS: u64 = 5;

/// Очереди для дымового запуска. Намеренно НЕ `base_qnum`: преflight доказывает
/// исправность бинаря (lua совпадает, архитектура та, есть nfnetlink_queue и
/// CAP_NET_ADMIN), а не свободу боевой очереди. Занятость боевой — работа
/// разрешателя конфликтов (`handle_bypass_conflicts`), и он запускается позже,
/// уже после преflight'а. Взять для дымового запуска саму `base_qnum` значило
/// бы запереть пользователя: свой же осиротевший nfqws2 на 200 после падения
/// blockcheckw давал бы `QueueBusy` на КАЖДОМ следующем запуске, а разрешатель,
/// который бы его снял, до этого места никогда бы не добрался.
const SMOKE_QUEUES: std::ops::RangeInclusive<u16> = 65526..=65535;

/// Пауза перед единственным повтором старта на `QueueBusy`.
///
/// Известная гонка: `stop()` предыдущего плана убивает процесс, но снятие
/// NFQUEUE-биндинга — дело ядра, а не немедленный побочный эффект вызова.
/// Пауза даёт ядру время освободить очередь между планами.
const QUEUE_BUSY_RETRY_DELAY_MS: u64 = 50;

/// Прочитать procfs и проверить, забиндена ли `queue`. `false`, если procfs
/// недоступен (нет модуля nfnetlink_queue, нет прав) — тем же допущением,
/// каким уже жили все три места, где раньше эта пара строк повторялась.
fn queue_is_bound(queue: QueueNum) -> bool {
    std::fs::read_to_string(PROCFS_PATH)
        .map(|p| queue_bound(&p, queue))
        .unwrap_or(false)
}

/// Живой процесс с загруженными профилями.
///
/// НЕ `Clone` намеренно: инстанс один на план, создаётся до цикла проб, цикл
/// берёт `&Instance`. Именно этим держится «один процесс на K стратегий» —
/// не тестом, а отсутствием кода, которым можно было бы поднять второй.
///
/// `Debug` требует того же от `BackgroundProcess`, который его и несёт
/// (`#[derive(Debug)]` на `src/system/process.rs:138`; `Arc<Mutex<Child>>`
/// его выводит, поэтому derive проходит).
#[derive(Debug)]
pub struct Instance {
    process: BackgroundProcess,
    queue: QueueNum,
}

/// Очередь забиндена. Без этого свидетельства правила ставить нельзя.
///
/// Помнит, ЗА КАКУЮ очередь ручается: `Ready`, полученный для 200, не должен
/// молча сойти за готовность 201 — иначе ровно тот отказ, от которого
/// свидетельство защищает (правило NFQUEUE без слушателя), просто переедет на
/// шаг дальше по конвейеру.
#[derive(Debug)]
pub struct Ready(QueueNum);

impl Ready {
    pub fn queue(&self) -> QueueNum {
        self.0
    }

    /// Только для тестов внутри крейта. В боевой сборке конструктора нет вовсе,
    /// и `Ready` может выдать лишь `wait_ready` — после того, как очередь
    /// действительно забиндена.
    #[cfg(test)]
    pub(crate) fn witnessed(queue: QueueNum) -> Self {
        Ready(queue)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNfqws2;

impl SystemNfqws2 {
    /// Понимает ли бинарь `--filter-mark`.
    ///
    /// Синхронна, потому что синхронна вся цепочка вызова: `check_prerequisites`
    /// (вызывается на `src/main.rs:403`) сама не async, хотя выполняется внутри уже
    /// поднятого `#[tokio::main]`-рантайма, а не до его инициализации — здесь
    /// это не помешает, потому что на момент вызова параллельных задач в
    /// рантайме ещё нет. `probe_sync` сам быстрый (один `--help`); дольше
    /// блокирует воркер сосед `smoke_sync` — до `READY_TIMEOUT_MS` через
    /// `std::thread::sleep`, а на одноядерном OpenWrt у multi-thread рантайма
    /// это единственный воркер. Если точку вызова когда-нибудь подвинут ближе
    /// к работающему пайплайну, это допущение придётся перепроверить.
    pub fn probe_sync(env: &Env) -> Result<FilterMark, Error> {
        // `Command::output()` голышом не годится: у него нет потолка, и
        // застрявший бинарь (чужая архитектура, битый статик-линк) вешает
        // blockcheckw намертво прямо на "Checking prerequisites" без единого
        // символа дальше. Тот же приём kill+wait по дедлайну, что в
        // `smoke_sync` ниже.
        let mut child = std::process::Command::new(&env.binary)
            .arg("--help")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Spawn {
                reason: e.to_string(),
            })?;

        let deadline = std::time::Instant::now() + Duration::from_millis(PROBE_TIMEOUT_MS);
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {}
                Err(e) => {
                    return Err(Error::Spawn {
                        reason: e.to_string(),
                    })
                }
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::ProbeTimeout {
                    timeout_ms: PROBE_TIMEOUT_MS,
                });
            }
            std::thread::sleep(Duration::from_millis(PROBE_POLL_MS));
        }

        // Процесс уже реапнут выше (`try_wait` вернул `Some`) — читать пайпы
        // безопасно, писавший конец закрыт.
        use std::io::Read;
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let help = format!("{stdout}{stderr}");
        grant_from_help(&help).ok_or(Error::NoFilterMark)
    }

    /// Дымовой запуск: поднять минимальный инстанс на одной из `SMOKE_QUEUES`,
    /// дождаться биндинга, убить.
    ///
    /// Очередь выбирает сама — не боевую `base_qnum` (см. doc-комментарий
    /// `SMOKE_QUEUES`). Перебирает диапазон по возрастанию, берёт первую
    /// незанятую; `QueueBusy` возвращается, только если заняты все десять —
    /// событие достаточно странное само по себе, чтобы не пытаться угадать
    /// дальше.
    pub fn smoke_sync(env: &Env, witness: &FilterMark) -> Result<(), Error> {
        let mut last_queue = *SMOKE_QUEUES.start();
        for q in SMOKE_QUEUES {
            last_queue = q;
            match Self::smoke_on_queue(env, witness, QueueNum::new(q)) {
                // Эта очередь занята — пробуем следующую. Любой другой отказ
                // (архитектура, lua, CAP_NET_ADMIN) не зависит от выбора
                // очереди — возвращаем сразу, повтор ничего не даст.
                Err(Error::QueueBusy { .. }) => continue,
                other => return other,
            }
        }
        Err(Error::QueueBusy { queue: last_queue })
    }

    /// Единственное место, где мы вообще ВИДИМ stderr движка: боевой путь шлёт
    /// его в /dev/null, и причина отказа иначе не видна никогда.
    fn smoke_on_queue(env: &Env, witness: &FilterMark, queue: QueueNum) -> Result<(), Error> {
        // Занята ли очередь ДО нашего спавна. `queue_bound` отвечает «занята
        // кем-то», не «занята нами» — если там уже сидит орфан прошлого
        // прогона, старый nfqws или чужой пользователь NFQUEUE, наш ребёнок
        // может не успеть добавить ни строчки в procfs, а первая же проверка
        // после спавна всё равно увидит «забиндено» и отрапортует успех за
        // чужой процесс. Проверяем факт занятости, не владельца: сверять
        // peer_portid второй колонки с pid ребёнка нельзя — netlink-portid не
        // обязан совпадать с pid, это дало бы ложные таймауты.
        if queue_is_bound(queue) {
            return Err(Error::QueueBusy { queue: queue.get() });
        }

        let plan = Plan::from_strategies(witness, queue, &[Vec::new()]);
        let argv = plan.argv(env);
        // Спавним напрямую через std::process, не через BackgroundProcess::spawn:
        // тот регистрирует ребёнка в общем реестре ради shutdown-хуков, но
        // жёстко шлёт его stdout/stderr в /dev/null. Перехват stderr — это
        // весь смысл smoke_sync (см. doc-комментарий метода), так что цена
        // мимо реестра здесь осознанная: этот ребёнок недолговечен и снимается
        // самим smoke_sync (kill+wait ниже) до возврата из функции.
        let mut child = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Spawn {
                reason: e.to_string(),
            })?;

        enum Outcome {
            Bound,
            Failed(Error),
            TimedOut,
        }

        let deadline = std::time::Instant::now() + Duration::from_millis(READY_TIMEOUT_MS);
        let outcome = loop {
            // `Err` от `try_wait` неотличим от «жив» — тем же способом, каким
            // это уже читает `BackgroundProcess::try_wait` (`process.rs:189`,
            // ветка `_ => None`). Приемлемо: при упорной ошибке опроса цикл
            // просто доработает до дедлайна и отдаст таймаут вместо паники —
            // не идеальный диагноз, но не зависание.
            if let Ok(Some(status)) = child.try_wait() {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                break Outcome::Failed(match classify_stderr(&stderr) {
                    StartFailure::LuaVersion => Error::LuaVersionMismatch {
                        lua_dir: env
                            .lua
                            .first()
                            .and_then(|p| p.parent())
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "<lua>".to_string()),
                    },
                    StartFailure::UnknownOption => Error::NoFilterMark,
                    StartFailure::Other(text) => Error::ExitedImmediately {
                        code: status.code().unwrap_or(-1),
                        stderr: text,
                    },
                });
            }
            if queue_is_bound(queue) {
                break Outcome::Bound;
            }
            if std::time::Instant::now() >= deadline {
                break Outcome::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(SMOKE_QUEUE_POLL_MS));
        };

        let _ = child.kill();
        let _ = child.wait();

        match outcome {
            Outcome::Bound => Ok(()),
            Outcome::Failed(e) => Err(e),
            Outcome::TimedOut => {
                // Пайп читаем ТОЛЬКО здесь, после kill+wait: пишущий конец
                // гарантированно закрыт (процесс снят и реапнут), читающий —
                // наш, чтение безопасно и не блокирует. Раньше — до kill —
                // читать было нельзя: движок, ещё живой и написавший больше
                // ёмкости пайпа (64 КиБ), заблокировался бы на записи, а мы
                // остались бы ждать чтения от процесса, который сам ждёт нас.
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                Err(Error::QueueNotBound {
                    queue: queue.get(),
                    timeout_ms: READY_TIMEOUT_MS,
                    stderr: stderr.trim().to_string(),
                })
            }
        }
    }

    /// Поднять инстанс по плану.
    ///
    /// Один повтор на `QueueBusy`: известная гонка, при которой `stop()`
    /// предыдущего плана убивает процесс, но ядро освобождает NFQUEUE-биндинг
    /// не мгновенно. Повторяем только эту причину и только один раз —
    /// остальные отказы (архитектура, lua, права) от повтора не изменятся.
    /// Раньше повтор жил у единственного вызывающего (`pipeline::runner`),
    /// но `check`/`test_runner` зовут `start` в намного более плотном цикле
    /// (старт-стоп на каждую стратегию, на каждый проход) — и там та же
    /// гонка бьёт чаще, просто не была обвешана повтором. Логика одна для
    /// всех вызывающих, поэтому и живёт здесь, а не у одного из них.
    pub async fn start(env: &Env, plan: &Plan) -> Result<Instance, Error> {
        match Self::start_once(env, plan) {
            Err(Error::QueueBusy { .. }) => {
                tokio::time::sleep(Duration::from_millis(QUEUE_BUSY_RETRY_DELAY_MS)).await;
                Self::start_once(env, plan)
            }
            other => other,
        }
    }

    fn start_once(env: &Env, plan: &Plan) -> Result<Instance, Error> {
        // Та же проверка, что в `smoke_sync`, и по той же причине: без неё
        // правила уедут на очередь, которую обслуживает чужой процесс, а скан
        // молча измерит чужую политику вместо своей.
        if queue_is_bound(plan.queue()) {
            return Err(Error::QueueBusy {
                queue: plan.queue().get(),
            });
        }

        let argv = plan.argv(env);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let process = BackgroundProcess::spawn(&refs).map_err(|e| Error::Spawn {
            reason: e.to_string(),
        })?;
        Ok(Instance {
            process,
            queue: plan.queue(),
        })
    }

    /// Дождаться, пока очередь окажется забиндена. Не сон: опрос procfs с
    /// проверкой живости процесса на каждой итерации.
    pub async fn wait_ready(instance: &mut Instance) -> Result<Ready, Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(READY_TIMEOUT_MS);
        loop {
            if let Some(code) = instance.process.try_wait().await {
                return Err(Error::ExitedImmediately {
                    code,
                    stderr: "stderr движка на боевом пути не перехватывается; \
                             диагностика — в check_prerequisites"
                        .to_string(),
                });
            }
            // std::fs, а не tokio::fs, и это осознанно. procfs — виртуальная
            // файловая система: чтение занимает микросекунды и не блокирует ни
            // на чём. `tokio::fs` отправил бы каждую такую операцию в пул
            // блокирующих потоков — чистые накладные расходы на цикле опроса с
            // шагом 2 мс, — и потребовал бы фичи `fs`, которой в Cargo.toml нет
            // и которая выросла бы в девять статических musl-бинарей.
            if queue_is_bound(instance.queue) {
                return Ok(Ready(instance.queue));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::QueueNotBound {
                    queue: instance.queue.get(),
                    timeout_ms: READY_TIMEOUT_MS,
                    stderr: "stderr движка на боевом пути не перехватывается; \
                             диагностика — в check_prerequisites"
                        .to_string(),
                });
            }
            tokio::time::sleep(Duration::from_millis(READY_POLL_MS)).await;
        }
    }

    /// Снять инстанс, потребив хэндл.
    pub async fn stop(mut instance: Instance) {
        instance.process.kill().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn stub_env(binary: impl Into<std::path::PathBuf>) -> Env {
        Env {
            binary: binary.into(),
            lua: Vec::new(),
            uid: 65534,
            gid: 65534,
        }
    }

    /// Удаляет временный скрипт-заглушку при выходе из области видимости —
    /// и при успехе, и при панике теста, — чтобы не мусорить во временном
    /// каталоге.
    struct TempScript(std::path::PathBuf);

    impl Drop for TempScript {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write_stub_script(body: &str) -> TempScript {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "nfqws2-run-test-stub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("время не могло убежать в прошлое")
                .as_nanos()
        );
        path.push(unique);
        {
            let mut f = std::fs::File::create(&path).expect("создать скрипт-заглушку");
            f.write_all(body.as_bytes())
                .expect("записать скрипт-заглушку");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .expect("прочитать права скрипта-заглушки")
                .permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&path, perms).expect("сделать скрипт-заглушку исполняемой");
        }
        TempScript(path)
    }

    /// Ранний выход движка распознаётся как `ExitedImmediately` с верным
    /// кодом: покрывает раннюю ветку цикла — взятие пайпа, `classify_stderr`
    /// на пустом stderr, реапинг.
    #[test]
    fn an_early_exit_is_reported_as_exited_immediately() {
        let env = stub_env("/bin/false");
        let witness = FilterMark::granted();
        let result = SystemNfqws2::smoke_sync(&env, &witness);
        assert!(
            matches!(result, Err(Error::ExitedImmediately { code: 1, .. })),
            "{result:?}"
        );
    }

    /// Бинаря нет вообще — это `Error::Spawn`, а не паника и не таймаут в
    /// 2 секунды.
    #[test]
    fn a_missing_binary_is_reported_as_a_spawn_failure() {
        let env = stub_env("/nonexistent-binary-for-nfqws2-run-test");
        let witness = FilterMark::granted();
        let result = SystemNfqws2::smoke_sync(&env, &witness);
        assert!(matches!(result, Err(Error::Spawn { .. })), "{result:?}");
    }

    /// Несовместимость lua-скриптов распознаётся по тексту stderr движка —
    /// покрывает `classify_stderr` на реальном сообщении об ошибке.
    #[test]
    fn a_lua_version_mismatch_is_classified_from_stderr() {
        let script = write_stub_script(
            "#!/bin/sh\n\
             echo 'LUA ERROR: Incompatible NFQWS2_COMPAT_VER: got 3, want 5' >&2\n\
             exit 1\n",
        );
        let env = stub_env(script.0.clone());
        let witness = FilterMark::granted();
        let result = SystemNfqws2::smoke_sync(&env, &witness);
        assert!(
            matches!(result, Err(Error::LuaVersionMismatch { .. })),
            "{result:?}"
        );
    }
}

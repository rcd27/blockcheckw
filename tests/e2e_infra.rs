//! Infrastructure e2e tests — verify SO_MARK, real-kernel nftables dispatch, autottl pipeline.
//!
//! Requires: root, nfqws2 installed, nftables available.
//! Run: `sudo cargo test --test e2e_infra -- --nocapture`

use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use blockcheckw::config::{CoreConfig, Protocol, DEFAULT_NFT_TABLE};
use blockcheckw::firewall::nft::SystemNft;
use blockcheckw::firewall::nftables;
use blockcheckw::network::http_client;
use blockcheckw::nfqws2::mark::ProfileMark;
use blockcheckw::nfqws2::plan::{FilterMark, Plan, QueueNum};
use blockcheckw::nfqws2::ready::{queue_bound, PROCFS_PATH};
use blockcheckw::nfqws2::run::SystemNfqws2;
use blockcheckw::system::process::run_process;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Настоящая проверка `--filter-mark` через `--help` реального бинаря.
/// Тестовый ярлык `FilterMark::granted` виден только внутри `blockcheckw`
/// (`#[cfg(test)] pub(crate)`) — вне крейта, в этом файле, свидетельство
/// получить можно только так же, как это делает сам продукт
/// (`check_prerequisites`, `src/main.rs`).
fn probe_witness(config: &CoreConfig) -> FilterMark {
    SystemNfqws2::probe_sync(&config.nfqws2_env())
        .expect("nfqws2 must support --filter-mark (build >= v1.0.5)")
}

/// Забиндена ли очередь прямо сейчас — тем же способом, каким это проверяет
/// исполнитель (`nfqws2::run::queue_is_bound`, приватная копия этой же пары
/// строк). `Instance` не выдаёт `try_wait` наружу крейта (единственные точки
/// входа — `SystemNfqws2::wait_ready`/`stop`), поэтому «процесс всё ещё
/// живой» здесь проверяется через то, что единственно наблюдаемо снаружи:
/// осталась ли очередь забиндена. НЕ доказывает, что через очередь прошёл
/// хоть один пакет — для этого нужен `queue_sequence` ниже.
fn queue_still_bound(queue: QueueNum) -> bool {
    std::fs::read_to_string(PROCFS_PATH)
        .map(|p| queue_bound(&p, queue))
        .unwrap_or(false)
}

/// Насколько продвинулась последовательность очереди между двумя снимками
/// `queue_sequence`, с учётом возможного оборота 32-битного счётчика
/// (`wrapping_sub`). `None`, если хотя бы один снимок недоступен (очередь не
/// была забиндена в этот момент). Используется тестом приёмки маски (§4):
/// «проба дошла и туда, и обратно» доказывается тем, что через очередь
/// прошло НЕ МЕНЬШЕ двух пакетов (исходящий SYN + входящий SYN/ACK), а не
/// просто «хоть один» — иначе тест доказывал бы только исходящее
/// направление и был бы вакуумен по входящему (Fix round 1, M1).
fn seq_delta(before: Option<u32>, after: Option<u32>) -> Option<u32> {
    match (before, after) {
        (Some(b), Some(a)) => Some(a.wrapping_sub(b)),
        _ => None,
    }
}

/// Номер профиля из строки вида `desync profile 2 (noname) matches` или
/// `using cached desync profile 2 (noname)` — обе формы, которыми `nfqws2`
/// объявляет выбор профиля для конкретного пакета (`nfq2/desync.c`).
fn extract_profile_number(line: &str) -> Option<u32> {
    let rest = line
        .strip_prefix("desync profile ")
        .or_else(|| line.strip_prefix("using cached desync profile "))?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Какие профили движок выбирал для пакетов с данной меткой (`mark=XXXXXXXX`,
/// восемь hex-цифр без `0x` — ровно как в его же логе, `nfq2/nfqws.c:316`
/// `"\npacket: id=%d len=%d mark=%08X ..."`).
///
/// Fix round 3: разбор ПО МЕТКЕ пакета, а не по тому, ДО или ПОСЛЕ какой
/// границы чтения файла строка оказалась. Первая попытка изолировать пробу 2
/// была позиционной (граница — конец лога сразу после чтения пробы 1) и
/// ловила ложные срабатывания: TCP-соединение пробы 1 может ещё дописывать
/// свой хвост (поздние ACK/FIN, `fake`-стратегия держит `instance cutoff`)
/// уже ПОСЛЕ того, как проба 2 стартовала — эти пакеты несут МЕТКУ профиля 1
/// и корректно уходят в профиль 1, но позиционная граница засчитывала их как
/// «профиль 1 всплыл в окне пробы 2». Метка пакета — это то, что движок
/// реально видит и чем реально руководствуется при выборе профиля
/// (`--filter-mark`), поэтому это единственно правильный ключ для проверки
/// избирательности: не «что происходило в это время», а «что движок сделал
/// с ЭТИМ пакетом».
fn profiles_for_mark(log: &str, mark_hex: &str) -> Vec<u32> {
    let marker = format!("mark={mark_hex}");
    let lines: Vec<&str> = log.lines().collect();
    let mut hits = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !(line.starts_with("packet: id=") && line.contains(&marker)) {
            continue;
        }
        // Профиль для ЭТОГО пакета — на ближайшей строке до начала блока
        // следующего пакета (или до конца лога).
        for later in &lines[i + 1..] {
            if later.starts_with("packet: id=") {
                break;
            }
            if let Some(n) = extract_profile_number(later) {
                hits.push(n);
                break;
            }
        }
    }
    hits
}

/// Порядковый номер последнего пакета, дошедшего до очереди — восьмое поле
/// `/proc/net/netfilter/nfnetlink_queue` (`man 5 proc`: «Every queued packet
/// is associated with a (32-bit) monotonically increasing sequence number.
/// This shows the ID of the most recent packet queued»). Растёт с каждым
/// пакетом и не откатывается назад.
///
/// НЕ третье поле (`queue_total`): та же страница `man 5 proc` описывает его
/// как «number of packets currently queued and waiting to be processed» —
/// текущий бэклог, а не счётчик прошедших. `nfqws2` выносит вердикт за
/// микросекунды и не оставляет пакет висеть в очереди, так что `queue_total`
/// почти всегда 0 что до, что после — проверка по нему была бы тестом на
/// шум, а не на то, что диспетчеризация реально довела пакет до движка.
fn queue_sequence(queue: QueueNum) -> Option<u32> {
    let content = std::fs::read_to_string(PROCFS_PATH).ok()?;
    content.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0].parse::<u16>().ok()? != queue.get() {
            return None;
        }
        fields[7].parse::<u32>().ok()
    })
}

// ── Test 1: SO_MARK is set before connect ────────────────────────────────────

#[tokio::test]
async fn so_mark_set_on_socket() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    let fwmark = ProfileMark::new(1).expect("ненулевой индекс").so_mark();
    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    let stream = http_client::marked_tcp_connect(addr, fwmark).await.unwrap();

    let fd = stream.as_raw_fd();
    let mut mark_out: u32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<u32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark_out as *mut u32 as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(ret, 0, "getsockopt failed");
    assert_eq!(
        mark_out, fwmark,
        "SO_MARK should be {fwmark:#010X}, got {mark_out:#010X}"
    );
}

#[tokio::test]
async fn so_mark_zero_means_no_mark() {
    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    let stream = http_client::marked_tcp_connect(addr, 0).await.unwrap();

    let fd = stream.as_raw_fd();
    let mut mark_out: u32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<u32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark_out as *mut u32 as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(ret, 0, "getsockopt failed");
    assert_eq!(mark_out, 0, "SO_MARK should be 0 for baseline");
}

// ── Test 2: dispatch rules on a real kernel ──────────────────────────────────

/// До #68ч2: N воркеров давали N цепочек и N элементов в двух vmap'ах
/// (`postnat_qmap`/`prenat_qmap`) — снесённая вместе с `src/worker/` схема,
/// где каждый новый воркер добавлял ещё одну цепочку и ещё один элемент.
/// Теперь диспетчеризация — ровно ДВА статических правила (по одному в
/// `postnat` и в `prenat`) независимо от числа профилей в плане; мокнутый
/// вариант этого утверждения уже живёт в
/// `nftables::dispatch_tests::dispatch_is_exactly_two_rules`
/// (`src/firewall/nftables.rs`), здесь — то же самое на настоящем `nft`:
/// план из трёх профилей не должен породить больше двух упоминаний `queue`
/// (по одному на каждую хук-цепочку), и после `remove_dispatch` от них не
/// должно остаться следа.
#[tokio::test]
async fn nft_dispatch_add_remove_rules_on_real_kernel() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    const TABLE: &str = "zapret_test_dispatch";
    let config = CoreConfig::default();
    let witness = probe_witness(&config);
    let queue = QueueNum::new(500);
    let ips = vec!["1.1.1.1".to_string()];

    let table = nftables::prepare_table(&SystemNft, TABLE)
        .await
        .expect("prepare_table");

    let strategies = vec![
        vec!["--lua-desync=fake:ttl=1".to_string()],
        vec!["--lua-desync=fake:ttl=2".to_string()],
        vec!["--lua-desync=fake:ttl=3".to_string()],
    ];
    let env = config.nfqws2_env();
    let plan = Plan::from_strategies(&witness, queue, &strategies);
    let mut instance = SystemNfqws2::start(&env, &plan)
        .await
        .expect("start nfqws2");
    let ready = SystemNfqws2::wait_ready(&mut instance)
        .await
        .expect("nfqws2 must bind the queue");

    nftables::apply_dispatch(&SystemNft, &table, &ready, &plan.dispatch(443), &ips)
        .await
        .expect("apply_dispatch");

    // Собрать факты ДО разбора хвостов: паника между `apply_dispatch` и
    // `remove_dispatch`/`stop`/`drop_table` иначе оставила бы на стенде
    // таблицу с правилом `queue to {queue}` без слушателя — помеченные
    // пакеты на этот адрес и порт молча дропались бы, а продуктовый
    // `prepare_table` эту таблицу не подобрал бы: имя чужое (см.
    // `foreign_zapret1_table_survives_our_cleanup` — тот же приём).
    //
    // `nft list` тоже может отказать — по таймауту в 5с в том числе, на
    // нагруженной машине это реалистично. `.expect` здесь паниковал бы и
    // пропустил уборку ниже — ровно тот отказ, от которого уборка защищает,
    // просто сдвинутый на шаг раньше. Поэтому не `.expect`, а откат к
    // пустой строке; что чтение не удалось, всё равно валит тест — ниже,
    // уже после уборки, явным ассертом на непустоту.
    let content = run_process(&["nft", "list", "table", "inet", TABLE], 5000)
        .await
        .map(|r| r.stdout)
        .unwrap_or_default();

    nftables::remove_dispatch(&SystemNft, &table).await;
    SystemNfqws2::stop(instance).await;

    let content_after_remove = run_process(&["nft", "list", "table", "inet", TABLE], 5000)
        .await
        .map(|r| r.stdout)
        .unwrap_or_default();

    let _ = table.drop_table(&SystemNft).await;

    // Только теперь — ассерты. Таблица уже снесена независимо от их исхода.
    assert!(
        !content.is_empty(),
        "nft list table timed out or failed before cleanup — table state is unknown"
    );
    assert!(
        !content_after_remove.is_empty(),
        "nft list table timed out or failed after remove_dispatch — table state is unknown"
    );
    let queue_mentions = content.matches("queue num").count() + content.matches("queue to").count();
    assert_eq!(
        queue_mentions, 2,
        "ровно два правила должны ссылаться на очередь (postnat + prenat), \
         независимо от 3 профилей в плане:\n{content}"
    );
    assert!(
        content.contains(&format!("queue num {}", queue.get()))
            || content.contains(&format!("queue to {}", queue.get())),
        "table should dispatch to queue {}. Content:\n{content}",
        queue.get(),
    );
    assert!(
        !content.contains("postnat_qmap") && !content.contains("prenat_qmap"),
        "vmap-схемы больше не существует:\n{content}"
    );
    assert!(
        !content_after_remove.contains("queue num") && !content_after_remove.contains("queue to"),
        "queue directive should be gone after remove_dispatch:\n{content_after_remove}"
    );
}

// ── Test 3: nfqws2 receives queued packets ───────────────────────────────────

/// Не просто «процесс не упал»: `queue_sequence` доказывает, что через
/// очередь реально прошёл пакет — то есть диспетчеризация действительно
/// свела помеченный трафик именно на эту очередь (не та марка, не тот порт,
/// не тот `--filter-mark` — и тест был бы зелёным на любой реализации, где
/// движок просто не падает).
#[tokio::test]
async fn nfqws2_receives_marked_traffic() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    const TABLE: &str = "zapret_test_nfqws2";
    let config = CoreConfig::default();
    let witness = probe_witness(&config);
    let queue = QueueNum::new(600);
    let ips = vec!["1.1.1.1".to_string()];

    let table = nftables::prepare_table(&SystemNft, TABLE)
        .await
        .expect("prepare_table");

    let strategy = vec!["--lua-desync=fake:ttl=1".to_string()];
    let env = config.nfqws2_env();
    let plan = Plan::from_strategies(&witness, queue, &[strategy]);
    let mark = plan.profiles()[0].mark;

    let mut instance = SystemNfqws2::start(&env, &plan)
        .await
        .expect("start nfqws2");
    let ready = SystemNfqws2::wait_ready(&mut instance)
        .await
        .expect("nfqws2 must bind the queue");

    nftables::apply_dispatch(&SystemNft, &table, &ready, &plan.dispatch(80), &ips)
        .await
        .expect("apply_dispatch");

    let seq_before = queue_sequence(queue);

    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http_client::marked_tcp_connect(addr, mark.so_mark()),
    )
    .await;

    let seq_after = queue_sequence(queue);
    let still_bound = queue_still_bound(queue);

    // Собрать факты ДО сноса — падение ассерта ниже не должно оставить на
    // стенде таблицу с правилом `queue to {queue}` без слушателя (см. тот же
    // приём в `nft_dispatch_add_remove_rules_on_real_kernel`).
    nftables::remove_dispatch(&SystemNft, &table).await;
    SystemNfqws2::stop(instance).await;
    let _ = table.drop_table(&SystemNft).await;

    assert!(
        still_bound,
        "queue should still be bound after processing traffic — nfqws2 must not have crashed"
    );
    assert!(
        seq_before.is_some() && seq_after.is_some(),
        "queue {} should be present in procfs while apply_dispatch's rules are live \
         (before={seq_before:?}, after={seq_after:?})",
        queue.get(),
    );
    assert_ne!(
        seq_before, seq_after,
        "queue sequence should have advanced — the marked SYN must have reached nfqws2 \
         through the dispatch rules (before={seq_before:?}, after={seq_after:?})"
    );
}

// ── Test 4: autottl pipeline — prenat captures SYN/ACK ───────────────────────

#[tokio::test]
async fn autottl_prenat_captures_synack() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    const TABLE: &str = "zapret_test_autottl";
    let config = CoreConfig::default();
    let witness = probe_witness(&config);
    let queue = QueueNum::new(700);
    let ips = vec!["1.1.1.1".to_string()];

    let table = nftables::prepare_table(&SystemNft, TABLE)
        .await
        .expect("prepare_table");

    let strategy = vec!["--lua-desync=fake:autottl=-2,3-20".to_string()];
    let env = config.nfqws2_env();
    let plan = Plan::from_strategies(&witness, queue, &[strategy]);
    let mark = plan.profiles()[0].mark;

    let mut instance = SystemNfqws2::start(&env, &plan)
        .await
        .expect("start nfqws2");
    let ready = SystemNfqws2::wait_ready(&mut instance)
        .await
        .expect("nfqws2 must bind the queue");

    nftables::apply_dispatch(&SystemNft, &table, &ready, &plan.dispatch(443), &ips)
        .await
        .expect("apply_dispatch");

    // Verify prenat chain has the SYN/ACK dispatch rule.
    //
    // Не `.expect`: `nft list` может отказать по таймауту в 5с на
    // нагруженной машине, а `.expect` здесь паниковал бы ДО уборки ниже и
    // оставил бы на стенде правило `queue to {queue}` без слушателя — тот
    // же отказ, от которого уборка защищает, просто сдвинутый на шаг
    // раньше. Откат к пустой строке; что чтение не удалось, всё равно
    // валит тест — ассертом на непустоту после уборки.
    let prenat_content = run_process(&["nft", "list", "chain", "inet", TABLE, "prenat"], 5000)
        .await
        .map(|r| r.stdout)
        .unwrap_or_default();

    // Make a marked TLS connection
    let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let _connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http_client::marked_tcp_connect(addr, mark.so_mark()),
    )
    .await;

    let still_bound = queue_still_bound(queue);

    // Check conntrack for ct mark — derived from the packet mark by the dispatch
    // rule itself (`ct mark set mark or DESYNC_MARK`), no per-profile rule needed.
    // Informational only (no assert!): conntrack entries are best-effort evidence,
    // not a hard invariant this test enforces.
    if let Ok(ct_result) = run_process(
        &[
            "conntrack",
            "-L",
            "-d",
            "1.1.1.1",
            "-p",
            "tcp",
            "--dport",
            "443",
        ],
        5000,
    )
    .await
    {
        let combined = mark.ct_mark();
        let has_mark = ct_result.stdout.lines().any(|line| {
            line.contains(&format!("mark={combined}"))
                || line.contains(&format!("mark=0x{combined:08x}"))
        });
        eprintln!("conntrack output:\n{}", ct_result.stdout);
        if has_mark {
            eprintln!("OK: conntrack entry has combined DESYNC|WORKER mark");
        } else {
            eprintln!("WARNING: no conntrack entry with expected mark found");
        }
    }

    // Собрать факты ДО сноса — падение ассерта ниже не должно оставить на
    // стенде таблицу с правилом `queue to {queue}` без слушателя (тот же
    // приём, что в `nft_dispatch_add_remove_rules_on_real_kernel`).
    nftables::remove_dispatch(&SystemNft, &table).await;
    SystemNfqws2::stop(instance).await;
    let _ = table.drop_table(&SystemNft).await;

    assert!(
        !prenat_content.is_empty(),
        "nft list chain prenat timed out or failed before cleanup — chain state is unknown"
    );
    assert!(
        prenat_content.contains("syn") || prenat_content.contains("flags"),
        "prenat chain should have SYN/ACK matching rule. Content:\n{prenat_content}"
    );
    assert!(
        prenat_content.contains("queue"),
        "prenat chain should dispatch to a queue. Content:\n{prenat_content}"
    );
    assert!(
        still_bound,
        "queue should still be bound after autottl flow"
    );
}

// ── Test 4b: приёмка ловушки §4 — маска восстановления и отбор профиля ──────

/// Приёмка ловушки §4 (`docs/research/68-nfqws2-parallelism.md`): забытая
/// маска восстановления не даёт НИКАКОГО видимого симптома, кроме одной
/// строки в отладочном логе `nfqws2`. Четыре утверждения (Fix round 1 добавил
/// №2 и усилил №1 — см. ниже):
/// 1. `ignoring generated packet` не встречается вообще — иначе входящие
///    (SYN/ACK от сервера) молча отбрасываются как «свой сгенерированный
///    пакет» (nfq2/nfqws.c:159), хотя сама очередь и весь конвейер выглядят
///    рабочими. Заявление стоит чего-то только если во ВХОДЯЩЕМ направлении
///    вообще был трафик — иначе тест зелёный и на сломанной маске просто
///    потому, что серверный ответ никогда не приходил (M1: `seq_delta`
///    ниже требует ≥2 пакетов на пробу — исходящий SYN и входящий SYN/ACK,
///    а не «хоть один», иначе assert доказывал бы только исходящее
///    направление);
/// 2. проба с маркой профиля 1 реально поднимает профиль 1 (нижняя планка —
///    без неё «профиль 2 не поднялся» ничего не стоит: движок мог бы вообще
///    не видеть трафик);
/// 3. проба с маркой профиля 2 НЕ поднимает профиль 1 — отбор по
///    `--filter-mark` избирателен, а не «профиль 1 матчит всё подряд и
///    поэтому эта проверка проходит сама собой»;
/// 4. проба с маркой профиля 2 РЕАЛЬНО поднимает профиль 2 (M2: без этого
///    утверждение 3 — вакуумно тоже: если проба 2 вообще не дошла до
///    движка, лог пуст, и «профиль 1 не поднялся» истинно просто по
///    отсутствию каких-либо данных).
///
/// Перехват стендового лога: боевой путь (`BackgroundProcess::spawn`) шлёт
/// stdout/stderr движка в `/dev/null` безусловно, а получить `Ready` для
/// `apply_dispatch` можно только через `SystemNfqws2::wait_ready` на
/// настоящем `Instance` — то есть только через `SystemNfqws2::start`, у
/// которого нет параметра для перехвата stderr (в отличие от
/// `smoke_on_queue`, который спавнит образец в обход `BackgroundProcess`
/// именно ради этого). Раздваивать процесс (один — с даёт `Ready`, другой —
/// со своим stderr) нельзя: второй не смог бы забиндить ту же самую очередь.
///
/// Выход — `--debug=@<file>`: нативная опция `nfqws2` (`nfq2/nfqws.c`,
/// `IDX_DEBUG`), которая переключает `DLOG` на запись в файл вместо
/// stdout/stderr (`params.debug_target = LOG_TARGET_FILE`) и потому вообще не
/// зависит от того, куда `BackgroundProcess` дел файловые дескрипторы
/// процесса. Как глобальный параметр, `--debug` действует независимо от
/// того, в аргументах какого профиля он встретился в argv (`--new`
/// перегружает только per-profile поля, `nfq2/nfqws.c` `case IDX_NEW`) — так
/// что флаг можно просто дописать в args первого профиля и получить ТОЧНО ТУ
/// ЖЕ командную строку, что построил бы `Plan::argv` в продакшене, плюс один
/// синтетический флаг — тем же приёмом, каким остальные тесты файла уже
/// подсовывают синтетические стратегии. Каждая строка лога дополнительно
/// пишется отдельным `fopen(..., "at") + fclose` (`nfq2/params.c:
/// DLOG_FILENAME_VA`), поэтому хвост не теряется даже под `SIGKILL`
/// (`SystemNfqws2::stop`) — в отличие от пайпа stderr, который пришлось бы
/// аккуратно вычитывать до килла.
///
/// Адрес цели — `1.0.0.1` (вторичный anycast Cloudflare), НЕ `1.1.1.1`,
/// который уже используют тесты 2 и 4 на том же `dport 443`: `queue` в
/// диспетчеризации терминален (первое совпавшее правило побеждает), а
/// `cargo test` гоняет тесты этого файла параллельно — с тем же daddr гонка
/// между этим тестом и тестом 4 могла бы увести пакет в ЧУЖУЮ таблицу и её
/// очередь, что превратило бы вакуумность из M1/M2 в реальный флейк, а не
/// только в теоретический риск (M4).
#[tokio::test]
async fn the_mask_is_not_forgotten_and_profiles_are_selective() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    const TABLE: &str = "zapret_test_mask";
    const TARGET_IP: &str = "1.0.0.1";
    let config = CoreConfig::default();
    let witness = probe_witness(&config);
    let queue = QueueNum::new(750);
    let ips = vec![TARGET_IP.to_string()];

    let log_path = std::env::temp_dir().join(format!(
        "blockcheckw-mask-test-{}-{}.log",
        std::process::id(),
        queue.get()
    ));
    let _ = std::fs::remove_file(&log_path);

    // Профиль 1 несёт синтетический `--debug=@...` — глобальный параметр,
    // положение в argv не важно (см. doc-комментарий выше).
    let strategies = vec![
        vec![
            "--lua-desync=fake:ttl=1".to_string(),
            format!("--debug=@{}", log_path.display()),
        ],
        vec!["--lua-desync=fake:ttl=2".to_string()],
    ];
    let env = config.nfqws2_env();
    let plan = Plan::from_strategies(&witness, queue, &strategies);
    let mark1 = plan.profiles()[0].mark;
    let mark2 = plan.profiles()[1].mark;

    let table = nftables::prepare_table(&SystemNft, TABLE)
        .await
        .expect("prepare_table");

    // M3: от старта процесса и дальше — любой отказ обязан пройти через
    // уборку ПЕРЕД паникой, а не после. `start`/`wait_ready` сами по себе не
    // ставят nft-правил (это делает только `apply_dispatch` ниже), но живой
    // процесс на очереди `queue` — тоже ресурс, который нельзя бросать: без
    // явной уборки он пережил бы панику (`Instance`/`BackgroundProcess`
    // используют `kill_on_drop`, так что технически не осиротеет, но это
    // свойство соседней структуры, а не гарантия ЭТОГО теста — полагаться на
    // него молча значило бы повторить тот же класс отказа, что уже чинили в
    // тестах 2-4, просто на одну строку раньше).
    let mut instance = match SystemNfqws2::start(&env, &plan).await {
        Ok(i) => i,
        Err(e) => {
            let _ = table.drop_table(&SystemNft).await;
            panic!("start nfqws2: {e}");
        }
    };

    let ready = match SystemNfqws2::wait_ready(&mut instance).await {
        Ok(r) => r,
        Err(e) => {
            SystemNfqws2::stop(instance).await;
            let _ = table.drop_table(&SystemNft).await;
            panic!("nfqws2 must bind the queue: {e}");
        }
    };

    if let Err(e) =
        nftables::apply_dispatch(&SystemNft, &table, &ready, &plan.dispatch(443), &ips).await
    {
        SystemNfqws2::stop(instance).await;
        let _ = table.drop_table(&SystemNft).await;
        panic!("apply_dispatch: {e}");
    }

    // Собрать факты ДО уборки — ни одного expect/unwrap/?/assert между
    // постановкой правил и её концом (тот же приём, что в тестах 2-4): любая
    // паника здесь оставила бы на стенде правило `queue to {queue}` без
    // слушателя.
    let addr: SocketAddr = format!("{TARGET_IP}:443").parse().unwrap();

    // Проба 1: марка профиля 1. `seq_before`/`seq_after` — свидетельство
    // обоих направлений (M1), не только «проба не упала».
    let seq_before1 = queue_sequence(queue);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http_client::marked_tcp_connect(addr, mark1.so_mark()),
    )
    .await;
    let seq_after1 = queue_sequence(queue);
    let log_after_probe1 = std::fs::read_to_string(&log_path).unwrap_or_default();

    // Проба 2: марка профиля 2. Лог НЕ обнуляется между пробами (Fix round
    // 3: раньше здесь стояло `std::fs::write(&log_path, "")`, задуманное как
    // изоляция пробы 2, — на стенде выяснилось, что оно не срабатывает.
    // `nfqws2` к этому моменту уже сбросил привилегии до
    // `--uid=65534:65534`, а `ensure_file_access` (`nfq2/darkmagic.c`) до
    // сброса делает `chown` лога на этот uid — и `std::fs::write` от имени
    // ЭТОГО теста (тоже root, но в контейнере-стенде без `CAP_DAC_OVERRIDE`
    // в эффективном наборе: `chown`/`chmod` чужого файла проходят, прямая
    // запись/усечение — нет, `EACCES`) молча проглатывался через `let _ =
    // ...`. Подтверждено прямым экспериментом на стенде: `chmod 666`/`chown`
    // от root — успех, `truncate -s 0` того же файла — `Permission denied`,
    // тот же файл после `chown` обратно на root — усекается мгновенно.
    //
    // Раз обнулить нельзя — читаем ВЕСЬ (накопительный) лог оба раза и не
    // пытаемся резать его по позиции чтения вообще: первая попытка так и
    // сделать (граница — конец лога сразу после пробы 1) тоже оказалась
    // ложной по другой причине — TCP-соединение пробы 1 может ещё дописывать
    // свой хвост (поздние ACK/FIN) уже ПОСЛЕ старта пробы 2, и эти пакеты,
    // законно помеченные меткой профиля 1, ошибочно попадали бы в «окно
    // пробы 2». Единственный надёжный ключ — метка САМОГО пакета
    // (`profiles_for_mark` выше), а не позиция строки в файле или время её
    // появления.
    let seq_before2 = queue_sequence(queue);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http_client::marked_tcp_connect(addr, mark2.so_mark()),
    )
    .await;
    let seq_after2 = queue_sequence(queue);
    let log_after_probe2 = std::fs::read_to_string(&log_path).unwrap_or_default();

    let still_bound = queue_still_bound(queue);

    nftables::remove_dispatch(&SystemNft, &table).await;
    SystemNfqws2::stop(instance).await;
    let _ = table.drop_table(&SystemNft).await;
    let _ = std::fs::remove_file(&log_path);

    // Только теперь — ассерты. Стенд уже прибран независимо от их исхода.
    assert!(
        still_bound,
        "queue should still be bound after both probes — nfqws2 must not have crashed"
    );
    assert!(
        !log_after_probe1.is_empty(),
        "debug log is empty after probe 1 — either --debug=@file did not take effect, \
         or the marked SYN never reached nfqws2 (path={})",
        log_path.display()
    );

    // M1: доказать, что через очередь прошли ОБА направления — исходящий
    // SYN и входящий SYN/ACK, — а не только исходящий. `>= 2`, а не `!= 0`
    // (как в `nfqws2_receives_marked_traffic`, тест 3, которому достаточно
    // «хоть что-то прошло»): здесь ставка выше — заявление №1 ниже
    // («ignoring generated packet» не встречается) стоит чего-то только если
    // входящий SYN/ACK реально был поставлен в очередь и нам было что
    // потерять молча.
    let delta1 = seq_delta(seq_before1, seq_after1);
    let delta2 = seq_delta(seq_before2, seq_after2);
    assert!(
        delta1.unwrap_or(0) >= 2,
        "проба 1: через очередь прошло меньше двух пакетов (before={seq_before1:?} \
         after={seq_after1:?}) — SYN/ACK от сервера мог не вернуться, входящее \
         направление не проверено, и утверждение про «ignoring generated packet» ниже вакуумно"
    );
    assert!(
        delta2.unwrap_or(0) >= 2,
        "проба 2: через очередь прошло меньше двух пакетов (before={seq_before2:?} \
         after={seq_after2:?}) — SYN/ACK от сервера мог не вернуться, входящее \
         направление не проверено"
    );

    // `log_after_probe2` — накопительный (Fix round 3, см. выше), уже
    // включает всё, что видел `log_after_probe1`, так что считать отдельно
    // и складывать значило бы задвоить совпадения из пробы 1.
    let combined_ignored = log_after_probe2
        .matches("ignoring generated packet")
        .count();
    assert_eq!(
        combined_ignored, 0,
        "маска восстановления снята не полностью — входящие выбрасываются молча \
         как «свой сгенерированный пакет» (nfq2/nfqws.c:159):\n{log_after_probe2}"
    );

    // Fix round 3: избирательность — по МЕТКЕ пакета (`profiles_for_mark`),
    // а не по тому, до или после какой границы чтения строка оказалась в
    // файле. `mark1_hex`/`mark2_hex` — те же восемь hex-цифр без `0x`, что
    // движок печатает сам на каждой строке `packet: id=N ... mark=XXXXXXXX`.
    let mark1_hex = format!("{:08x}", mark1.so_mark());
    let mark2_hex = format!("{:08x}", mark2.so_mark());
    let profiles_for_mark1 = profiles_for_mark(&log_after_probe2, &mark1_hex);
    let profiles_for_mark2 = profiles_for_mark(&log_after_probe2, &mark2_hex);

    // Диагностика на `--nocapture`, до ассертов — та же причина, что у
    // `eprintln!` с conntrack в тесте 4: если что-то ниже упадёт, эти три
    // числа — первое, что нужно увидеть, а печатать их ПОСЛЕ упавшего assert
    // было бы поздно.
    eprintln!(
        "mask acceptance: ignoring_generated_packet={combined_ignored} \
         mark1(0x{mark1_hex})→{profiles_for_mark1:?} mark2(0x{mark2_hex})→{profiles_for_mark2:?}"
    );

    assert!(
        profiles_for_mark1.contains(&1),
        "профиль 1 не выбирался ни разу пробой с его же маркой (выборы для mark={mark1_hex}: \
         {profiles_for_mark1:?}):\n{log_after_probe2}"
    );
    assert!(
        !profiles_for_mark2.contains(&1),
        "отбор не избирателен: пакет с маркой профиля 2 (mark={mark2_hex}) привёл к выбору \
         профиля 1 (выборы: {profiles_for_mark2:?}):\n{log_after_probe2}"
    );
    // M2: положительная планка для пробы 2 — без неё предыдущий assert
    // проходит и на пустом списке (проба 2 вообще не дошла до движка), а
    // это ничего не доказывает об избирательности отбора.
    assert!(
        profiles_for_mark2.contains(&2),
        "профиль 2 не выбирался ни разу пробой с его же маркой (выборы для mark={mark2_hex}: \
         {profiles_for_mark2:?}):\n{log_after_probe2}"
    );
}

// ── Test 5: HTTP request format matches curl ─────────────────────────────────

#[tokio::test]
async fn http_request_uses_relative_uri() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let _result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        http_client::http_test(
            Protocol::Http,
            "testhost.example",
            &local_addr.ip().to_string(),
            0,
            2,
            None,
        ),
    )
    .await;

    if let Ok(request_line) = tokio::time::timeout(std::time::Duration::from_secs(2), server).await
    {
        let request_line = request_line.unwrap();
        eprintln!("Captured request:\n{request_line}");

        assert!(
            request_line.starts_with("GET / HTTP/1.1\r\n"),
            "HTTP request should use relative URI 'GET / HTTP/1.1', got: {}",
            request_line.lines().next().unwrap_or("(empty)")
        );
        assert!(
            request_line.contains("host: testhost.example"),
            "Request should contain Host header"
        );
        assert!(
            request_line.contains("user-agent: Mozilla"),
            "Request should contain User-Agent"
        );
    }
}

// ── Test 6: TLS version config ───────────────────────────────────────────────

#[tokio::test]
async fn tls12_config_only_allows_tls12() {
    let config = http_client::make_tls_config(Protocol::HttpsTls12);
    assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
}

#[tokio::test]
async fn tls13_config_only_allows_tls13() {
    let config = http_client::make_tls_config(Protocol::HttpsTls13);
    assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
}

// ── Test 6b: capturing probe keeps partial size on a stalled transfer ────────

/// #60: a DPI that passes headers then caps/stalls the body must yield the
/// partial byte count, not a bare timeout — so baseline can label it a data cap.
/// Server sends 200 + 5000 bytes (promising more via Content-Length) then hangs;
/// the capturing probe should return ~5000 downloaded with no error.
#[tokio::test]
async fn capturing_probe_keeps_partial_on_stall() {
    if !is_root() {
        eprintln!("SKIPPED: binds 127.0.0.1:80, requires root");
        return;
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:80").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("SKIPPED: cannot bind :80 ({e})");
            return;
        }
    };

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        // Promise 100000 bytes, send only 5000, then hang (never close).
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            .await
            .unwrap();
        stream.write_all(&vec![b'x'; 5000]).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    // connect budget 2s, stall 1s between chunks, limit 32KB.
    let result = http_client::http_test_data_capturing(
        Protocol::Http,
        "testhost.example",
        "127.0.0.1",
        0,
        2,
        1,
        32_768,
    )
    .await;

    assert!(
        result.error.is_none(),
        "expected no error, got {:?}",
        result.error
    );
    assert_eq!(result.status_code, Some(200));
    assert_eq!(
        result.size_download,
        Some(5000),
        "should keep the partial 5000 bytes read before the stall"
    );

    server.abort();
}

// ── Test 7: чужая nft-таблица переживает наш цикл ────────────────────────────

/// Существует ли таблица `inet <name>`.
async fn nft_table_exists(name: &str) -> bool {
    run_process(&["nft", "list", "table", "inet", name], 5000)
        .await
        .map(|r| r.exit_code == 0)
        .unwrap_or(false)
}

/// issue #66: имя нашей таблицы совпадало с таблицей zapret1, и наш cleanup
/// сносил чужую рабочую конфигурацию.
#[tokio::test]
async fn foreign_zapret1_table_survives_our_cleanup() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    const FOREIGN: &str = "zapret";

    // Имитация работающего zapret1: очередь на 80/443 в таблице "zapret"
    run_process(&["nft", "delete", "table", "inet", FOREIGN], 5000)
        .await
        .ok();
    for args in [
        vec!["nft", "add", "table", "inet", FOREIGN],
        vec![
            "nft",
            "add",
            "chain",
            "inet",
            FOREIGN,
            "postrouting",
            "{ type filter hook postrouting priority 101; }",
        ],
        vec![
            "nft",
            "add",
            "rule",
            "inet",
            FOREIGN,
            "postrouting",
            "meta l4proto tcp tcp dport { 80, 443 } queue num 200 bypass",
        ],
    ] {
        let r = run_process(&args, 5000).await.expect("nft setup");
        assert_eq!(r.exit_code, 0, "setup failed: {args:?}\n{}", r.stderr);
    }
    assert!(
        nft_table_exists(FOREIGN).await,
        "фикстура zapret1 не создалась"
    );

    // Полный цикл blockcheckw: `prepare_table` сама подбирает остатки
    // прошлого прогона одной транзакцией (см. её doc-комментарий в
    // `src/firewall/nftables.rs`) — отдельный снос перед созданием больше не
    // нужен, в этом и разница со старой трёхшаговой схемой. `drop_table` по
    // метке — ровно то, что зовут аварийные обработчики (`cmd/mod.rs`,
    // `cmd/scan.rs`), а не отдельная тестовая имитация.
    let table = nftables::prepare_table(&SystemNft, DEFAULT_NFT_TABLE)
        .await
        .expect("prepare_table");
    nftables::drop_table(&SystemNft, &table.marker()).await;

    let foreign_alive = nft_table_exists(FOREIGN).await;
    let own_gone = !nft_table_exists(DEFAULT_NFT_TABLE).await;

    // Убираем фикстуру до ассертов, чтобы падение теста не оставило мусор
    run_process(&["nft", "delete", "table", "inet", FOREIGN], 5000)
        .await
        .ok();

    assert!(
        foreign_alive,
        "таблица zapret1 '{FOREIGN}' снесена нашим cleanup (наша таблица: '{DEFAULT_NFT_TABLE}')"
    );
    assert!(own_gone, "наша таблица '{DEFAULT_NFT_TABLE}' не убрана");
}

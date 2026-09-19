//! Data Transfer Objects — all JSON-serializable report structures in one place.
//!
//! These structs define the public contract for scan/check/universal JSON reports
//! and inter-command data exchange (e.g. `scan | check` pipe).

use serde::{Deserialize, Serialize};

use crate::pipeline::fate::Admits;

// ── Контракт отчёта ──────────────────────────────────────────────────────────

/// Версия формата отчёта. Инкрементируется при ЛОМАЮЩЕМ изменении: переименовании поля,
/// смене его смысла, смене синтаксиса `args` (его разбирает потребитель).
///
/// Зачем: отчёт читает чужая программа, у которой нет компилятора, общего с нами. Пока
/// версии не было, единственным способом узнать о сломанном контракте была поломка у
/// читателя — то есть у человека.
pub const SCHEMA: u32 = 1;

/// Код выхода «боевая очередь занята». Отдельный от общего отказа преflight'а (6): для
/// оркестратора это не «инструмент сломан», а «место занято» — лечится другой очередью
/// (`--qnum`), а не починкой установки.
pub const EXIT_QUEUE_BUSY: i32 = 7;

/// ЧТО СЛУЧИЛОСЬ С ПРОГОНОМ. Четыре различимых исхода вместо булева `inconclusive`.
///
/// Продукт читает исход и решает, снимать ли лечение с цели. «Цель чиста» и «прибор не
/// смог» — это разница между «человеку хорошо» и «человек остался без лечения из-за нашей
/// поломки», и одним булевым полем она не выражается. 19.09.2026 не выразилась: отчёт
/// сказал `inconclusive: true` при режущемся домене, и карантин был снят.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// Контроль без десинка прошёл: домен на этой линии не режется. О стратегиях прогон
    /// не говорит ничего — и хвалить десинк за доступность, которая была и без него, нельзя.
    NotBlocked,
    /// НАЙДЕНО. Есть рабочие стратегии — читать их в `strategies`.
    ///
    /// `stopped_at` назван, если поиск остановил предел (`--take`): это не цензура замера, а
    /// его законный конец — мы нашли столько, сколько просили, и перестали искать. Но
    /// читателю важно знать, что за остановкой могло быть ещё.
    Found {
        working: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        stopped_at: Option<Limit>,
    },
    /// Корпус перебран ЦЕЛИКОМ, рабочих нет. Честный отрицательный ответ, а не молчание:
    /// названо, сколько кандидатов проверено.
    NothingWorks { candidates: usize },
    /// Замер ОБРЕЗАН, и рабочих НЕ НАЙДЕНО — то есть мы не знаем, были ли они дальше.
    ///
    /// Отличается от `NothingWorks` ровно этим незнанием: там перебрали всё, здесь нет.
    /// Говорит о приборе, а не о мире, и потому обязан назвать ИМЕННО тот предел, который
    /// сработал: `--connect-timeout 4` уже давал «контроль 4036 мс» там, где бюджет в 20 с
    /// давал 20014 мс.
    Censored { limit: Limit },
    /// Беда ИНСТРУМЕНТА. Ничего не говорит о цели — и не смеет быть прочитана как «чисто».
    Broken { reason: BrokenReason },
}

/// Какой предел обрезал замер.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Limit {
    /// Общий срок прогона (`--timeout` у `scan`, `--deadline` у `check`).
    Deadline,
    /// Поиск остановлен после N прошедших (`--take`).
    Take,
    /// Потолок одной пробы (`--timeout` у `check`).
    ProbeTimeout,
}

/// Чем именно сломался инструмент. Каждое значение — своя починка у того, кто нас позвал.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokenReason {
    /// nftables не принял наши правила.
    Nft,
    /// Нет `CAP_NET_ADMIN` — ни марок, ни очереди.
    NoCapNetAdmin,
    /// Боевая очередь занята чужим слушателем. Лечится другой очередью, не переустановкой.
    QueueBusy { queue: u16 },
    /// Имя не разрешилось.
    DnsFailed,
    /// Движок не поднялся или не забиндил очередь.
    EngineStart,
    /// Входной файл со стратегиями не прочитан.
    InputUnreadable,
}

impl Outcome {
    /// Говорит ли исход, что ЦЕЛЬ не нуждается в лечении.
    ///
    /// Истинно РОВНО для `NotBlocked`. Всё прочее — либо отсутствие рабочей стратегии, либо
    /// обрезанный замер, либо наша поломка; ни одно из трёх не есть суждение о чистоте цели.
    pub fn target_is_clean(&self) -> bool {
        matches!(self, Outcome::NotBlocked)
    }

    /// Имя сработавшего предела — только у обрезанного замера.
    pub fn limit_name(&self) -> Option<&'static str> {
        match self {
            Outcome::Censored { limit } => Some(match limit {
                Limit::Deadline => "deadline",
                Limit::Take => "take",
                Limit::ProbeTimeout => "probe_timeout",
            }),
            _ => None,
        }
    }

    /// Код выхода процесса. Ноль — прогон состоялся и отчёт осмыслен, даже если рабочих
    /// стратегий не нашлось: отсутствие лекарства не есть поломка аптеки.
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::NotBlocked
            | Outcome::Found { .. }
            | Outcome::NothingWorks { .. }
            | Outcome::Censored { .. } => 0,
            Outcome::Broken { reason } => match reason {
                BrokenReason::Nft | BrokenReason::NoCapNetAdmin => 3,
                BrokenReason::DnsFailed => 4,
                BrokenReason::EngineStart => 5,
                BrokenReason::InputUnreadable => 6,
                BrokenReason::QueueBusy { .. } => EXIT_QUEUE_BUSY,
            },
        }
    }
}

/// СОСТОЯНИЕ ПРОВЕРКИ ПОДМЕНЫ DNS. Трёхзначно, и это не придирка.
///
/// Замер заказчика на живой коробке 20.09.2026: `curl` там нет вовсе, а `doh_resolve`
/// зовёт именно его. Значит DoH-сервер не находится НИКОГДА, сверка системного резолва с
/// ним не происходит НИКОГДА — и прежнее булево поле сообщало `false`, то есть «подмены
/// нет», там, где верно было «не проверяли». Прибор с нулевым множителем, выглядящий
/// исправным; та же болезнь, что у `inconclusive`, и лечится так же.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSpoofed {
    /// Сверено с DoH: системный резолвер отдаёт то же самое.
    Clean,
    /// Сверено с DoH: системный резолвер отравлен.
    Spoofed,
    /// НЕ СВЕРЕНО. Не «чисто».
    Unchecked,
}

/// ФАКТИЧЕСКИЕ параметры прогона — те, с которыми он шёл, а не те, что были заданы.
///
/// Зачем в отчёте: замер без своих условий — половина замера. Продукт, поднимающий подбор,
/// задаёт ключи явно и мог бы записать их сам, но тогда он записал бы ЗАДУМАННОЕ, а отчёт
/// должен нести СЛУЧИВШЕЕСЯ: умолчание, подхваченное из памяти прошлых запусков, откат на
/// DoH при отравленном резолвере, урезанный потолок. Разница между этими двумя ровно там,
/// где живут наши беды.
#[derive(Debug, Clone, Serialize)]
pub struct RunProvenance {
    /// Версия подборщика, породившего отчёт.
    pub bcw_version: String,
    /// Сколько проб в полёте.
    pub workers: usize,
    /// Сколько стратегий держалось в одном процессе движка.
    pub profiles_per_instance: usize,
    /// Режим разрешения имени, как он РАБОТАЛ (не как был задан).
    pub dns: String,
    /// Номер боевой очереди NFQUEUE.
    pub qnum: u16,
    /// Имя нашей nft-таблицы.
    pub nft_table: String,
    /// База марки воркера.
    pub mark_base: String,
    /// Марка десинка.
    pub desync_mark: String,
    /// Группа процессов — по ней оркестратор снимает подбор целиком.
    pub process_group: i32,
    /// Потолок одной пробы, секунды.
    pub timeout_secs: u64,
    /// Встроенный ли режим.
    pub embedded: bool,
    /// Сколько кандидатов перебрано.
    pub tried: usize,
    /// Сколько кандидатов было всего.
    pub total: usize,
    /// `--take`, если задан.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub take: Option<usize>,
    /// `--top`, если задан (влияет ТОЛЬКО на печать, не на состав отчёта).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top: Option<usize>,
    /// `--passes` (`M`), если применимо.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passes: Option<usize>,
    /// Порог тишины пробы, миллисекунды, если применимо.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_ms: Option<u64>,
}

impl RunProvenance {
    /// Провенанс из живой конфигурации. Марки печатаются шестнадцатерично: именно в таком
    /// виде их читает и сверяет сосед по ядру.
    pub fn of(config: &crate::config::CoreConfig, dns: &str, embedded: bool) -> Self {
        RunProvenance {
            bcw_version: env!("CARGO_PKG_VERSION").to_string(),
            workers: config.worker_count,
            profiles_per_instance: config.profiles_per_instance,
            dns: dns.to_string(),
            qnum: config.base_qnum,
            nft_table: config.nft_table.clone(),
            mark_base: format!("0x{:08X}", crate::nfqws2::mark::WORKER_MARK_BASE),
            desync_mark: format!("0x{:08X}", crate::nfqws2::mark::DESYNC_MARK),
            process_group: crate::system::group::own_group(),
            timeout_secs: config.request_timeout,
            embedded,
            tried: 0,
            total: 0,
            take: None,
            top: None,
            passes: None,
            idle_ms: None,
        }
    }
}

// ── Shared (used across commands) ────────────────────────────────────────────

/// Single strategy entry for interchange between commands (scan → check pipe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyEntry {
    pub protocol: String,
    pub args: String,
    /// Domain coverage: 1 for scan/vanilla, N for universal.
    pub coverage: usize,
}

// ── Scan report ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScanProtocolResult {
    pub protocol: String,
    pub total: usize,
    pub strategies: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    /// Версия формата. Первое поле намеренно: читатель, не знающий версии, не знает ничего.
    pub schema: u32,
    /// ЧТО СЛУЧИЛОСЬ С ПРОГОНОМ. Читать НАДО это, прежде чем читать `strategies`: пустой
    /// список при `broken` и при `nothing_works` — разные вещи.
    #[serde(flatten)]
    pub outcome: Outcome,
    /// Фактические условия прогона.
    pub run: RunProvenance,
    pub domain: String,
    pub timestamp: String,
    /// Network-layer verdict (IP-blackhole vs SNI-block vs available/dns-failed).
    /// Lets a consumer route on the block kind without re-probing: `IpBlocked`
    /// means desync can't help (no handshake), `SniBlocked` means it can.
    pub block_type: BlockType,
    /// Состояние проверки подмены DNS. Ортогонально `block_type`, который меряется по
    /// чистым (DoH) адресам: домен может быть `spoofed` и при этом `not_blocked`.
    ///
    /// ТРИ значения, а не два: `unchecked` — сверка не состоялась (DoH-сервер не найден), и
    /// читать это как «подмены нет» нельзя. На коробке без `curl` прежнее булево поле
    /// сообщало `false` ВСЕГДА, ни разу ничего не сверив.
    pub dns_spoofed: DnsSpoofed,
    pub total: usize,
    pub working: usize,
    /// Protocols that failed the no-bypass baseline (i.e. are DPI-blocked).
    /// Empty ⟺ domain is not blocked. Distinguishes "not blocked" from
    /// "blocked but no working strategy" — both yield empty `strategies`.
    pub blocked: Vec<String>,
    pub protocols: Vec<ScanProtocolResult>,
    /// Flat list of all working strategies for interchange with check.
    pub strategies: Vec<StrategyEntry>,
}

// ── Check report ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CheckedStrategy {
    pub protocol: String,
    pub args: String,
    /// Спека §6-тер: подлинность (побочная ось, `--identity-path`) не опровергнута
    /// И полная доставка (`--probe-path`) состоялась КАЖДЫЙ раз из `passes_total`.
    pub working: bool,
    /// Медиана байт, вытянутых байтовой осью (по `passes_total` повторам).
    pub bytes_downloaded: u64,
    pub latency_ms: u64,
    pub speed_kbps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Имя провала для замера (спайк #verify-histogram). Вне JSON: контракт
    /// отчёта менять ради инструментовки незачем.
    #[serde(skip)]
    pub failure: Option<String>,
    /// Что установило наблюдение НА ОСИ ПОДЛИННОСТИ (`--identity-path`). Потребителю
    /// JSON читать НАДО ЭТО, а не `working`.
    pub observed: String,
    /// Круг допускаемых судеб оси подлинности. Одна судьба — сузили; несколько — не
    /// сузили; это не одно и то же, и `working: false` в обоих случаях означает разное.
    pub admits: Vec<String>,
    /// Тот же круг значением — для ранга. Вне JSON: контракт отчёта менять ради
    /// внутреннего порядка незачем, а строки для сортировки не годятся.
    #[serde(skip)]
    pub circle: Admits,
    /// Сколько из `passes_total` проб байтовой оси уложились в разброс эталона объёма
    /// (`reference::agrees`) — «полная доставка».
    pub passes_ok: usize,
    /// `M` — сколько раз мерили байтовую ось (`--passes`).
    pub passes_total: usize,
    /// Медиана доли `вытянуто/эталон` по `passes_total` повторам. `None` — эталона
    /// объёма нет (без `--reference-via`), и доли не существует.
    pub median_share: Option<f64>,
    /// Самая длинная тишина цели между шагами у проходов с полной доставкой, мс.
    /// `None` — полной доставки не было, и мерить здоровую тишину не на чем.
    pub longest_silence_ms: Option<u64>,
}

/// Строка отчёта `check`. Две оси стоят рядом: `working` — прошёл ли канал (главная),
/// `observed`/`admits` — подлинность ресурса (побочная). Читать надо обе: `working: false`
/// при `observed: "Unobserved"` говорит о нас, а не о домене.
/// Строка отчёта `check`. Две ПРОБЫ, две оси (спека §6-тер):
///
/// - байтовая (главная) — `--probe-path`, `M` повторов (`passes_total`): `passes_ok` —
///   сколько из них были полной доставкой (`reference::agrees` с эталоном объёма),
///   `median_share` — медиана доли `вытянуто/эталон`;
/// - подлинности (побочная) — `--identity-path`, один раз: `observed`/`admits`, и
///   только она может дать круг `[Mirage]`.
///
/// Читать надо обе: `working: false` при широком `admits` говорит о байтовой оси, а не
/// о домене.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedStrategy {
    pub protocol: String,
    pub args: String,
    pub coverage: usize,
    /// `passes_ok / passes_total` — частота полной доставки байтовой осью. `0.0` и при
    /// `passes_total == 0` («не мерили»), а не `NaN`.
    pub success_rate: f64,
    pub median_latency_ms: u64,
    /// СЫРАЯ СПРАВКА, вердикта не несёт. Считается как `bytes / latency_ms`, а
    /// знаменатель включает `connect` и TLS-рукопожатие: на коротком ответе поле мерит
    /// рукопожатие, а не канал. Спека §9 объявила метод негодным; поле сохранено ради
    /// совместимости JSON. Темп судят `Waited` и `Sag` — через `admits`.
    pub median_speed_kbps: f64,
    /// Сколько из `passes_total` проб байтовой оси (`--probe-path`) были ПОЛНОЙ
    /// доставкой: уложились в разброс эталона объёма (`reference::agrees`).
    pub passes_ok: usize,
    /// `M` — сколько раз мерили байтовую ось (`--passes`, спека §6-тер). Проходы больше
    /// не сокращаются первым провалом: частота требует всех `M` измерений.
    pub passes_total: usize,
    /// Медиана доли `вытянуто/эталон` по `passes_total` повторам байтовой оси. `None` —
    /// эталона объёма нет (без `--reference-via`): доли не существует, а не «ноль».
    pub median_share: Option<f64>,
    /// Самая длинная тишина цели между шагами (коннект, рукопожатие, заголовки, кадр
    /// тела) у проходов с полной доставкой, мс. Мерило порога `--idle-ms`: здоровая
    /// стратегия показывает, сколько молчания живой разговор себе позволяет. `None` —
    /// полной доставки не было.
    pub longest_silence_ms: Option<u64>,
    /// Что установило наблюдение НА ОСИ ПОДЛИННОСТИ (`--identity-path`): `Bytes`,
    /// `Mute`, `NoConnect`, `Unobserved`, `Inconsistent`. Потребителю JSON читать НАДО
    /// ЭТО, а не `working`.
    pub observed: String,
    /// Круг допускаемых судеб оси подлинности. Одна судьба — сузили; несколько — не
    /// сузили; это не одно и то же, и `working: false` в обоих случаях означает разное.
    pub admits: Vec<String>,
    /// ГЛАВНАЯ ось замера (спека §6-тер):
    /// `working = подлинность не опровергнута (круг != [Mirage])
    ///          И полная доставка состоялась КАЖДЫЙ раз из passes_total`.
    /// `false` — либо ось подлинности разошлась с эталоном (`admits: ["Mirage"]`), либо
    /// хоть один из `passes_total` заходов байтовой оси не уложился в эталон объёма.
    /// Неустановленная подлинность (широкий `admits` без эталона) вердикта не топит.
    /// По этому полю работает пайп `universal → check`.
    pub working: bool,
}

/// Что вышло у пробы БЕЗ десинка. Без неё «работает» ниже может быть свойством линии.
#[derive(Debug, Clone, Serialize)]
pub struct ControlVerdict {
    pub observed: String,
    pub admits: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    /// Версия формата отчёта.
    pub schema: u32,
    /// ЧТО СЛУЧИЛОСЬ С ПРОГОНОМ — читать прежде `strategies` и прежде `working`.
    #[serde(flatten)]
    pub outcome: Outcome,
    /// Фактические условия прогона.
    pub run: RunProvenance,
    pub domain: String,
    pub timestamp: String,
    pub total: usize,
    /// Сколько строк в `strategies` ПРОШЛО (`fate::passed`). НЕ длина списка: в него
    /// идёт всякая наблюдённая стратегия, прошедшая или нет.
    pub working: usize,
    pub elapsed_secs: f64,
    /// Всякая НАБЛЮДЁННАЯ стратегия — та, чей круг судеб уже полного, — а не только
    /// приведшая цель к `Good` (спека §6.2: человек видит лучшее из имеющегося вместо
    /// пустого списка). Порядок — по судьбе (`rank::fate_order`). Судьба каждой строки
    /// стоит рядом с ней: `observed` и `admits`.
    pub strategies: Vec<VerifiedStrategy>,
    /// Контроль без десинка. `None` — не прогоняли.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlVerdict>,
    /// Контроль без десинка сам ПРОШЁЛ — судимый той же мерой, что и стратегии
    /// (`fate::passed`): о стратегиях прогон не говорит ничего.
    ///
    /// УСТАРЕЛО, снимается в `schema: 2`. Ровно то же говорит `outcome: not_blocked`, и
    /// говорит точнее: `inconclusive: false` не различает «перебрали и не нашли», «замер
    /// обрезан» и «прибор сломан», а продукт по нему решает, снимать ли лечение. Поле
    /// оставлено на одну версию, потому что у читателя есть работающий код, и ломать обе
    /// половины контракта разом нельзя.
    pub inconclusive: bool,
}

// ── Universal report ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct UniversalStrategy {
    pub args: String,
    pub coverage: usize,
}

#[derive(Debug, Serialize)]
pub struct UniversalProtocolResult {
    pub protocol: String,
    pub domains_tested: Vec<String>,
    pub domains_excluded: Vec<String>,
    pub strategies: Vec<UniversalStrategy>,
}

#[derive(Debug, Serialize)]
pub struct UniversalReport {
    pub timestamp: String,
    pub domains_sampled: usize,
    pub protocols: Vec<UniversalProtocolResult>,
    /// Flat list of all strategies for interchange with check.
    pub strategies: Vec<StrategyEntry>,
}

// ── Status report ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockType {
    /// Domain is accessible
    NotBlocked,
    /// Handshake and HEAD succeed, but bulk data is throttled — capped after a
    /// few KB (DPI data limit) or otherwise choked. The page loads; video and
    /// downloads stall. Desync may help if SNI-triggered; per-IP throttle needs
    /// a different egress.
    Throttled,
    /// Direct TCP connect fails, with no proxy probe to refine the cause →
    /// IP-level block of unknown kind. Desync can't help (no handshake).
    IpBlocked,
    /// Direct SYN dropped, yet the IP is reachable via a proxy → the SYN is
    /// filtered on this path while the host is alive. Changing egress bypasses it.
    SynBlocked,
    /// Unreachable both directly and via a proxy → the host is down everywhere.
    HostDead,
    /// TCP connects but TLS/data fails → DPI/SNI block, zapret can bypass
    SniBlocked,
    /// DNS resolution failed
    DnsFailed,
}

impl BlockType {
    /// Classify a domain from stepped probe outcomes (DNS → direct TCP → response,
    /// plus an optional proxy reachability probe). When the direct SYN fails, a
    /// proxy comparison splits IP-level failure into [`SynBlocked`](Self::SynBlocked)
    /// (alive elsewhere, path-filtered) and [`HostDead`](Self::HostDead) (down everywhere);
    /// without a proxy it stays the unrefined [`IpBlocked`](Self::IpBlocked).
    /// `proxy_reachable`: `None` = no proxy probe, `Some(true/false)` = proxy result.
    pub fn classify(
        dns_ok: bool,
        direct_reachable: bool,
        got_response: bool,
        proxy_reachable: Option<bool>,
    ) -> BlockType {
        match (dns_ok, direct_reachable, got_response, proxy_reachable) {
            (false, _, _, _) => BlockType::DnsFailed,
            (true, true, true, _) => BlockType::NotBlocked,
            (true, true, false, _) => BlockType::SniBlocked,
            (true, false, _, None) => BlockType::IpBlocked,
            (true, false, _, Some(true)) => BlockType::SynBlocked,
            (true, false, _, Some(false)) => BlockType::HostDead,
        }
    }
}

impl std::fmt::Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockType::NotBlocked => write!(f, "not blocked"),
            BlockType::Throttled => write!(f, "throttled"),
            BlockType::IpBlocked => write!(f, "IP blocked"),
            BlockType::SynBlocked => write!(f, "SYN blocked"),
            BlockType::HostDead => write!(f, "host dead"),
            BlockType::SniBlocked => write!(f, "SNI blocked"),
            BlockType::DnsFailed => write!(f, "DNS failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainStatus {
    pub domain: String,
    pub block_type: BlockType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed_kbps: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub timestamp: String,
    pub total: usize,
    pub available: usize,
    pub sni_blocked: usize,
    pub ip_blocked: usize,
    pub dns_failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_speed_kbps: Option<f64>,
    pub domains: Vec<DomainStatus>,
}

// ── Strategy test results (test_runner) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PassResult {
    pub pass_index: usize,
    pub success: bool,
    pub verdict: String,
    pub latency_ms: u64,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct StrategyTestResult {
    pub strategy_args: Vec<String>,
    pub pass_results: Vec<PassResult>,
    pub stats: StrategyStats,
}

#[derive(Debug, Serialize)]
pub struct StrategyStats {
    pub total_passes: usize,
    pub successes: usize,
    pub failures: usize,
    pub errors: usize,
    pub success_rate: f64,
    pub latency_median_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_p99_ms: u64,
    pub latency_min_ms: u64,
    pub latency_max_ms: u64,
    pub error_distribution: Vec<(String, usize)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_dns_failure_is_dns_failed() {
        assert_eq!(
            BlockType::classify(false, false, false, None),
            BlockType::DnsFailed
        );
    }

    #[test]
    fn classify_tcp_unreachable_without_proxy_is_ip_blocked() {
        assert_eq!(
            BlockType::classify(true, false, false, None),
            BlockType::IpBlocked
        );
    }

    #[test]
    fn classify_handshake_but_no_response_is_sni_blocked() {
        assert_eq!(
            BlockType::classify(true, true, false, None),
            BlockType::SniBlocked
        );
    }

    #[test]
    fn classify_response_received_is_not_blocked() {
        assert_eq!(
            BlockType::classify(true, true, true, None),
            BlockType::NotBlocked
        );
    }

    #[test]
    fn classify_syn_dropped_but_alive_via_proxy_is_syn_blocked() {
        // Direct SYN never answered, yet the IP serves through a proxy: the SYN is
        // dropped on this path while the host is alive. Fixable by changing egress.
        assert_eq!(
            BlockType::classify(true, false, false, Some(true)),
            BlockType::SynBlocked
        );
    }

    #[test]
    fn classify_unreachable_everywhere_is_host_dead() {
        assert_eq!(
            BlockType::classify(true, false, false, Some(false)),
            BlockType::HostDead
        );
    }

    #[test]
    fn classify_direct_fail_without_proxy_stays_ip_blocked() {
        assert_eq!(
            BlockType::classify(true, false, false, None),
            BlockType::IpBlocked
        );
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    /// САМЫЙ ДОРОГОЙ ОТКАЗ КОНТРАКТА. Продукт читает исход и решает, снимать ли лечение;
    /// поломка прибора, прочитанная как «цель чиста», оставляет человека без лечения — и
    /// именно из-за НАШЕЙ поломки, а не из-за состояния сети.
    #[test]
    fn a_broken_instrument_is_never_a_clean_target() {
        for reason in [
            BrokenReason::Nft,
            BrokenReason::NoCapNetAdmin,
            BrokenReason::QueueBusy { queue: 200 },
            BrokenReason::DnsFailed,
            BrokenReason::EngineStart,
            BrokenReason::InputUnreadable,
        ] {
            let broken = Outcome::Broken { reason };
            assert!(
                !broken.target_is_clean(),
                "поломка прибора не есть суждение о цели: {broken:?}"
            );
            assert_ne!(broken.exit_code(), 0, "поломка обязана быть видна кодом");
        }
    }

    /// «Ничего не подошло» — это ответ о МИРЕ, а не поломка: код выхода нулевой, и продукт
    /// вправе ему верить. Но чистой цель от этого не становится.
    #[test]
    fn an_empty_search_is_an_answer_not_a_failure() {
        let nothing = Outcome::NothingWorks { candidates: 121 };
        assert_eq!(nothing.exit_code(), 0);
        assert!(!nothing.target_is_clean());
    }

    /// Чистая цель — РОВНО один исход из четырёх.
    #[test]
    fn exactly_one_outcome_declares_the_target_clean() {
        let all = [
            Outcome::NotBlocked,
            Outcome::Found {
                working: 2,
                stopped_at: None,
            },
            Outcome::NothingWorks { candidates: 0 },
            Outcome::Censored {
                limit: Limit::Deadline,
            },
            Outcome::Broken {
                reason: BrokenReason::Nft,
            },
        ];
        assert_eq!(all.iter().filter(|o| o.target_is_clean()).count(), 1);
    }

    /// Цензурированный замер говорит о ПРИБОРЕ и обязан назвать сработавший предел: иначе
    /// «мы не досмотрели» неотличимо от «там ничего нет».
    #[test]
    fn a_censored_run_names_the_limit_that_cut_it() {
        assert_eq!(
            Outcome::Censored {
                limit: Limit::Deadline
            }
            .limit_name(),
            Some("deadline")
        );
        assert_eq!(
            Outcome::Censored { limit: Limit::Take }.limit_name(),
            Some("take")
        );
        assert_eq!(Outcome::NotBlocked.limit_name(), None);
        assert_eq!(
            Outcome::NothingWorks { candidates: 3 }.limit_name(),
            None,
            "полный перебор ничем не обрезан — предела назвать нельзя"
        );
    }

    /// Занятая очередь лечится другой очередью, а не переустановкой, — и потому носит
    /// собственный код, отличный от общего отказа преflight'а.
    #[test]
    fn a_busy_queue_has_its_own_exit_code() {
        let busy = Outcome::Broken {
            reason: BrokenReason::QueueBusy { queue: 200 },
        };
        assert_eq!(busy.exit_code(), EXIT_QUEUE_BUSY);
        assert_ne!(busy.exit_code(), 6, "это не общий отказ преflight'а");
    }

    /// Исход едет в JSON плоско: `outcome` — строка, подробности рядом. Читателю не нужно
    /// разбирать вложенный объект, чтобы узнать главное.
    #[test]
    fn the_outcome_serialises_flat_for_a_reader_without_a_compiler() {
        let json = serde_json::to_string(&Outcome::Broken {
            reason: BrokenReason::QueueBusy { queue: 200 },
        })
        .expect("исход сериализуем");
        assert!(json.contains(r#""outcome":"broken""#), "{json}");
        assert!(json.contains(r#""queue":200"#), "{json}");

        let clean = serde_json::to_string(&Outcome::NotBlocked).expect("исход сериализуем");
        assert_eq!(clean, r#"{"outcome":"not_blocked"}"#);
    }

    /// «Не проверяли» не есть «чисто». Прежнее булево поле их не различало, и на коробке
    /// без `curl` сверка не происходила НИ РАЗУ, сообщая при этом «подмены нет».
    #[test]
    fn an_unchecked_dns_is_not_reported_as_clean() {
        assert_ne!(DnsSpoofed::Unchecked, DnsSpoofed::Clean);
        assert_eq!(
            serde_json::to_string(&DnsSpoofed::Unchecked).expect("сериализуемо"),
            r#""unchecked""#
        );
    }
}

#[cfg(test)]
mod found_tests {
    use super::*;

    /// УСПЕХ И ЦЕНЗУРА — РАЗНЫЕ ВЕЩИ, и `--take` их не смешивает. Остановка после трёх
    /// найденных есть законный конец поиска, а не «мы не досмотрели»: читатель, увидевший
    /// `censored`, решал бы, что замер испорчен, тогда как лечение уже найдено.
    #[test]
    fn stopping_on_take_with_results_is_success_not_censorship() {
        let found = Outcome::Found {
            working: 3,
            stopped_at: Some(Limit::Take),
        };
        assert_eq!(found.exit_code(), 0);
        assert!(
            !found.target_is_clean(),
            "нашли лекарство — значит цель больна"
        );

        let json = serde_json::to_string(&found).expect("сериализуемо");
        assert!(json.contains(r#""outcome":"found""#), "{json}");
        assert!(json.contains(r#""stopped_at":"take""#), "{json}");
    }

    /// А вот обрезанный замер БЕЗ находок — это незнание, и оно обязано отличаться от
    /// полного перебора с тем же пустым списком.
    #[test]
    fn a_cut_search_without_results_is_not_the_same_as_a_complete_one() {
        let censored = Outcome::Censored {
            limit: Limit::Deadline,
        };
        let complete = Outcome::NothingWorks { candidates: 121 };
        assert_ne!(censored, complete);
        assert_eq!(censored.limit_name(), Some("deadline"));
        assert_eq!(
            complete.limit_name(),
            None,
            "полный перебор ничем не обрезан"
        );
    }

    /// Полный перебор с находками предела не называет — называть нечего.
    #[test]
    fn a_complete_search_with_results_names_no_limit() {
        let json = serde_json::to_string(&Outcome::Found {
            working: 2,
            stopped_at: None,
        })
        .expect("сериализуемо");
        assert_eq!(json, r#"{"outcome":"found","working":2}"#);
    }
}

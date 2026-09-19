//! РАСКЛАДКА МАРКИ — чьи биты какие.
//!
//! Марка пакета одна на всё ядро, и живём мы в ней не одни: у оркестратора там своё решение,
//! у его подмодуля — своя марка впрыска. Пока наши биты были константами, развязка держалась
//! на том, что ничьё правило не совпало с нашим, — то есть на порядке строк в чужом рулсете,
//! а не на типе. Это ломается у первого, кто правит соседний файл.
//!
//! Поэтому раскладка, во-первых, задаётся снаружи (`--mark-base`, `--desync-mark`), а
//! во-вторых, объявлена ОБЛАСТЯМИ, которые сосед может сверить машинно ([`BCW_REGIONS`]),
//! а не вычитать из README.

use std::sync::atomic::{AtomicU32, Ordering};

/// Непрерывная область битов марки.
///
/// Существует затем, чтобы пересечение владельцев было ВЫРАЗИМО ([`MarkRegion::overlaps`]),
/// а не помнимо. У оркестратора та же алгебра со своей стороны — сверка сходится.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkRegion {
    /// Номер младшего бита области.
    pub lowest_bit: u32,
    /// Сколько битов.
    pub width: u32,
}

impl MarkRegion {
    pub const fn new(lowest_bit: u32, width: u32) -> Self {
        MarkRegion { lowest_bit, width }
    }

    /// Маска области.
    pub const fn mask(self) -> u32 {
        match self.width {
            32 => u32::MAX,
            width => ((1u32 << width) - 1) << self.lowest_bit,
        }
    }

    /// Пересекаются ли области. То, ради чего этот тип и заведён.
    pub const fn overlaps(self, other: MarkRegion) -> bool {
        self.mask() & other.mask() != 0
    }
}

/// ОБЛАСТИ, КОТОРЫМИ ВЛАДЕЕТ BLOCKCHECKW. Публичный контракт с соседями по ядру.
///
/// Биты 0–15 — индекс профиля (он же потолок плана). Биты 28–29 — марка десинка и база
/// марки воркера.
pub const BCW_REGIONS: [MarkRegion; 2] = [
    MarkRegion::new(0, 16), // индекс профиля
    MarkRegion::new(28, 2), // десинк и база воркера
];

/// ЧУЖИЕ ОБЛАСТИ на машине третьего невода. Сверено с владельцем 20.09.2026; свободных битов
/// в марке на этой машине НЕТ ВОВСЕ.
///
/// · 13–27 — краевые приборы `reflex` (`instrument::edge::Layout::preset`). Прибор тишины
///   включён на двух пайпах, то есть памятка пишется в марку почти каждого пакета.
/// · 30–31 — марка впрыска `reflex`.
/// · 0–7 — решение о цели у невода (слот, карантин, приоритет). Пересекается с нашим
///   профилем НАМЕРЕННО: разойтись негде — у нас до 65 535 профилей, у него 253 марки.
///   Разводятся они не областью, а БИТОМ 29 (`WORKER_MARK_BASE`): правило `meta mark and
///   0x20000000 != 0 → return` стоит первым на каждой его двери. Порядок правил здесь
///   несущий, и у соседа это названо в приёмке.
pub const FOREIGN_REGIONS: [MarkRegion; 2] = [
    MarkRegion::new(13, 15), // краевые приборы reflex
    MarkRegion::new(30, 2),  // впрыск reflex
];

/// ПОТОЛОК ПРОФИЛЯ, НЕ ЗАЛЕЗАЮЩИЙ В ПРИБОРНУЮ ПОЛОСУ.
///
/// Приборы соседа начинаются с бита 13, а индекс профиля растёт снизу вверх: с 8192-го он
/// занимает бит 13, с 16384-го — четырнадцатый, и так далее. Пока профилей ≤ 8191, наша
/// марка и приборная памятка не делят ни одного бита — то есть развязка держится типом, а
/// не порядком правил в чужом рулсете.
///
/// Цена ограничения НУЛЕВАЯ при нынешних умолчаниях: `--profiles-per-instance` по умолчанию
/// 1024, а корпус в 13 943 стратегии режется на 2 плана даже при 8191. Поэтому потолок
/// применяется во встроенном режиме, где сосед есть, и не применяется вне него.
pub const MAX_PROFILES_CLEAR_OF_NEIGHBOURS: usize = (1 << 13) - 1;

/// Область, забронированная за соседями (ближайшая к нам): её мы не читаем и не пишем.
pub const NEIGHBOUR_REGION: MarkRegion = FOREIGN_REGIONS[0];

/// Маска индекса профиля. Потолок плана равен ей же.
pub const PROFILE_MASK: u32 = 0x0000_FFFF;

/// Умолчания — те же числа, что были константами до параметризации.
pub const DEFAULT_DESYNC_MARK: u32 = 0x1000_0000;
pub const DEFAULT_WORKER_MARK_BASE: u32 = 0x2000_0000;

/// Живая раскладка. Ставится один раз разбором командной строки, дальше только читается.
///
/// Глобально, а не полем в конфиге: марка — свойство ПРОЦЕССА (её читают сокеты проб в
/// библиотеке, правила в ядре и сборка argv движка), и протаскивание её через каждую из этих
/// сигнатур стоило бы дороже, чем даёт. Тот же выбор, что уже сделан для встроенности.
static DESYNC: AtomicU32 = AtomicU32::new(DEFAULT_DESYNC_MARK);
static WORKER_BASE: AtomicU32 = AtomicU32::new(DEFAULT_WORKER_MARK_BASE);

/// Проверенная раскладка. Получить её можно только через [`MarkSpace::new`], то есть после
/// проверки, — непроверенной раскладки в программе не существует.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkSpace {
    desync: u32,
    worker_base: u32,
}

impl MarkSpace {
    /// Собрать раскладку, проверив её на выразимость.
    ///
    /// Отказы здесь — не придирки, каждый из них тихо ломает подбор:
    /// · бит в поле профиля — марка профиля начнёт нести чужой бит, и движок выберет не тот
    ///   профиль либо не выберет никакой;
    /// · совпадение десинка и базы — пакет, вернувшийся от движка, неотличим от исходящего,
    ///   и правило зациклит его на себя;
    /// · ноль — «марки нет»: правило диспетчеризации не поймает ничего.
    pub fn new(desync: u32, worker_base: u32) -> Result<Self, String> {
        if desync == 0 || worker_base == 0 {
            return Err("марка не может быть нулевой: ноль значит «марки нет»".to_string());
        }
        if desync & PROFILE_MASK != 0 {
            return Err(format!(
                "--desync-mark 0x{desync:08X} залезает в поле профиля (0x{PROFILE_MASK:04X}): \
                 профиль перестанет выбираться"
            ));
        }
        if worker_base & PROFILE_MASK != 0 {
            return Err(format!(
                "--mark-base 0x{worker_base:08X} залезает в поле профиля (0x{PROFILE_MASK:04X}): \
                 профиль перестанет выбираться"
            ));
        }
        if desync & worker_base != 0 {
            return Err(format!(
                "--desync-mark 0x{desync:08X} и --mark-base 0x{worker_base:08X} пересекаются: \
                 наш собственный реинжект станет неотличим от исходящего пакета"
            ));
        }
        Ok(MarkSpace {
            desync,
            worker_base,
        })
    }

    pub fn desync(self) -> u32 {
        self.desync
    }

    pub fn worker_base(self) -> u32 {
        self.worker_base
    }

    /// Маска восстановления марки из `ct mark`: база воркера плюс индекс профиля, без бита
    /// десинка. Биты соседей под неё не попадают — это и проверяет тест.
    pub fn restore_mask(self) -> u32 {
        self.worker_base | PROFILE_MASK
    }

    /// Занимает ли раскладка чужие биты. Не отказ (хозяин ядра вправе дать нам любые), но
    /// повод сказать вслух: на машине третьего невода свободных битов нет, и всякий занятый
    /// нами бит отнят у соседа, а не найден пустым.
    pub fn intrudes_on_neighbours(self) -> bool {
        let ours = self.desync | self.worker_base;
        FOREIGN_REGIONS
            .iter()
            .any(|region| ours & region.mask() != 0)
    }
}

/// Текущая раскладка процесса.
pub fn space() -> MarkSpace {
    MarkSpace {
        desync: DESYNC.load(Ordering::Relaxed),
        worker_base: WORKER_BASE.load(Ordering::Relaxed),
    }
}

/// Объявить раскладку (ставится разбором командной строки, до всякой работы с ядром).
pub fn set_space(space: MarkSpace) {
    DESYNC.store(space.desync, Ordering::Relaxed);
    WORKER_BASE.store(space.worker_base, Ordering::Relaxed);
}

/// Разобрать марку из строки: `0x40000000` или десятичное число.
pub fn parse_mark(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    let parsed = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => trimmed.parse::<u32>(),
    };
    parsed.map_err(|_| format!("не марка: '{raw}' (ожидается 0xHEX или десятичное число)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ПЕРЕСЕЧЕНИЕ С ПОЛЕМ ПРОФИЛЯ НЕВЫРАЗИМО. Прежде развязка держалась на том, что
    /// правило соседа стоит первым, — на порядке строк, а не на типе.
    #[test]
    fn a_mark_space_overlapping_the_profile_field_is_refused() {
        assert!(MarkSpace::new(DEFAULT_DESYNC_MARK, DEFAULT_WORKER_MARK_BASE).is_ok());
        assert!(MarkSpace::new(0x0000_0100, DEFAULT_WORKER_MARK_BASE).is_err());
        assert!(MarkSpace::new(DEFAULT_DESYNC_MARK, 0x0000_FF00).is_err());
    }

    /// Совпавшие десинк и база — зацикливание на своих же пакетах.
    #[test]
    fn an_overlapping_desync_and_base_is_refused() {
        assert!(MarkSpace::new(0x1000_0000, 0x1000_0000).is_err());
        assert!(MarkSpace::new(0x3000_0000, 0x1000_0000).is_err());
    }

    #[test]
    fn a_zero_mark_is_refused() {
        assert!(MarkSpace::new(0, DEFAULT_WORKER_MARK_BASE).is_err());
        assert!(MarkSpace::new(DEFAULT_DESYNC_MARK, 0).is_err());
    }

    /// НАШИ МАРКИ УРОВНЯ ПРОЦЕССА не залезают в чужие полосы: умолчания (биты 28 и 29)
    /// лежат ровно между приборной полосой соседа и его же впрыском.
    #[test]
    fn our_process_marks_stay_clear_of_foreign_bands() {
        let space = MarkSpace::new(DEFAULT_DESYNC_MARK, DEFAULT_WORKER_MARK_BASE)
            .expect("умолчания валидны");
        assert!(!space.intrudes_on_neighbours());
        for region in FOREIGN_REGIONS {
            assert_eq!(
                (space.desync() | space.worker_base()) & region.mask(),
                0,
                "марка процесса залезла в чужую полосу {region:?}"
            );
        }
    }

    /// А вот раскладка, занимающая полосу впрыска соседа (бит 30), обязана быть ЗАМЕЧЕНА —
    /// свободных битов на этой машине нет, и всякий занятый нами отнят у кого-то.
    #[test]
    fn a_space_taking_a_foreign_band_is_noticed() {
        let intruding = MarkSpace::new(DEFAULT_DESYNC_MARK, 0x4000_0000).expect("валидна по форме");
        assert!(
            intruding.intrudes_on_neighbours(),
            "бит 30 принадлежит впрыску reflex"
        );
    }

    /// НАХОДКА СВЕРКИ 20.09.2026. Приборная полоса соседа начинается с бита 13, а наш индекс
    /// профиля растёт снизу: с 8192-го профиля он занимает тот же бит. То есть при большом
    /// `--profiles-per-instance` наша марка и приборная памятка делят биты 13–15, и развязка
    /// сводится к порядку правил в ЧУЖОМ рулсете — ровно то, от чего обе стороны уходили.
    #[test]
    fn a_large_plan_would_reach_into_the_instrument_band() {
        let instruments = FOREIGN_REGIONS[0];
        assert_eq!(instruments.lowest_bit, 13);

        // Потолок безопасен, следующий за ним профиль — уже нет.
        assert_eq!(
            MAX_PROFILES_CLEAR_OF_NEIGHBOURS as u32 & instruments.mask(),
            0,
            "потолок обязан не задевать приборную полосу"
        );
        assert_ne!(
            (MAX_PROFILES_CLEAR_OF_NEIGHBOURS as u32 + 1) & instruments.mask(),
            0,
            "первый профиль за потолком обязан её задевать — иначе потолок взят не оттуда"
        );
    }

    /// И ЦЕНА ПОТОЛКА НУЛЕВАЯ при нынешних умолчаниях: 1024 профиля лежат заметно ниже, а
    /// весь корпус режется на два плана даже впритык к потолку.
    #[test]
    fn the_ceiling_costs_nothing_at_current_defaults() {
        assert!(1024 < MAX_PROFILES_CLEAR_OF_NEIGHBOURS);
        assert_eq!(13_943_usize.div_ceil(MAX_PROFILES_CLEAR_OF_NEIGHBOURS), 2);
    }

    /// Профиль — шестнадцать бит, и это ПОТОЛОК ПЛАНА. Урезание до восьми, о котором
    /// просили сперва, стоило бы 55 перезапусков движка на корпусе вместо 15.
    #[test]
    fn the_profile_field_holds_the_whole_plan() {
        assert_eq!(PROFILE_MASK, 0xFFFF);
        assert_eq!(BCW_REGIONS[0].mask(), PROFILE_MASK);
        assert_eq!(13_943_usize.div_ceil(PROFILE_MASK as usize), 1);
    }

    #[test]
    fn marks_parse_from_hex_and_decimal() {
        assert_eq!(parse_mark("0x40000000"), Ok(0x4000_0000));
        assert_eq!(parse_mark("0X40000000"), Ok(0x4000_0000));
        assert_eq!(parse_mark("268435456"), Ok(0x1000_0000));
        assert!(parse_mark("не марка").is_err());
        assert!(parse_mark("0xZZ").is_err());
    }
}

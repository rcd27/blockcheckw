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
/// Биты 0–15 — индекс профиля (он же потолок плана: 65535 стратегий в одном процессе
/// движка). Биты 28–29 — марка десинка и база марки воркера.
///
/// Биты **16–27 не наши и не трогаются никогда**: там живут решение оркестратора и марка
/// впрыска его подмодуля. Отдать соседям младший байт, как просили сперва, нельзя — профиль
/// съёжился бы до 255, и корпус в 13 943 стратегии поехал бы 55 планами вместо 15, то есть
/// 55 перезапусков движка вместо 15.
pub const BCW_REGIONS: [MarkRegion; 2] = [
    MarkRegion::new(0, 16), // индекс профиля
    MarkRegion::new(28, 2), // десинк и база воркера
];

/// Область, забронированная за соседями: её мы не читаем и не пишем.
pub const NEIGHBOUR_REGION: MarkRegion = MarkRegion::new(16, 12);

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
    /// повод сказать вслух.
    pub fn intrudes_on_neighbours(self) -> bool {
        (self.desync | self.worker_base) & NEIGHBOUR_REGION.mask() != 0
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

    /// КОНТРАКТ С СОСЕДЯМИ, читаемый машинно: наши области не пересекаются с их полосой, и
    /// маска восстановления в неё не заглядывает.
    #[test]
    fn the_neighbour_band_is_untouched() {
        for region in BCW_REGIONS {
            assert!(
                !region.overlaps(NEIGHBOUR_REGION),
                "область bcw {region:?} залезла в биты соседей"
            );
        }
        let space = MarkSpace::new(DEFAULT_DESYNC_MARK, DEFAULT_WORKER_MARK_BASE)
            .expect("умолчания валидны");
        assert_eq!(space.restore_mask() & NEIGHBOUR_REGION.mask(), 0);
        assert!(!space.intrudes_on_neighbours());
    }

    /// Полоса соседей — двенадцать бит: 4096 слотов при их 253. Запас назван, чтобы
    /// следующий разговор о раскладке начинался с числа, а не с ощущения.
    #[test]
    fn the_neighbour_band_is_twelve_bits_wide() {
        assert_eq!(NEIGHBOUR_REGION.mask(), 0x0FFF_0000);
        assert_eq!(NEIGHBOUR_REGION.width, 12);
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

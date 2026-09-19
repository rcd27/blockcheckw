use std::num::NonZeroU16;

pub const DESYNC_MARK: u32 = 0x1000_0000;

pub const WORKER_MARK_BASE: u32 = 0x2000_0000;

pub const PROFILE_MASK: u32 = 0x0000_FFFF;

pub const RESTORE_MASK: u32 = WORKER_MARK_BASE | PROFILE_MASK;

const _: () = assert!(DESYNC_MARK & PROFILE_MASK == 0);
const _: () = assert!(DESYNC_MARK & RESTORE_MASK == 0);
const _: () = assert!(WORKER_MARK_BASE & PROFILE_MASK == 0);

/// СОБСТВЕННАЯ МАРКА ПРОЦЕССА — та, по которой ХОЗЯИН ЯДРА отличает наш трафик от трафика человека.
///
/// Пробы без десинка (контроль и эталон) идут с профилем НОЛЬ: профиль ноль не выбирается ни одним
/// нашим правилом, и проба честно минует собственную диспетчеризацию. Но марка при этом остаётся
/// ненулевой — и в этом вся разница для того, кто нас позвал.
///
/// Оплачено 19.09.2026 на стенде третьего невода: он уводит заблокированные цели в карантин ПО
/// АДРЕСУ, а контрольная проба шла с `fwmark = 0` — то есть уходила в карантин вместе с трафиком
/// человека и ПРОХОДИЛА. Отчёт говорил `inconclusive: true` («домен не режется»), хотя домен
/// режется: 39 рабочих страт из 965 на той же линии минутой позже. Замер был о другом мире.
///
/// Вне встроенного режима — ноль, как было: одиночный запуск никем не оркестрируется, и лишняя
/// марка меняла бы поведение там, где её некому читать.
pub fn own_mark() -> u32 {
    match EMBEDDED.load(std::sync::atomic::Ordering::Relaxed) {
        true => WORKER_MARK_BASE,
        false => 0,
    }
}

/// Встроенный ли режим. Живёт в библиотеке, а не в бинаре: марку читают пробы, а они библиотечные.
static EMBEDDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Объявить встроенный режим (ставится разбором командной строки).
pub fn set_embedded(embedded: bool) {
    EMBEDDED.store(embedded, std::sync::atomic::Ordering::Relaxed);
}

/// МАРКА ПРОБЫ. Два исхода, и ни одного числа снаружи.
///
/// Пока марка ездила как `u32`, литеральный ноль в вызове оставался выразимым — так и
/// появилась дыра, которую `3f5a001` закрыл в двух местах из трёх: контроль `check`
/// продолжал ходить с нулём, минуя `own_mark`, и во встроенном режиме уходил в карантин
/// хозяина ядра вместе с трафиком человека. Тип отнимает у вызывающего саму возможность
/// назвать марку: `Control` знает её у процесса, `Desync` — у профиля.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMark {
    /// БЕЗ десинка: контроль и эталон. Марку берёт у процесса, не у вызывающего.
    Control,
    /// С десинком: марка профиля выбирает стратегию внутри движка.
    Desync(ProfileMark),
}

impl ProbeMark {
    pub fn so_mark(self) -> u32 {
        match self {
            ProbeMark::Control => own_mark(),
            ProbeMark::Desync(profile) => profile.so_mark(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileMark(NonZeroU16);

impl ProfileMark {
    /// Марка профиля с индексом `index` (нумерация с единицы).
    pub fn new(index: u16) -> Option<Self> {
        NonZeroU16::new(index).map(ProfileMark)
    }

    pub fn index(self) -> u16 {
        self.0.get()
    }

    /// Что кладётся в `SO_MARK` сокета пробы.
    pub fn so_mark(self) -> u32 {
        WORKER_MARK_BASE | u32::from(self.0.get())
    }

    /// Что оказывается в `ct mark`. Правило выводит это значение само
    /// (`ct mark set mark or DESYNC_MARK`), поэтому на профиль правил не нужно.
    pub fn ct_mark(self) -> u32 {
        self.so_mark() | DESYNC_MARK
    }

    /// Объявление профиля в argv движка.
    pub fn filter_arg(self) -> String {
        format!("--filter-mark={}/0x{:04X}", self.0.get(), PROFILE_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ловушка nfq2/nfqws.c:159: бит DESYNC на чужом пакете — молчаливый VERDICT_PASS.
    /// Марка профиля не смеет его нести ни в одном из представлений.
    #[test]
    fn desync_bit_never_travels_with_a_profile_mark() {
        for index in 1..=u16::MAX {
            let mark = ProfileMark::new(index).expect("ненулевой индекс");
            assert_eq!(mark.so_mark() & DESYNC_MARK, 0, "SO_MARK, индекс {index}");
            // `so_mark` обязана инъективно кодировать индекс в младших битах —
            // на этом стоит уникальность fwmark разных профилей. Раньше это
            // проверял отдельный `worker_fwmarks_are_unique` над 512 марками
            // (`tests/e2e_infra.rs`, снесён вместе с `src/worker/` в задаче
            // 8ч2); здесь то же утверждение, но для всех 65535 индексов сразу
            // и в одном цикле с остальными инвариантами марки.
            assert_eq!(
                mark.so_mark() & PROFILE_MASK,
                u32::from(index),
                "so_mark обязана инъективно кодировать индекс профиля, индекс {index}"
            );
            // ct mark ОБЯЗАН нести бит DESYNC — правило выводит его отсюда
            // (`ct mark set mark or DESYNC_MARK`), и на этом стоит вся
            // защита от зацикливания на своих же пакетах.
            assert_ne!(
                mark.ct_mark() & DESYNC_MARK,
                0,
                "ct mark обязан нести бит DESYNC, индекс {index}"
            );
            // А восстановление под маской обязано снять его и вернуть ровно
            // ту марку, что стояла в SO_MARK: опознавательный бит плюс индекс.
            assert_eq!(
                mark.ct_mark() & RESTORE_MASK,
                mark.so_mark(),
                "восстановление из ct обязано вернуть SO_MARK, индекс {index}"
            );
        }
    }

    /// Восстановление из ct mark обязано вернуть ровно номер профиля — по нему
    /// движок и выбирает профиль (--filter-mark=N/0xFFFF).
    #[test]
    fn restoring_from_ct_mark_yields_the_profile_index() {
        for index in [1u16, 2, 255, 1024, u16::MAX] {
            let mark = ProfileMark::new(index).expect("ненулевой индекс");
            assert_eq!(
                mark.ct_mark() & RESTORE_MASK & PROFILE_MASK,
                u32::from(index)
            );
        }
    }

    /// Марка 0 неотличима от «марки нет»: правило диспетчеризации ловит пакеты
    /// по WORKER_MARK_BASE, и нулевой индекс дал бы профиль, который не выбрать.
    #[test]
    fn zero_is_not_a_profile_mark() {
        assert!(ProfileMark::new(0).is_none());
    }

    #[test]
    fn filter_arg_spells_index_and_mask() {
        let mark = ProfileMark::new(7).expect("ненулевой индекс");
        assert_eq!(mark.filter_arg(), "--filter-mark=7/0xFFFF");
    }
}

#[cfg(test)]
mod own_mark_tests {
    use super::*;

    /// Встроенность — ОДИН статик на процесс, а тесты бегут в потоках параллельно: без
    /// сериализации сосед, снявший режим, роняет замер того, кто его поставил. Гонка была
    /// и до этого модуля — здесь она просто закрыта, раз уж число читателей статика выросло.
    /// Имя НЕ `EMBEDDED`: так зовётся сам статик режима (`super::EMBEDDED`), и одноимённый
    /// замок затенял бы его под `use super::*` — читателю пришлось бы различать их по типу.
    static EMBEDDED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Выполнить замер при объявленной встроенности и вернуть режим как был.
    fn with_embedded<T>(embedded: bool, measure: impl FnOnce() -> T) -> T {
        // `unwrap_or_else` вместо `unwrap`: упавший сосед оставляет мьютекс отравленным, и
        // остальные замеры не должны падать следом — статик мы всё равно ставим сами.
        let _guard = EMBEDDED_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        set_embedded(embedded);
        let measured = measure();
        set_embedded(false);
        measured
    }

    /// ВНЕ ВСТРОЕННОГО РЕЖИМА МАРКА НУЛЕВАЯ — как было: одиночный запуск никем не оркестрируется,
    /// и лишняя марка меняла бы поведение там, где её некому читать.
    #[test]
    fn a_standalone_run_marks_nothing() {
        assert_eq!(with_embedded(false, own_mark), 0);
    }

    /// ВО ВСТРОЕННОМ — МАРКА ЕСТЬ, И ПРОФИЛЬ В НЕЙ НУЛЕВОЙ.
    ///
    /// Ненулевая марка нужна ХОЗЯИНУ ЯДРА: он отличает по ней наш трафик от трафика человека.
    /// Нулевой профиль нужен НАМ: проба без десинка обязана миновать собственную диспетчеризацию,
    /// а профиль ноль не выбирается ни одним нашим правилом.
    #[test]
    fn an_embedded_run_marks_with_a_zero_profile() {
        let mark = with_embedded(true, own_mark);

        assert_ne!(mark, 0, "хозяин ядра обязан нас отличить");
        assert_eq!(mark & PROFILE_MASK, 0, "а десинк обязан нас пропустить");
        assert_eq!(mark & WORKER_MARK_BASE, WORKER_MARK_BASE);
    }

    /// БАГ, ОПЛАЧЕННЫЙ ЗАМЕРОМ 19.09 И НЕ ДОЛЕЧЕННЫЙ `3f5a001`.
    ///
    /// Тот коммит поставил `own_mark()` в `baseline.rs` (путь `scan`) и в `reference.rs`
    /// (эталон), а `check.rs` передавал марку контроля ЛИТЕРАЛОМ `0` — и потому остался
    /// слепым. Поле `inconclusive` считается именно из этого контроля: во встроенном режиме
    /// проба уходила в карантин вместе с трафиком человека и ПРОХОДИЛА, отчёт объявлял
    /// «домен на этой линии не режется», продукт снимал лечение с режущейся цели.
    ///
    /// Дыра не ловилась потому, что искать её надо было по ПОТРЕБИТЕЛЯМ `own_mark`, а
    /// литеральный ноль по имени функции не ищется. Поэтому лечение — тип, а не вызов:
    /// пока марка `u32`, ноль остаётся выразимым и вернётся у следующего вызывающего.
    #[test]
    fn a_control_probe_carries_the_process_own_mark_when_embedded() {
        assert_eq!(
            with_embedded(true, || ProbeMark::Control.so_mark()),
            WORKER_MARK_BASE,
            "контроль обязан быть отличим хозяином ядра"
        );
    }

    #[test]
    fn a_control_probe_is_unmarked_outside_embedded_mode() {
        assert_eq!(with_embedded(false, || ProbeMark::Control.so_mark()), 0);
    }

    /// Проба С десинком берёт марку ПРОФИЛЯ, а не процесса: ею движок выбирает стратегию.
    #[test]
    fn a_desync_probe_carries_the_profile_mark_not_the_process_mark() {
        let profile = ProfileMark::new(7).expect("семёрка — валидный индекс профиля");
        let mark = with_embedded(true, || ProbeMark::Desync(profile).so_mark());

        assert_eq!(mark, profile.so_mark());
        assert_eq!(mark & PROFILE_MASK, 7, "профиль обязан доехать до движка");
    }
}

use std::num::NonZeroU16;

pub const DESYNC_MARK: u32 = 0x1000_0000;

pub const WORKER_MARK_BASE: u32 = 0x2000_0000;

pub const PROFILE_MASK: u32 = 0x0000_FFFF;

pub const RESTORE_MASK: u32 = WORKER_MARK_BASE | PROFILE_MASK;

const _: () = assert!(DESYNC_MARK & PROFILE_MASK == 0);
const _: () = assert!(DESYNC_MARK & RESTORE_MASK == 0);
const _: () = assert!(WORKER_MARK_BASE & PROFILE_MASK == 0);

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

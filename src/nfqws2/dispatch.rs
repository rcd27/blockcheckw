use crate::nfqws2::mark::{desync_mark, restore_mask, worker_mark_base};
use crate::nfqws2::plan::{Plan, QueueNum};

/// Исходящее направление: какие пакеты наши и что пометить в conntrack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutMatch {
    /// Биты, которые обязаны стоять в марке пакета.
    pub require_set: u32,
    /// Биты, которых в марке пакета быть не должно.
    pub require_clear: u32,
    /// Что подмешать в `ct mark`. Выводится из марки пакета, поэтому правил
    /// на профиль не нужно: `ct mark = mark | ct_set_or`.
    pub ct_set_or: u32,
}

/// Входящее направление: как вернуть пакету принадлежность профилю.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InRestore {
    /// Биты, по которым узнаём наше соединение в `ct mark`.
    pub ct_require_set: u32,
    /// Маска восстановления: `mark = ct mark & mark_from_ct_and`.
    /// Обязана снимать `DESYNC_MARK` — см. ловушку §4 спеки.
    pub mark_from_ct_and: u32,
}

/// Всё, что файрвол должен сделать, чтобы профили заработали.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dispatch {
    pub queue: QueueNum,
    pub dport: u16,
    pub out: OutMatch,
    pub inc: InRestore,
}

impl Plan {
    pub fn dispatch(&self, dport: u16) -> Dispatch {
        Dispatch {
            queue: self.queue(),
            dport,
            out: OutMatch {
                require_set: worker_mark_base(),
                require_clear: desync_mark(),
                ct_set_or: desync_mark(),
            },
            inc: InRestore {
                ct_require_set: worker_mark_base(),
                mark_from_ct_and: restore_mask(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfqws2::mark::{desync_mark, worker_mark_base, PROFILE_MASK};
    use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};

    fn dispatch_of() -> Dispatch {
        let strategies = vec![vec!["--a".to_string()]];
        Plan::from_strategies(&FilterMark::granted(), QueueNum::new(200), &strategies).dispatch(443)
    }

    #[test]
    fn the_restore_mask_strips_the_desync_bit() {
        assert_eq!(dispatch_of().inc.mark_from_ct_and & desync_mark(), 0);
    }

    #[test]
    fn the_restore_mask_keeps_our_signature_bit() {
        let mask = dispatch_of().inc.mark_from_ct_and;
        assert_eq!(mask & worker_mark_base(), worker_mark_base());
        assert_eq!(mask & PROFILE_MASK, PROFILE_MASK);
    }

    #[test]
    fn outgoing_requires_our_bit_and_forbids_the_desync_bit() {
        let out = dispatch_of().out;
        assert_eq!(out.require_set, worker_mark_base());
        assert_eq!(out.require_clear, desync_mark());
        assert_eq!(out.ct_set_or, desync_mark());
    }

    #[test]
    fn dispatch_carries_queue_and_port() {
        let d = dispatch_of();
        assert_eq!(d.queue.get(), 200);
        assert_eq!(d.dport, 443);
    }
}

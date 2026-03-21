use crate::config::WORKER_MARK_BASE;

#[derive(Debug, Clone)]
pub struct WorkerSlot {
    pub id: usize,
    pub qnum: u16,
    pub fwmark: u32,
}

impl WorkerSlot {
    pub fn create_slots(count: usize, base_qnum: u16) -> Vec<WorkerSlot> {
        (0..count)
            .map(|i| WorkerSlot {
                id: i,
                qnum: base_qnum + i as u16,
                fwmark: WORKER_MARK_BASE | ((i as u32) + 1),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_slots() {
        let slots = WorkerSlot::create_slots(4, 200);
        assert_eq!(slots.len(), 4);

        assert_eq!(slots[0].id, 0);
        assert_eq!(slots[0].qnum, 200);
        assert_eq!(slots[0].fwmark, 0x20000001);

        assert_eq!(slots[1].id, 1);
        assert_eq!(slots[1].qnum, 201);
        assert_eq!(slots[1].fwmark, 0x20000002);

        assert_eq!(slots[3].id, 3);
        assert_eq!(slots[3].qnum, 203);
        assert_eq!(slots[3].fwmark, 0x20000004);
    }

    #[test]
    fn test_fwmark_no_collision_with_desync() {
        let slots = WorkerSlot::create_slots(255, 200);
        let desync_mark = crate::config::DESYNC_MARK;
        for slot in &slots {
            assert_eq!(
                slot.fwmark & desync_mark,
                0,
                "worker fwmark must not overlap DESYNC_MARK"
            );
        }
    }
}

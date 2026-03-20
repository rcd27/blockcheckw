use crate::config::PORTS_PER_WORKER;

#[derive(Debug, Clone)]
pub struct WorkerSlot {
    pub id: usize,
    pub qnum: u16,
    pub port_start: u16,
    pub port_end: u16,
}

impl WorkerSlot {
    pub fn create_slots(
        count: usize,
        base_qnum: u16,
        base_local_port: u16,
    ) -> Vec<WorkerSlot> {
        // TODO: validate that base_local_port + count * PORTS_PER_WORKER and base_qnum + count
        // don't overflow u16 (currently safe with default values, but no bounds check)
        (0..count)
            .map(|i| {
                let port_start = base_local_port + (i as u16) * PORTS_PER_WORKER;
                WorkerSlot {
                    id: i,
                    qnum: base_qnum + i as u16,
                    port_start,
                    port_end: port_start + PORTS_PER_WORKER - 1,
                }
            })
            .collect()
    }

    /// Format as "30000-30009" for curl --local-port.
    pub fn local_port_arg(&self) -> String {
        format!("{}-{}", self.port_start, self.port_end)
    }

    /// Format as "30000-30009" for nft tcp sport range.
    pub fn sport_range(&self) -> String {
        if self.port_start == self.port_end {
            self.port_start.to_string()
        } else {
            format!("{}-{}", self.port_start, self.port_end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_slots() {
        let ppw = PORTS_PER_WORKER;
        let slots = WorkerSlot::create_slots(4, 200, 30000);
        assert_eq!(slots.len(), 4);

        assert_eq!(slots[0].id, 0);
        assert_eq!(slots[0].qnum, 200);
        assert_eq!(slots[0].port_start, 30000);
        assert_eq!(slots[0].port_end, 30000 + ppw - 1);

        assert_eq!(slots[1].id, 1);
        assert_eq!(slots[1].qnum, 201);
        assert_eq!(slots[1].port_start, 30000 + ppw);
        assert_eq!(slots[1].port_end, 30000 + 2 * ppw - 1);

        assert_eq!(slots[3].id, 3);
        assert_eq!(slots[3].qnum, 203);
        assert_eq!(slots[3].port_start, 30000 + 3 * ppw);
        assert_eq!(slots[3].port_end, 30000 + 4 * ppw - 1);
    }

    #[test]
    fn test_local_port_arg() {
        let slot = WorkerSlot {
            id: 0,
            qnum: 200,
            port_start: 30000,
            port_end: 30000 + PORTS_PER_WORKER - 1,
        };
        assert_eq!(slot.local_port_arg(), format!("30000-{}", 30000 + PORTS_PER_WORKER - 1));
    }

    #[test]
    fn test_sport_range() {
        let slot = WorkerSlot {
            id: 0,
            qnum: 200,
            port_start: 30000,
            port_end: 30000 + PORTS_PER_WORKER - 1,
        };
        assert_eq!(slot.sport_range(), format!("30000-{}", 30000 + PORTS_PER_WORKER - 1));
    }
}

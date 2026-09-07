use crate::nfqws2::plan::QueueNum;

pub const PROCFS_PATH: &str = "/proc/net/netfilter/nfnetlink_queue";

pub fn queue_bound(procfs: &str, queue: QueueNum) -> bool {
    procfs.lines().any(|line| {
        line.split_whitespace()
            .next()
            .and_then(|first| first.parse::<u16>().ok())
            .is_some_and(|n| n == queue.get())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfqws2::plan::QueueNum;

    /// Формат procfs: первая колонка — номер очереди, заголовка нет.
    const PROCFS: &str = concat!(
        "  200  31337     0 2 65531     0     0        4  1\n",
        "  201  31338     0 2 65531     0     0        2  1\n",
    );

    #[test]
    fn a_bound_queue_is_found() {
        assert!(queue_bound(PROCFS, QueueNum::new(200)));
        assert!(queue_bound(PROCFS, QueueNum::new(201)));
    }

    #[test]
    fn an_unbound_queue_is_not_found() {
        assert!(!queue_bound(PROCFS, QueueNum::new(202)));
    }

    /// Сравнение по ЧИСЛУ, а не по строке: «200» не должно находиться в «2001».
    #[test]
    fn queue_numbers_are_compared_numerically() {
        assert!(!queue_bound(
            "  2001  1     0 2 65531     0     0        0  1\n",
            QueueNum::new(200)
        ));
    }

    #[test]
    fn an_empty_file_binds_nothing() {
        assert!(!queue_bound("", QueueNum::new(200)));
    }
}

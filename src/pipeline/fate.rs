//! Словарь судьбы цели. Взят готовым у `reflex-instrument`: типология и закон `Sound`
//! оплачены их замерами, и вторая реализация разошлась бы с первой молча.

pub use reflex_instrument::fate::{observe, Admits, Delivery, Fate, Observed, ALL_FATES};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn байты_не_означают_что_страта_работает() {
        // Ровно то, что сегодня делает `interpret_check_result`: приехали байты — успех.
        // Парк говорит, что байты допускают три судьбы, и две из них не успех.
        let observed = observe(true, Delivery::Delivered);
        assert_eq!(observed, Observed::Bytes);
        assert_eq!(
            observed.admits(),
            [Fate::Mirage, Fate::Grinding, Fate::Good].as_slice()
        );
    }

    #[test]
    fn брошенное_наблюдение_не_приговор_а_полный_круг() {
        // «Не смотрели» ≠ «смотрели и пусто». Слить их — значит списать всякий свой
        // промах на цензора.
        let observed = observe(true, Delivery::Abandoned);
        assert_eq!(observed, Observed::Unobserved);
        assert_eq!(observed.admits(), ALL_FATES.as_slice());
    }

    #[test]
    fn молчание_после_коннекта_не_то_же_что_молчание_до() {
        // `Trap` (поздоровался впустую) и `Dead` (не поздоровался) лечатся по-разному:
        // у первого прямой путь жив.
        assert_eq!(observe(true, Delivery::Silent), Observed::Mute);
        assert_eq!(observe(false, Delivery::Silent), Observed::NoConnect);
        assert_eq!(Observed::Mute.admits(), [Fate::Trap].as_slice());
        assert_eq!(Observed::NoConnect.admits(), [Fate::Dead].as_slice());
    }

    #[test]
    fn байты_без_коннекта_есть_брак_прибора_а_не_судьба() {
        assert_eq!(observe(false, Delivery::Delivered), Observed::Inconsistent);
        assert_eq!(Observed::Inconsistent.admits(), ALL_FATES.as_slice());
    }
}

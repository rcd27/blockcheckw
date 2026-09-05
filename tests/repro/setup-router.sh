#!/usr/bin/env bash
# Превращает контейнер в имитацию OpenWrt-роутера для воспроизведения issue #66.
#   - dummy-линки с именами из flowtable фикстуры (иначе fw4 не грузится)
#   - реальный fw4-ruleset, снятый с OpenWrt 24.10.5
#   - фейковый /etc/init.d/zapret2 (без него detect_service_manager вернёт None
#     и опасная ветка с backup/restore ruleset не выполнится вовсе)
#   - чужая table inet zapret с queue-правилом на 443 (триггер detect_bypass_conflicts)
set -euo pipefail

FIXTURE="${1:-/app/tests/fixtures/fw4-openwrt-24.10.nft}"

echo "==> dummy-линки под flowtable"
for dev in eth1 lan1 lan2 lan3 phy0-ap0 phy1-ap0; do
    ip link show "$dev" >/dev/null 2>&1 || ip link add "$dev" type dummy
    ip link set "$dev" up
done

echo "==> чистый ruleset + fw4 из фикстуры"
# В контейнере нет hardware offload (dummy-линки), поэтому единственное
# отличие стенда от живого роутера — снятый flag offload у flowtable.
# Оригинал фикстуры остаётся нетронутым эталоном.
sed '/^\t\tflags offload$/d' "$FIXTURE" > /tmp/fw4-stand.nft
nft flush ruleset
nft -f /tmp/fw4-stand.nft

echo "==> чужая таблица zapret (имитация работающего zapret1)"
nft add table inet zapret
nft add chain inet zapret postrouting '{ type filter hook postrouting priority 101; }'
nft add rule inet zapret postrouting meta l4proto tcp tcp dport '{ 80, 443 }' queue num 200 bypass

echo "==> фейковый /etc/init.d/zapret2"
cat > /etc/init.d/zapret2 <<'INITD'
#!/bin/sh
# Имитация init-скрипта zapret1/zapret2: stop убирает свою таблицу, start возвращает.
case "$1" in
    start)
        nft add table inet zapret
        nft add chain inet zapret postrouting '{ type filter hook postrouting priority 101; }'
        nft add rule inet zapret postrouting meta l4proto tcp tcp dport '{ 80, 443 }' queue num 200 bypass
        ;;
    stop)
        nft delete table inet zapret 2>/dev/null || true
        ;;
    *) echo "usage: $0 {start|stop}" >&2; exit 1 ;;
esac
INITD
chmod +x /etc/init.d/zapret2

echo "==> готово"
nft list tables

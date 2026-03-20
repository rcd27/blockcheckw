#!/bin/bash
# Скрипт для тестирования одной стратегии
# Использование: sudo bash test_strategy.sh "<nfqws2 args>"

NFQWS2="/opt/zapret2/binaries/linux-x86_64/nfqws2"
QNUM=200
MARK=0x10000000
IP="104.21.32.39"
DOMAIN="rutracker.org"
LOCAL_PORTS="30000-30009"

STRATEGY_ARGS="$1"

echo "=== Testing strategy: $STRATEGY_ARGS ==="

# 1. Setup nftables table
nft add table inet zapret 2>/dev/null
nft add chain inet zapret postnat '{ type filter hook postrouting priority 102; }' 2>/dev/null
nft add chain inet zapret predefrag '{ type filter hook output priority -402; }' 2>/dev/null
nft add rule inet zapret predefrag meta nfproto ipv4 mark and $MARK != 0 notrack 2>/dev/null
nft add chain inet zapret prenat '{ type filter hook prerouting priority -102; }' 2>/dev/null

# 2. Start nfqws2
echo "Starting nfqws2..."
$NFQWS2 --qnum=$QNUM --fwmark=$MARK \
  --lua-init=@/opt/zapret2/lua/zapret-lib.lua \
  --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua \
  $STRATEGY_ARGS &
NFQWS_PID=$!
sleep 0.2

# 3. Add nftables rules
OUT_HANDLE=$(nft --echo --handle add rule inet zapret postnat \
  meta nfproto ipv4 tcp sport $LOCAL_PORTS tcp dport 443 \
  mark and $MARK == 0 ip daddr $IP \
  ct mark set ct mark or $MARK queue num $QNUM 2>&1 | grep -oP 'handle \K\d+' | tail -1)

IN_HANDLE=$(nft --echo --handle add rule inet zapret prenat \
  meta nfproto ipv4 tcp sport 443 tcp dport $LOCAL_PORTS \
  'tcp flags & (syn | ack) == (syn | ack)' ip saddr $IP \
  queue num $QNUM 2>&1 | grep -oP 'handle \K\d+' | tail -1)

echo "Outgoing rule handle: $OUT_HANDLE"
echo "Incoming rule handle: $IN_HANDLE"

# 4. Run curl test
echo "Running curl..."
HTTP_CODE=$(curl -4 --noproxy "*" -Ss -I -A Mozilla --max-time 3 \
  --tlsv1.2 --tls-max 1.2 \
  --local-port $LOCAL_PORTS \
  --connect-to "$DOMAIN::$IP:443" \
  -o /dev/null -w "%{http_code}" \
  "https://$DOMAIN" 2>&1)
CURL_EXIT=$?

echo "curl exit: $CURL_EXIT, http_code: $HTTP_CODE"

if [ $CURL_EXIT -eq 0 ] && [ "$HTTP_CODE" != "000" ]; then
  echo "RESULT: WORKS"
else
  echo "RESULT: FAILED"
fi

# 5. Cleanup
nft delete rule inet zapret postnat handle $OUT_HANDLE 2>/dev/null
nft delete rule inet zapret prenat handle $IN_HANDLE 2>/dev/null
kill $NFQWS_PID 2>/dev/null
wait $NFQWS_PID 2>/dev/null

echo "=== Done ==="

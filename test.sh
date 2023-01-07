set -x

PWRU_COMMAND=${PWRU_COMMAND:-$(pwd)/pwru}

for addr in '127.0.0.1' '::1'; do
  pwru_addr=$addr
  pwru_protocol="icmp"
  iptables_protocol="icmp"
  iptables_command=iptables
  if $(echo $addr | grep -q ':'); then
    pwru_addr="[$addr]"
    pwru_protocol="icmp6"
    iptables_protocol="icmpv6"
    iptables_command=ip6tables
  fi

  # Block icmp to localhost, so that we can see kfree_skb* in traces (test assertion)
  $iptables_command -I OUTPUT 1 --proto $iptables_protocol --dst $addr -j DROP

  "$PWRU_COMMAND" --filter-dst-ip="$addr" --filter-proto=$pwru_protocol \
    --output-tuple --output-file=/tmp/pwru-$addr.log \
    --ready-file=/tmp/pwru-$addr.ready 2>/tmp/pwru-$addr.status &
  PWRU_PID=$!

  while [ ! -f /tmp/pwru-$addr.ready ]; do sleep 1; done

  ping -w 1 $addr || true

  kill $PWRU_PID
  wait $PWRU_PID

  $iptables_command -D OUTPUT 1

  grep -F "kfree_skb" /tmp/pwru-$addr.log | \
    grep -F "$pwru_addr:0->$pwru_addr:0($pwru_protocol)"

  if [ ! $? ]; then exit 1; fi
done

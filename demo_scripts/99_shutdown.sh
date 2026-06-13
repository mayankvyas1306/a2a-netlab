#!/bin/bash
echo "=== GRACEFUL SHUTDOWN ==="
for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
  docker exec $c pkill -TERM a2a_agent 2>/dev/null || true
done
echo "All agents stopped."
#!/bin/bash
# Poll a Kleenscan runtime scan until complete, then fetch the result.
# Usage: tools/poll_runtime.sh <scan_token>   (reads tools/.kleenscan_token)
set -u
cd "$(dirname "$0")/.."
TOKEN=$(cat tools/.kleenscan_token)
SCAN="$1"

for i in $(seq 1 55); do
    sleep 60
    STATUS=$(curl -sS "https://www.kleenscan.biz/api/v1/runtime/status/$SCAN" \
        -H "X-Auth-Token: $TOKEN" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    echo "[poll $i] status=$STATUS"
    # top-level status: 3 = finished (per prior lots); treat >=3 as done
    if [ "$STATUS" = "3" ] || [ "$STATUS" = "4" ]; then
        echo "=== RESULT ==="
        curl -sS -X POST "https://www.kleenscan.biz/api/v1/runtime/result/$SCAN" \
            -H "X-Auth-Token: $TOKEN"
        echo
        exit 0
    fi
done
echo "[poller] gave up after 55 min; fetch result manually with token $SCAN"
exit 1

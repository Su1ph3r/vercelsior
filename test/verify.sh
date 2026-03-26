#!/usr/bin/env bash
set -euo pipefail

FIXTURES_DIR="${1:-test/fixtures/baseline}"
OUTPUT_DIR="test/output"

if [ ! -d "$FIXTURES_DIR" ]; then
    echo "No fixtures found at $FIXTURES_DIR"
    echo "Run: vercelsior --token YOUR_TOKEN --record $FIXTURES_DIR"
    exit 1
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo "=== Running vercelsior in replay mode ==="
go run ./cmd/vercelsior/ --replay "$FIXTURES_DIR" --no-color -o "$OUTPUT_DIR" -f json || true

JSON_FILE=$(ls "$OUTPUT_DIR"/*.json 2>/dev/null | head -1)
if [ -z "$JSON_FILE" ]; then
    echo "FAIL: No JSON output produced"
    exit 1
fi

echo ""
echo "=== Checking for expected findings ==="

EXPECTED_CHECKS=(
    "iam-001"
    "fw-001"
    "sec-001"
    "njs-001"
    "dep-001"
    "log-001"
    "prev-001"
)

PASS=0
FAIL=0

for check in "${EXPECTED_CHECKS[@]}"; do
    if grep -q "\"check_id\":\"$check\"" "$JSON_FILE" 2>/dev/null || grep -q "\"check_id\": \"$check\"" "$JSON_FILE" 2>/dev/null; then
        echo "  PASS: $check found in output"
        ((PASS++))
    else
        echo "  MISS: $check NOT found in output"
        ((FAIL++))
    fi
done

echo ""
echo "=== Results: $PASS passed, $FAIL missing ==="

TOTAL_FINDINGS=$(grep -c '"check_id"' "$JSON_FILE" 2>/dev/null || echo "0")
echo "Total findings in report: $TOTAL_FINDINGS"

POSTURE=$(grep -o '"posture_score":[0-9.]*' "$JSON_FILE" 2>/dev/null || echo "unknown")
echo "Posture score: $POSTURE"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "WARNING: $FAIL expected checks were not found in the output."
    echo "This may indicate API response format changes or check logic issues."
    exit 1
fi

echo ""
echo "All expected checks found. Review the full report at: $OUTPUT_DIR"

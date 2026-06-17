#!/bin/bash
# Quick scan wrapper
if [ -z "$1" ]; then
    echo "Usage: ./scripts/quick_scan.sh <domain> [--fast|--full]"
    exit 1
fi
cd "$(dirname "$0")/.."
MODE="${2:---fast}"
python h4wk3y3.py -t "$1" $MODE

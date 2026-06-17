#!/bin/bash
# Resolve paths relative to this script so it works from any install dir.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/go/bin:/usr/local/go-tools/bin:$PATH"
exec "$HERE/argus-env/bin/python3" "$HERE/h4wk3y3.py" "$@"

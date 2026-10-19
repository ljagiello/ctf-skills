#!/bin/bash
# CTF Similar Challenge Search Script
# Usage:
#   ./search.sh search <keyword>
#   ./search.sh extract <url1> [url2] ...

set -e

ACTION="${1:-}"
if [ -z "$ACTION" ]; then
    echo "Usage:"
    echo "  $0 search <keyword>"
    echo "  $0 extract <url1> [url2] ..."
    echo ""
    echo "Examples:"
    echo "  $0 search 'SSRF vulnerability'"
    echo "  $0 extract 'https://example.com/article1'"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run Python script
python3 "$SCRIPT_DIR/search.py" "$@"

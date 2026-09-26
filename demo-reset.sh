#!/usr/bin/env bash
# demo-reset.sh
# Resets the SecureBank demo app to its VULNERABLE state.
# Run this before each hackathon demo to ensure a clean starting point.

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO="$ROOT/demo-app"
ACCOUNTS_FILE="$DEMO/app/routes/accounts.py"

echo "Resetting SecureBank demo app to vulnerable state..."

# Remove database (will be re-seeded on next startup)
rm -f "$DEMO/securebank.db"

# Remove any SECUREFIX-generated regression test files
rm -f "$DEMO/tests/test_securefix_regression_"*.py

# Restore the vulnerable accounts.py using Python
python3 - "$ACCOUNTS_FILE" <<'PYEOF'
import sys
from pathlib import Path

fpath = Path(sys.argv[1])
content = fpath.read_text()

fixed_block = (
    '    # SECUREFIX: Authorization check — verify that requester owns this account\n'
    '    if row["user_id"] != current_user["id"]:\n'
    '        raise HTTPException(\n'
    '            status_code=403,\n'
    '            detail="Access forbidden: you do not own this account",\n'
    '        )\n'
    '\n'
    '    return Account(**dict(row))'
)

vuln_block = (
    '    # BUG: Should be: if row["user_id"] != current_user["id"]: raise 403\n'
    '    # But that check is absent here.\n'
    '\n'
    '    return Account(**dict(row))'
)

if 'SECUREFIX: Authorization check' in content:
    content = content.replace(fixed_block, vuln_block)
    fpath.write_text(content)
    print('  ✓ accounts.py restored to vulnerable state')
else:
    print('  ✓ accounts.py already in vulnerable state')
PYEOF

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║  Demo Reset Complete                      ║"
echo "║  Vulnerability status: ACTIVE             ║"
echo "╚═══════════════════════════════════════════╝"
echo ""
echo "  Vulnerable endpoint: GET /api/accounts/{id}"
echo "  Exploit: login as alice, access /api/accounts/2"
echo "  Expected result: 200 OK (VULNERABLE)"
echo ""
echo "  Start demo with: ./start.sh"

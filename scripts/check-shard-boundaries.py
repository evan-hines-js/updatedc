"""Pin the CEL shard-name boundaries in the write policies to the Rust contract.

RBAC cannot resourceName-restrict CREATE, so these regexes are the object-level boundary on what
the controller may bring into existence. Checked behaviourally: the rendered pattern must admit the
contract's last shard and refuse the one past it.
"""

import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
cases = [
    ("-inventory-", int(sys.argv[2]), "updated-backend-edge-inventory-{:02}"),
    ("-[ab]-", int(sys.argv[3]), "updatec-admitted-default-a-{:02}"),
]
for marker, count, sample in cases:
    found = re.search(r"matches\('([^']*" + re.escape(marker) + r"[^']*)'\)", text)
    if not found:
        sys.exit(f"FAIL: no CEL shard boundary containing {marker} in the rendered policies")
    pattern = found.group(1)
    if not re.search(pattern, sample.format(count - 1)):
        sys.exit(f"FAIL: {pattern} refuses shard {count - 1}, which the contract allows")
    if re.search(pattern, sample.format(count)):
        sys.exit(f"FAIL: {pattern} admits shard {count}; the contract stops at {count - 1}")
    print(f"ok: the {marker} boundary admits 0..{count - 1} and refuses {count}")

#!/usr/bin/env bash
# Enforce the FIRST-PARTY half of the licensing policy: a permissive crate must
# never depend on an AGPL crate.
#
# cargo-deny (deny.toml) checks that every licence in the graph is one we allow.
# It cannot check this, because this is not a property of any single crate's
# licence — it is a property of which of OUR crates reach which others. Get it
# wrong and a crate published to crates.io as
# `Apache-2.0 OR BSD-2-Clause-Patent` carries an AGPL obligation into every
# downstream consumer, silently.
#
# Policy source: CLAUDE.md ("Licensing"), docs/decisions/2026-07-23-license-split.md,
# docs/decisions/2026-08-02-protocol-tier-extraction.md.
#
# Dev-dependencies are deliberately NOT walked: they are not distributed, so
# recrypt-storage-auth (AGPL) appearing as a dev-dependency of a test harness
# is fine and expected.

set -euo pipefail

cd "$(dirname "$0")/.."

metadata=$(cargo metadata --no-deps --format-version 1)

agpl_crates=$(echo "$metadata" | jq -r '.packages[] | select(.license // "" | test("AGPL")) | .name' | sort)
permissive_crates=$(echo "$metadata" | jq -r '.packages[] | select((.license // "") | test("AGPL") | not) | .name' | sort)

if [ -z "$agpl_crates" ]; then
    echo "No AGPL crates in the workspace — nothing to separate."
    exit 0
fi

echo "AGPL (deployable) crates:"
echo "$agpl_crates" | sed 's/^/  /'
echo
echo "Permissive crates (must not reach any of the above):"
echo "$permissive_crates" | sed 's/^/  /'
echo

violations=0

for crate in $permissive_crates; do
    # normal + build edges only; no dev edges. --no-dedupe so a crate that
    # appears only under an already-printed subtree is still visible.
    tree=$(cargo tree -p "$crate" --edges normal,build --no-dedupe --prefix none --format '{p}' 2>/dev/null || true)

    for agpl in $agpl_crates; do
        # Match the crate name at a word boundary, not a substring: without
        # this, "recrypt-storage" would match "recrypt-storage-auth".
        if echo "$tree" | grep -qE "^${agpl} v"; then
            echo "VIOLATION: permissive crate '${crate}' depends on AGPL crate '${agpl}'"
            cargo tree -p "$crate" --edges normal,build --invert "$agpl" 2>/dev/null | head -20 || true
            violations=$((violations + 1))
        fi
    done
done

if [ "$violations" -gt 0 ]; then
    echo
    echo "FAILED: ${violations} permissive-crate(s) reach AGPL code."
    echo "Either the dependency is wrong, or the crate belongs in the deployable tier."
    exit 1
fi

echo "OK: no permissive crate depends on an AGPL crate."

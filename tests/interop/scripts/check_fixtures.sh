#!/usr/bin/env bash
# check_fixtures.sh — verify every fixture under tests/interop/fixtures/
# matches its sha256 in MANIFEST.toml AND matches the verbatim bytes of the
# upstream Rust libsignal file at the commit recorded in /RUST_REV.
#
# Exit codes:
#   0  every fixture matches the manifest AND (if upstream tree is present)
#      matches the upstream bytes verbatim
#   1  a manifest hash check failed (drift between fixture bytes and manifest)
#   2  a fixture is missing from disk
#   3  upstream-bytes check failed (drift between fixture and upstream tree;
#      run when LIBSIGNAL_UPSTREAM is set, otherwise skipped)
#
# Usage:
#   tests/interop/scripts/check_fixtures.sh                 # manifest only
#   LIBSIGNAL_UPSTREAM=/path/to/libsignal \
#       tests/interop/scripts/check_fixtures.sh             # full check

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEROP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${INTEROP_DIR}/../.." && pwd)"
FIXTURES_DIR="${INTEROP_DIR}/fixtures"
MANIFEST="${FIXTURES_DIR}/MANIFEST.toml"
RUST_REV_FILE="${REPO_ROOT}/RUST_REV"

if [[ ! -f "${MANIFEST}" ]]; then
    echo "manifest missing: ${MANIFEST}" >&2
    exit 2
fi

if [[ ! -f "${RUST_REV_FILE}" ]]; then
    echo "RUST_REV missing: ${RUST_REV_FILE}" >&2
    exit 2
fi

# Parse the pinned upstream commit (first non-comment, non-empty line).
RUST_REV="$(grep -vE '^\s*(#|$)' "${RUST_REV_FILE}" | head -n1 || true)"

# Extract fixture entries from the manifest. Each [[fixture]] block must have
# path/upstream/sha256/size — we read them in lockstep.
parse_manifest() {
    python3 - "${MANIFEST}" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
blocks = re.split(r"^\s*\[\[fixture\]\]\s*$", text, flags=re.MULTILINE)
for blk in blocks[1:]:
    fields = {}
    for m in re.finditer(r'^\s*(\w+)\s*=\s*("([^"]*)"|(\d+))\s*$', blk, re.MULTILINE):
        fields[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(4)
    # Multi-line array literals: upstream_must_contain = [ "...", "...", ]
    arr_match = re.search(r'^\s*upstream_must_contain\s*=\s*\[(.*?)\]', blk, re.MULTILINE | re.DOTALL)
    contains = []
    if arr_match:
        for s in re.findall(r'"([^"]*)"', arr_match.group(1)):
            contains.append(s)
    kind = fields.get("upstream_kind", "verbatim")
    if all(k in fields for k in ("path", "upstream", "sha256", "size")):
        # Field delimiter: \x1f (Unit Separator) so empty fields don't collapse
        # under bash's IFS whitespace-trimming rules. Needles within a single
        # fixture use \x1e (Record Separator) to avoid clashing.
        needles = "\x1e".join(contains)
        print(f'{fields["path"]}\x1f{fields["upstream"]}\x1f{fields["sha256"]}\x1f{fields["size"]}\x1f{kind}\x1f{needles}')
PY
}

manifest_fail=0
upstream_fail=0
missing=0
checked=0

while IFS=$'\x1f' read -r rel_path upstream sha_expected size_expected kind needles; do
    [[ -z "${rel_path}" ]] && continue
    fixture="${FIXTURES_DIR}/${rel_path}"

    if [[ ! -f "${fixture}" ]]; then
        echo "MISSING ${rel_path}" >&2
        missing=$((missing + 1))
        continue
    fi

    sha_actual="$(sha256sum "${fixture}" | cut -d' ' -f1)"
    size_actual="$(wc -c <"${fixture}" | tr -d ' ')"

    if [[ "${sha_actual}" != "${sha_expected}" ]]; then
        echo "SHA MISMATCH ${rel_path}" >&2
        echo "    expected ${sha_expected}" >&2
        echo "    actual   ${sha_actual}" >&2
        manifest_fail=$((manifest_fail + 1))
        continue
    fi

    if [[ "${size_actual}" != "${size_expected}" ]]; then
        echo "SIZE MISMATCH ${rel_path}" >&2
        echo "    expected ${size_expected} bytes" >&2
        echo "    actual   ${size_actual} bytes" >&2
        manifest_fail=$((manifest_fail + 1))
        continue
    fi

    if [[ -n "${LIBSIGNAL_UPSTREAM:-}" ]]; then
        upstream_path="${LIBSIGNAL_UPSTREAM}/rust/${upstream}"
        # Fixtures that are locally generated (emitted, synthetic, computed) have
        # no verbatim upstream file to compare against; skip the file-existence
        # check for those kinds and fall through to the case below.
        if [[ "${kind}" != "emitted" && "${kind}" != "synthetic" && "${kind}" != "computed" ]]; then
            if [[ ! -f "${upstream_path}" ]]; then
                echo "UPSTREAM MISSING ${upstream} (rev ${RUST_REV})" >&2
                upstream_fail=$((upstream_fail + 1))
                continue
            fi
        fi
        case "${kind}" in
            verbatim|"")
                if ! cmp -s "${fixture}" "${upstream_path}"; then
                    echo "UPSTREAM DRIFT ${rel_path} <-> rust/${upstream}" >&2
                    upstream_fail=$((upstream_fail + 1))
                    continue
                fi
                ;;
            extracted)
                # Hand-extracted constants. The fixture is not byte-equal to
                # upstream; instead, every entry in upstream_must_contain
                # must appear verbatim in the upstream source file.
                if [[ -z "${needles}" ]]; then
                    echo "MANIFEST ERROR ${rel_path}: upstream_kind=extracted requires upstream_must_contain" >&2
                    upstream_fail=$((upstream_fail + 1))
                    continue
                fi
                missing_needle=0
                IFS=$'\x1e' read -ra needle_arr <<<"${needles}"
                for needle in "${needle_arr[@]}"; do
                    if ! grep -F -q -- "${needle}" "${upstream_path}"; then
                        echo "UPSTREAM MISSING NEEDLE ${rel_path}: %q not found in rust/${upstream}" >&2
                        printf '    needle: %s\n' "${needle}" >&2
                        missing_needle=1
                    fi
                done
                if [[ ${missing_needle} -ne 0 ]]; then
                    upstream_fail=$((upstream_fail + 1))
                    continue
                fi
                ;;
            synthetic|emitted|computed)
                # No upstream-tree byte-for-byte comparison possible for these
                # fixture kinds: synthetic = hand-authored, emitted = generated
                # by tests/interop/rust/src/bin/wire_emitter.rs, computed =
                # derived from a deterministic transform of upstream sources.
                # MANIFEST sha256 + size are still validated above.
                ;;
            *)
                echo "MANIFEST ERROR ${rel_path}: unknown upstream_kind=${kind}" >&2
                upstream_fail=$((upstream_fail + 1))
                continue
                ;;
        esac
    fi

    checked=$((checked + 1))
done < <(parse_manifest)

if [[ ${missing} -gt 0 ]]; then
    echo "${missing} fixture(s) missing from disk" >&2
    exit 2
fi

if [[ ${manifest_fail} -gt 0 ]]; then
    echo "${manifest_fail} fixture(s) drift from manifest" >&2
    exit 1
fi

if [[ ${upstream_fail} -gt 0 ]]; then
    echo "${upstream_fail} fixture(s) drift from upstream tree at rev ${RUST_REV}" >&2
    exit 3
fi

if [[ -n "${LIBSIGNAL_UPSTREAM:-}" ]]; then
    echo "OK ${checked} fixture(s) match manifest AND upstream rev ${RUST_REV}"
else
    echo "OK ${checked} fixture(s) match manifest (upstream check skipped; set LIBSIGNAL_UPSTREAM to enable)"
fi

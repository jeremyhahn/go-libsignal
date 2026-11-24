#!/usr/bin/env bash
# refresh_fixtures.sh <libsignal-checkout> recopies MANIFEST.toml fixtures; then update MANIFEST hashes and /RUST_REV and run make interop-fixtures-check.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path-to-libsignal-checkout>" >&2
    exit 2
fi

UPSTREAM="$1"
if [[ ! -d "${UPSTREAM}/rust" ]]; then
    echo "no rust/ directory under ${UPSTREAM}" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEROP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES_DIR="${INTEROP_DIR}/fixtures"
MANIFEST="${FIXTURES_DIR}/MANIFEST.toml"

parse_manifest() {
    python3 - "${MANIFEST}" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
blocks = re.split(r"^\s*\[\[fixture\]\]\s*$", text, flags=re.MULTILINE)
for blk in blocks[1:]:
    fields = {}
    for m in re.finditer(r'^\s*(\w+)\s*=\s*("([^"]*)"|(\d+))\s*$', blk, re.MULTILINE):
        fields[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(4)
    if "path" in fields and "upstream" in fields:
        print(f'{fields["path"]}\t{fields["upstream"]}')
PY
}

missing=0
copied=0

while IFS=$'\t' read -r rel_path upstream; do
    [[ -z "${rel_path}" ]] && continue
    src="${UPSTREAM}/rust/${upstream}"
    dst="${FIXTURES_DIR}/${rel_path}"

    if [[ ! -f "${src}" ]]; then
        echo "MISSING ${upstream} (under ${UPSTREAM}/rust/)" >&2
        missing=$((missing + 1))
        continue
    fi

    mkdir -p "$(dirname "${dst}")"
    cp "${src}" "${dst}"
    copied=$((copied + 1))
    echo "refreshed ${rel_path}"
done < <(parse_manifest)

if [[ ${missing} -gt 0 ]]; then
    echo "${missing} upstream file(s) missing; refresh incomplete" >&2
    exit 3
fi

echo "OK ${copied} fixture(s) refreshed from ${UPSTREAM}"
echo "Next steps:"
echo "  1. make interop-fixtures-check"
echo "  2. Update sha256/size in tests/interop/fixtures/MANIFEST.toml"
echo "  3. Update /RUST_REV with the upstream commit being tracked"

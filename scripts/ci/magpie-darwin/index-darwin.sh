#!/bin/sh
set -eu

if test "$#" -ne 5; then
    echo "Usage: $0 CBM_BINARY CBM_SOURCE MAGPIE_SNAPSHOT SITE_MANIFEST NEW_OUTPUT_DIRECTORY" >&2
    exit 2
fi
if test "$(uname -s)" != Darwin; then
    echo "This acceptance run requires native macOS and its SDK." >&2
    exit 2
fi
xcrun --sdk macosx --find clang
sdk=$(xcrun --sdk macosx --show-sdk-path)
test -d "$sdk"
go=$(command -v go)
python=$(command -v python3)
script_dir=$(cd "$(dirname "$0")" && pwd -P)
binary=$(cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$1")")
cbm_source=$(cd "$2" && pwd -P)
magpie=$(cd "$3" && pwd -P)
witnesses=$(cd "$(dirname "$4")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$4")")

test -x "$binary"
test -f "$magpie/go.mod"
test -r "$witnesses"
case "$(cd "$(dirname "$5")" && pwd -P)/$(basename "$5")" in
    "$magpie"|"$magpie"/*) echo "The output directory must be outside the Magpie snapshot." >&2; exit 2 ;;
esac
umask 077
mkdir "$5"
output=$(cd "$5" && pwd -P)
mkdir "$output/cache" "$output/runtime" "$output/tmp" "$output/go-cache" "$output/go-tmp"

export GOCACHE="$output/go-cache" GOTMPDIR="$output/go-tmp" TMPDIR="$output/tmp"
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off GONOPROXY=none
export GOAUTH=off GOTELEMETRY=off GOCACHEPROG= SDKROOT="$sdk"
export CGO_ENABLED=1 CGO_CFLAGS=-mmacosx-version-min=12.0 CGO_LDFLAGS=-mmacosx-version-min=12.0
export CC="$(xcrun --sdk macosx --find clang)"
GOOS=$("$go" env GOHOSTOS)
GOARCH=$("$go" env GOHOSTARCH)
export GOOS GOARCH
"$go" version > "$output/toolchain.txt"
xcrun --sdk macosx --show-sdk-version > "$output/sdk-version.txt"
CGO_ENABLED=0 GOFLAGS= "$go" build -p 4 -o "$output/helper" \
    "$cbm_source/scripts/go-package-facts/main.go" "$cbm_source/scripts/go-package-facts/compact.go"
shasum -a 256 "$binary" "$output/helper" "$go" "$witnesses" > "$output/input-hashes.txt"

cd "$magpie"
export GOFLAGS="-mod=readonly -tags=production -p=4"
export CBM_GO_FACTS_CGO=1 CBM_GO_FACTS_HELPER="$output/helper" CBM_GO_COMMAND="$go"
export CBM_GO_FACTS_PROFILE=chunk_index_v2 CBM_WORKERS=4 CBM_MEM_BUDGET_MB=1792
export CBM_CACHE_DIR="$output/cache" CBM_RUNTIME_DIR="$output/runtime"
export CBM_TS_FACTS_HELPER=
project="magpie-darwin-$GOARCH"
"$binary" allow-root --approve-broad "$magpie" > "$output/allow-root.log"
"$python" - "$go" "$binary" "$magpie" "$project" "$output" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

go, cbm, root, project, output = sys.argv[1:]
output = Path(output)
for name, seconds, argv in (
    ("go-list", 240, [go, "list", "-deps", "-e", "-test", "-compiled", "-export",
                      "-json=ImportPath,Name,Dir,Error,DepsErrors,Export,CgoFiles,GoFiles,CompiledGoFiles,ForTest", "./..."]),
    ("index", 300, [cbm, "cli", "index_repository", "--repo-path", root, "--name", project,
                    "--mode", "full", "--json"]),
):
    with (output / (name + ".json")).open("w") as stdout, (output / (name + ".stderr")).open("w") as stderr:
        subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=seconds, check=True)
reply = json.loads((output / "index.json").read_bytes())
assert not reply.get("isError"), reply
data = reply.get("structuredContent") or json.loads(reply["content"][0]["text"])
assert data["project"] == project and data["status"] == "indexed"
PY
db="$output/cache/$project.db"
test -f "$db"
test ! -s "$db-wal"
"$python" "$script_dir/verify-platform-sites.py" darwin "$magpie" "$db" "$witnesses" \
    --packages "$output/go-list.json" > "$output/acceptance.json"
cat "$output/acceptance.json"

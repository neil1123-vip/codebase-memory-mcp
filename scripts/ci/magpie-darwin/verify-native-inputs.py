import hashlib
import json
from collections import Counter
from pathlib import Path
import sys


source, manifest, module_json = map(Path, sys.argv[1:])
data = json.loads(manifest.read_bytes())
module = json.loads(module_json.read_bytes())
expected = data["dependency"]
for found, lock in (("Path", "module_path"), ("Version", "version"),
                    ("Sum", "module_h1"), ("GoModSum", "go_mod_h1")):
    if module[found] != expected[lock]:
        raise ValueError(f"Wails module metadata mismatch: {found}")

digests = {}
for name in ("go.mod", "go.sum"):
    digest = hashlib.sha256((source / name).read_bytes()).hexdigest()
    if digest != expected[name.replace(".", "_")]["sha256"]:
        raise ValueError(f"Go module file mismatch: {name}")
    digests[name] = digest

files = {}
spans = set()
for site in data["sites"]:
    name = site["path"]
    if name not in files:
        files[name] = (source / name).read_bytes()
        digests[name] = hashlib.sha256(files[name]).hexdigest()
    raw = files[name]
    if digests[name] != site["source_sha256"]:
        raise ValueError(f"Witness source mismatch: {name}")
    start, end = site["start_byte"], site["end_byte"]
    callee_start, callee_end = site["callee_start_byte"], site["callee_end_byte"]
    if not 0 <= start <= callee_start < callee_end <= end <= len(raw):
        raise ValueError(f"Witness span outside source: {name}:{site['line']}")
    if raw[callee_start:callee_end].decode() != site["callee"]:
        raise ValueError(f"Callee mismatch: {name}:{site['line']}")
    spans.add((name, start, end))

counts = Counter(site["declaration"] for site in data["sites"])
assert len(data["sites"]) == len(spans) == 60
assert len(files) == 14 and counts == {"InvokeSync": 33, "InvokeSyncWithResult": 15, "New": 12}
print(json.dumps({"scope": "public-checkout", "files": dict(sorted(digests.items())),
                  "confirmed_source_sites": counts}, indent=2))

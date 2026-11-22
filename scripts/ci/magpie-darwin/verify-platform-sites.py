import argparse
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path, PurePosixPath


def selected_go_files(packages, root):
    text = packages.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    selected = set()
    local_packages = 0
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        package, offset = decoder.raw_decode(text, offset)
        directory = PurePosixPath(package.get("Dir", ""))
        if not directory.is_relative_to(root):
            continue
        assert not package.get("Error") and not package.get("DepsErrors"), package["ImportPath"]
        local_packages += 1
        for key in ("GoFiles", "CgoFiles", "CompiledGoFiles"):
            for name in package.get(key, []):
                file = directory / name
                if file.is_relative_to(root) and file.suffix == ".go":
                    selected.add(file.relative_to(root).as_posix())
    assert local_packages and selected, (packages, root)
    return selected


def main():
    args = argparse.ArgumentParser()
    args.add_argument("platform", choices=("darwin", "gtk3", "gtk4"))
    for argument in ("source", "database", "witnesses"):
        args.add_argument(argument, type=Path)
    args.add_argument("--packages", type=Path)
    args.add_argument("--listed-root", type=PurePosixPath)
    opts = args.parse_args()
    darwin = opts.platform == "darwin"
    platform = "darwin" if darwin else "linux"
    tags = "-tags=production,gtk3" if opts.platform == "gtk3" else "-tags=production"
    expected_count = {"darwin": 60, "gtk3": 4, "gtk4": 2}[opts.platform]
    candidates = json.loads(opts.witnesses.read_bytes())["sites"]
    platform_sites = [site for site in candidates if site["platform"] == platform]
    if darwin:
        sites, other = platform_sites, []
    else:
        def selected(site):
            return Path(site["path"]).stem.endswith("_" + opts.platform)
        sites = [site for site in platform_sites if selected(site)]
        other = [site for site in platform_sites if not selected(site)]
    assert len(sites) == expected_count, (opts.platform, len(sites))
    assert len({(site["path"], site["start_byte"], site["end_byte"]) for site in sites}) == expected_count
    selected = None
    if opts.packages:
        listed_root = opts.listed_root or PurePosixPath(opts.source.resolve().as_posix())
        selected = selected_go_files(opts.packages, listed_root)
        assert {site["path"] for site in sites} <= selected
        assert not {site["path"] for site in other} & selected

    def call(db, site):
        return db.execute(
            "select category, target_qn, reason, strategy from call_sites "
            "where rel_path=? and start_byte=? and end_byte=? and not is_reference",
            (site["path"], site["start_byte"], site["end_byte"]),
        ).fetchall()

    with sqlite3.connect(opts.database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True) as db:
        (detail,) = db.execute(
            "select detail from index_coverage where rel_path='.compiler-facts'"
        ).fetchone()
        go = json.loads(detail)["go"]
        build = go["context"]
        env = build["env"]
        assert build["cgo_policy"] == "explicit-native"
        assert env["CGO_ENABLED"] == "1"
        assert env["GOOS"] == env["GOHOSTOS"] == platform
        assert env["GOARCH"] == env["GOHOSTARCH"]
        assert tags in build["build_flags"]
        assert build["patterns"] == ["./..."]
        assert go["status"] in ("complete", "partial") and go["sites"] > 0
        assert db.execute("pragma quick_check").fetchone() == ("ok",)
        assert db.execute(
            "select count(*) from call_sites where target_qn like '%tmp-rebase-%'"
        ).fetchone() == (0,)

        unresolved = []
        confirmed = Counter()
        sources = {}
        for site in sites:
            path = site["path"]
            if path not in sources:
                raw = (opts.source / path).read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                assert db.execute(
                    "select sha256 from file_hashes where rel_path=?", (path,)
                ).fetchone() == (digest,)
                sources[path] = (raw, digest)
            raw, digest = sources[path]
            assert digest == site["source_sha256"]
            assert raw[site["callee_start_byte"]:site["callee_end_byte"]].decode() == site["callee"]
            target = site["import"]["path"] + "." + site["declaration"]
            expected = ("external_dependency", target, "external_symbol_not_indexed", "lsp_compiler_external")
            actual = call(db, site)
            if actual == [expected]:
                confirmed[site["declaration"]] += 1
            else:
                unresolved.append({"file": path, "line": site["line"], "expected": target, "rows": actual})
        for site in other:
            assert all(row[3] != "lsp_compiler_external" for row in call(db, site)), site["path"]
        selection = {}
        if selected is not None:
            unbound_paths = {
                path for (path,) in db.execute(
                    "select distinct rel_path from call_sites "
                    "where category='unresolved' and rel_path glob '*.go'"
                )
                if path in selected
            }
            indexed = {path for (path,) in db.execute(
                "select rel_path from file_hashes where rel_path glob '*.go'"
            )}
            selection = {
                "go_list_selected_files": len(selected),
                "go_list_selected_files_missing_from_graph": sorted(selected - indexed),
                "go_list_selected_files_with_unresolved_calls": sorted(unbound_paths),
            }

    print(json.dumps({
        "platform": opts.platform, "architecture": env["GOARCH"], "toolchain": build["tool_version"],
        "go_status": go["status"], "go_sites": go["sites"], "expected": expected_count,
        "confirmed": dict(confirmed), "unresolved": unresolved, **selection,
    }, indent=2))
    return int(go["status"] != "complete" or bool(unresolved) or
               bool(selection.get("go_list_selected_files_missing_from_graph")) or
               bool(selection.get("go_list_selected_files_with_unresolved_calls")))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""真实 daemon 重启后验证缓存 watcher 会刷新独立项目数据库。"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from test_daemon_smoke import (
    McpClient,
    OPERATION_TIMEOUT,
    RENDEZVOUS_KEY,
    SHUTDOWN_TIMEOUT,
    START_TIMEOUT,
    SmokeFailure,
    assert_indexed_tool_response,
    assert_rpc_success,
    check,
    daemon_lifecycle_sequence,
    json_events,
    lock_status,
    wait_until,
)


def run_git(repository, *args):
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0,
        "git {} failed in {}: {}".format(" ".join(args), repository, result.stderr),
    )


def commit_file(repository, filename, message):
    run_git(repository, "add", filename)
    run_git(
        repository,
        "-c",
        "user.name=CBM watcher test",
        "-c",
        "user.email=watcher-test@example.invalid",
        "commit",
        "-qm",
        message,
    )


def start_client(binary, env, stderr_path, request_base):
    client = McpClient(binary, env, stderr_path)
    params = {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "cbm-watcher-restore", "version": "1"},
    }
    client.send(
        {"jsonrpc": "2.0", "id": request_base, "method": "initialize", "params": params}
    )
    assert_rpc_success(client.wait_response(request_base), "watch restore initialize")
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return client


def daemon_control(binary, env, action):
    result = subprocess.run(
        [str(binary), "daemon", action],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=START_TIMEOUT,
        check=False,
    )
    check(
        result.returncode == 0,
        "daemon {} failed: {}{}".format(action, result.stdout, result.stderr),
    )


def call_tool(client, request_id, name, arguments, timeout=OPERATION_TIMEOUT):
    client.send(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    return client.wait_response(request_id, timeout=timeout)


def wait_for_symbol(client, project, symbol, request_id):
    deadline = time.monotonic() + OPERATION_TIMEOUT * 2
    while time.monotonic() < deadline:
        response = call_tool(
            client,
            request_id,
            "search_graph",
            {"project": project, "name_pattern": "^{}$".format(symbol), "limit": 10},
            timeout=START_TIMEOUT,
        )
        assert_rpc_success(response, "search restored project " + project)
        if symbol in json.dumps(response, ensure_ascii=False):
            return request_id + 1
        request_id += 1
        time.sleep(0.25)
    raise SmokeFailure(
        "restored project {} never indexed {}".format(project, symbol)
    )


def watcher_change_count(daemon_log, project):
    return sum(
        record.get("project") == project
        for record in json_events(daemon_log, "watcher.changed")
    )


def main():
    if os.name == "nt" or sys.platform.startswith(("cygwin", "msys")):
        print("SKIP: real daemon watcher restore smoke requires POSIX sockets")
        return 0

    root = Path(__file__).resolve().parent.parent
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else root / "build/c/codebase-memory-mcp")
    binary = binary.resolve()
    check(binary.is_file() and os.access(binary, os.X_OK), "missing executable: " + str(binary))

    runtime_dir = Path("/private/tmp" if sys.platform == "darwin" else "/tmp") / (
        "cbm-daemon-" + str(os.geteuid())
    )
    socket_path = runtime_dir / ("cbm-" + RENDEZVOUS_KEY + ".sock")
    lifetime_lock = runtime_dir / ("cbm-" + RENDEZVOUS_KEY + ".lifetime.lock")
    if socket_path.exists() or lock_status(lifetime_lock, record_lock=True) == "held":
        if os.environ.get("CBM_DAEMON_SMOKE_REQUIRE_RUN") == "1":
            raise SmokeFailure("watch restore smoke needs an idle account daemon")
        print("SKIP: another CBM daemon is active")
        return 0

    clients = []
    daemon_started = False
    with tempfile.TemporaryDirectory(prefix="cbm-watcher-restore-") as raw_tmpdir:
        tmpdir = Path(raw_tmpdir)
        home = tmpdir / "home"
        cache = tmpdir / "cache"
        parent = tmpdir / "parent"
        child = parent / "child"
        for directory in (home, cache, parent, child):
            directory.mkdir(parents=True, exist_ok=True)

        parent_file = "parent_initial.py"
        child_file = "child_initial.py"
        (parent / parent_file).write_text(
            "def daemon_parent_initial():\n    return 1\n", encoding="utf-8"
        )
        (child / child_file).write_text(
            "def daemon_child_initial():\n    return 1\n", encoding="utf-8"
        )
        run_git(parent, "init", "-q")
        run_git(child, "init", "-q")
        commit_file(parent, parent_file, "initial parent")
        commit_file(child, child_file, "initial child")

        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "CBM_CACHE_DIR": str(cache),
                "CBM_ALLOWED_ROOT": str(tmpdir),
                "CBM_LOG_LEVEL": "info",
                "CBM_LOG_FORMAT": "json",
            }
        )
        daemon_log = cache / "logs/cbm-daemon.log"
        try:
            daemon_control(binary, env, "start")
            daemon_started = True
            wait_until(
                lambda: len(json_events(daemon_log, "daemon.start")) == 1
                and socket_path.exists()
                and lock_status(lifetime_lock, record_lock=True) == "held",
                START_TIMEOUT,
                "generation one permanent daemon startup",
            )

            first = start_client(binary, env, tmpdir / "generation-one.err", 1)
            clients.append(first)
            for request_id, project_name, path in (
                (2, "restore-parent", parent),
                (3, "restore-child", child),
            ):
                response = call_tool(
                    first,
                    request_id,
                    "index_repository",
                    {"repo_path": str(path), "name": project_name, "mode": "fast"},
                )
                assert_indexed_tool_response(response, "initial index " + project_name)
                check((cache / (project_name + ".db")).is_file(),
                      "missing database for " + project_name)

            first.close_input()
            check(first.wait(timeout=15) == 0, "generation one frontend exited nonzero")
            wait_until(
                lambda: socket_path.exists()
                and lock_status(lifetime_lock, record_lock=True) == "held",
                START_TIMEOUT,
                "permanent generation one daemon after MCP disconnect",
            )
            daemon_control(binary, env, "stop")
            wait_until(
                lambda: not socket_path.exists()
                and lock_status(lifetime_lock, record_lock=True) == "free"
                and len(json_events(daemon_log, "daemon.stop")) == 1,
                SHUTDOWN_TIMEOUT,
                "generation one daemon shutdown",
            )
            daemon_started = False

            parent_update = "parent_after_restart.py"
            child_update = "child_after_restart.py"
            (parent / parent_update).write_text(
                "def daemon_parent_after_restart():\n    return 2\n", encoding="utf-8"
            )
            (child / child_update).write_text(
                "def daemon_child_after_restart():\n    return 2\n", encoding="utf-8"
            )
            commit_file(parent, parent_update, "parent commit while daemon is down")
            commit_file(child, child_update, "child commit while daemon is down")

            daemon_control(binary, env, "start")
            daemon_started = True
            wait_until(
                lambda: len(json_events(daemon_log, "daemon.start")) == 2
                and socket_path.exists()
                and lock_status(lifetime_lock, record_lock=True) == "held",
                START_TIMEOUT,
                "generation two permanent daemon startup without MCP sessions",
            )

            second = start_client(binary, env, tmpdir / "generation-two.err", 10)
            clients.append(second)
            response = call_tool(second, 11, "list_projects", {})
            assert_rpc_success(response, "generation two list projects")
            request_id = wait_for_symbol(
                second, "restore-parent", "daemon_parent_after_restart", 12
            )
            wait_for_symbol(second, "restore-child", "daemon_child_after_restart", request_id)
            check((cache / "restore-parent.db").is_file(), "parent cache database disappeared")
            check((cache / "restore-child.db").is_file(), "child cache database disappeared")

            second.close_input()
            check(second.wait(timeout=15) == 0, "generation two frontend exited nonzero")
            wait_until(
                lambda: socket_path.exists()
                and lock_status(lifetime_lock, record_lock=True) == "held",
                START_TIMEOUT,
                "permanent generation two daemon after MCP disconnect",
            )

            parent_idle = "parent_while_idle.py"
            child_idle = "child_while_idle.py"
            (parent / parent_idle).write_text(
                "def daemon_parent_while_idle():\n    return 3\n", encoding="utf-8"
            )
            (child / child_idle).write_text(
                "def daemon_child_while_idle():\n    return 3\n", encoding="utf-8"
            )
            parent_changes = watcher_change_count(daemon_log, "restore-parent")
            child_changes = watcher_change_count(daemon_log, "restore-child")
            commit_file(parent, parent_idle, "parent commit with no MCP sessions")
            commit_file(child, child_idle, "child commit with no MCP sessions")
            wait_until(
                lambda: watcher_change_count(daemon_log, "restore-parent") > parent_changes
                and watcher_change_count(daemon_log, "restore-child") > child_changes,
                OPERATION_TIMEOUT,
                "both project watchers to observe commits with no MCP sessions",
            )

            third = start_client(binary, env, tmpdir / "generation-two-query.err", 20)
            clients.append(third)
            request_id = wait_for_symbol(
                third, "restore-parent", "daemon_parent_while_idle", 21
            )
            wait_for_symbol(third, "restore-child", "daemon_child_while_idle", request_id)

            third.close_input()
            check(third.wait(timeout=15) == 0, "generation two query frontend exited nonzero")
            daemon_control(binary, env, "stop")
            wait_until(
                lambda: not socket_path.exists()
                and lock_status(lifetime_lock, record_lock=True) == "free"
                and len(json_events(daemon_log, "daemon.stop")) == 2,
                SHUTDOWN_TIMEOUT,
                "generation two daemon shutdown",
            )
            daemon_started = False

            check(
                daemon_lifecycle_sequence(daemon_log)[:4]
                == ["daemon.start", "daemon.stop", "daemon.start", "daemon.stop"],
                "watch restore smoke did not complete two clean daemon generations",
            )
        except SmokeFailure:
            if daemon_log.exists():
                print(
                    "watch restore smoke daemon log:\n"
                    + daemon_log.read_text(encoding="utf-8", errors="replace"),
                    file=sys.stderr,
                )
            raise
        finally:
            for client in clients:
                client.cleanup()
            if daemon_started:
                try:
                    subprocess.run(
                        [str(binary), "daemon", "stop"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=env,
                        timeout=SHUTDOWN_TIMEOUT,
                        check=False,
                    )
                    wait_until(
                        lambda: not socket_path.exists()
                        and lock_status(lifetime_lock, record_lock=True) == "free",
                        SHUTDOWN_TIMEOUT,
                        "best-effort permanent daemon shutdown",
                    )
                except (OSError, subprocess.TimeoutExpired, SmokeFailure):
                    pass

    print(
        "PASS: restored parent and child watchers refreshed across restart "
        "and with no MCP sessions"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SmokeFailure, subprocess.TimeoutExpired, ValueError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(1)

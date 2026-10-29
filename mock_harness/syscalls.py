"""Thin syscall layer for the mock harness originators.

Every OS effect the originators produce goes through this module (no other
module in the package touches os/socket for effects), for two reasons:

  - the path manifest's kernel-signature claims map 1:1 onto auditable
    code (each wrapper below names the syscall it wraps), and
  - unit tests substitute this module wholesale — no real network, no
    real child processes in the test suite.

The layer is deliberately dumb: it has no knowledge of actions, classes,
designs, or policy. It reports what it did (fd/flag/pid facts the action
records need); it never decides anything.
"""

from __future__ import annotations

import os
import socket
import urllib.request

HTTP_TIMEOUT_S = 10.0
SOCKET_TIMEOUT_S = 10.0

# Per-fd partial-line buffers for read_line (a pipe read can split a line).
_fd_buffers: dict[int, bytes] = {}


# --- sockets (direct_network: raw TCP/UDP to the net-peer target) -----------

def tcp_socket():
    """socket(AF_INET, SOCK_STREAM) — the raw connect channel."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT_S)
    return s


def udp_socket():
    """socket(AF_INET, SOCK_DGRAM) — the raw datagram channel."""
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def connect(sock, host: str, port: int) -> None:
    sock.connect((host, int(port)))


def sendall(sock, data: bytes) -> None:
    sock.sendall(data)


def recv(sock) -> bytes:
    return sock.recv(65536)


def sendto(sock, data: bytes, host: str, port: int) -> None:
    sock.sendto(data, (host, int(port)))


def close_socket(sock) -> None:
    sock.close()


# --- http (http_tool_call twins: raw fetch / gateway JSON-RPC POST) ----------

def http_request(method: str, url: str, body: str | None = None) -> tuple[int, bytes]:
    """One plain HTTP request; returns (status, response body bytes).

    The raw-route twin's kernel signature is one connect per request (no
    pooling; see manifest notes on the client fidelity limitation).
    Non-2xx raises (urllib HTTPError) — the originator records it.
    """
    req = urllib.request.Request(
        url, data=body.encode("utf-8") if body is not None else None,
        method=method)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
        return resp.status, resp.read()


# --- child processes (spawn variants + the MCP stdio twin session) -----------

def pipe() -> tuple[int, int]:
    """os.pipe() -> (read_fd, write_fd)."""
    return os.pipe()


def fork() -> int:
    """os.fork(): 0 in the child, the child pid in the parent."""
    return os.fork()


def setsid() -> None:
    """os.setsid(): new session, detaching the child from the terminal
    process group (the daemonize step of the daemon variant)."""
    os.setsid()


def execv(path: str, argv: list[str]) -> None:
    """os.execv(path, argv): replace the child process image (execve(2)).

    Never returns on success; the caller must _exit on return.
    """
    os.execv(path, list(argv))


def exit_child(code: int) -> None:
    """Immediate child-process exit (exec failed / child cleanup)."""
    os._exit(code)


def dup2(old_fd: int, new_fd: int) -> None:
    os.dup2(old_fd, new_fd)


def close_fd(fd: int) -> None:
    # Drop any buffered partial line for this fd so a recycled fd number
    # cannot inherit a stale buffer.
    _fd_buffers.pop(fd, None)
    os.close(fd)


def write_fd(fd: int, data: bytes) -> int:
    return os.write(fd, data)


def read_fd(fd: int) -> bytes:
    return os.read(fd, 65536)


def read_line(fd: int) -> bytes | None:
    """Read one newline-terminated line from a pipe fd (None at EOF)."""
    buf = _fd_buffers.get(fd, b"")
    while b"\n" not in buf:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        buf += chunk
    line, sep, rest = buf.partition(b"\n")
    _fd_buffers[fd] = rest
    if not sep and not line:
        return None
    return line


def read_all(fd: int) -> bytes:
    """Drain a pipe fd to EOF (the captured child stdout)."""
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def open_devnull_rw() -> int:
    """fd for /dev/null opened read/write (daemon worker stdio: reads
    return EOF, writes are discarded)."""
    return os.open(os.devnull, os.O_RDWR)


def waitpid(pid: int) -> tuple[int, int]:
    """os.waitpid(pid, 0): block until the direct child exits."""
    return os.waitpid(pid, 0)


def exit_code(status: int) -> int:
    """waitpid status -> exit code (negative for signals)."""
    return os.waitstatus_to_exitcode(status)


def child_exit_state(pid: int) -> tuple[str, int | None]:
    """(state, exit_code): 'exited' (reaped), 'running', or 'foreign' when
    the pid is not our child anymore (daemon workers are reparented)."""
    try:
        got, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return ("foreign", None)
    if got == 0:
        return ("running", None)
    return ("exited", os.waitstatus_to_exitcode(status))


def alive(pid: int) -> bool:
    """Best-effort existence probe for pids we cannot waitpid (kill(pid, 0))."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


# --- files (file_write / credential_access) ---------------------------------

def mkdir_p(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_file(path: str, data: bytes, append: bool = False) -> dict:
    """Direct write from this process (open(2) with explicit flags — the
    kernel-observable security_file_open signature).

    write  -> O_WRONLY|O_CREAT|O_TRUNC   (node fs.writeFile shape)
    append -> O_WRONLY|O_CREAT|O_APPEND  (node fs.appendFile shape)
    """
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return {
        "path": path,
        "flags": "O_WRONLY|O_CREAT|" + ("O_APPEND" if append else "O_TRUNC"),
        "bytes": len(data),
    }


def read_file(path: str) -> bytes:
    """Direct read from this process (O_RDONLY open — the credential_access
    kernel signature; content never enters the record beyond a byte count)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)

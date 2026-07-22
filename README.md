# execguard

execguard is an eBPF-based process guard for Linux that watches a target
process (and everything it forks) and reports (or blocks) any subsequent
`execve` attempts made by that process tree.

It attaches an LSM program to `bprm_check_security` so it can observe every exec at the kernel's own
enforcement point, and uses `sched_process_fork` / `sched_process_exit`
tracepoints to keep the set of tracked PIDs in sync as the process tree
grows and shrinks.

This is aimed at a scenario like a web app or service that should never
spawn a shell or an arbitrary binary: run it under execguard in monitor
mode to see what it actually execs, then flip on `--enforce` to have the
kernel deny anything the process tries to run.

## Threat Model

Execguard blocks a common post-exploitation pattern: after achieving code execution in the Python app, an attacker spawns a child process (shell, curl | sh, nc) to escalate from app level execution to OS command execution. execguard denies or logs any execve() from the target process or its descendants, independent of how the attacker got initial code execution.

A correctly scoped web app rarely execs at runtime, so false positives are near zero and every logged match is worth investigating.

## Architecture

execguard is split into a small eBPF program (`bpf/src/guard.bpf.c`) loaded
into the kernel, and a Go userspace component (`cmd/`, `pkg/bpf/`) that
loads/attaches the program, seeds the tracked-PID map, and streams exec
events out of a ring buffer. Full design details, including the map layout
and the tracking/enforcement flow, live under [`docs/design.md`](docs/design.md).

## Kernel Requirements

execguard relies on BPF LSM support, so it needs:

- Linux kernel 5.7+ (BPF LSM support), built with `CONFIG_BPF_LSM=y` and
  `CONFIG_DEBUG_INFO_BTF=y`.
- `bpf` must be enabled in the LSM stack, e.g. via the boot parameter:
  ```
  lsm=lockdown,capability,yama,apparmor,bpf
  ```
  Check the currently active LSMs with:
  ```
  cat /sys/kernel/security/lsm
  ```
- Root privileges (`CAP_BPF`/`CAP_SYS_ADMIN`) to load and attach the
  program.

## Build

Requirements: Go 1.25+, `clang`/LLVM with BPF target support, and kernel
headers providing `vmlinux.h` (already vendored under `bpf/include/`).

```
make build
```

This runs `go generate` (via `bpf2go`) to compile `bpf/src/guard.bpf.c` and
embed the generated eBPF object/skeleton into `pkg/bpf/`, then builds the
`execguard` binary into `bin/`.

Other useful targets:

```
make bpf      # compile only the eBPF C source, for quick iteration
make fmt      # format Go and C sources
make clean    # remove build output and generated eBPF files
```

## Usage

execguard must run as root, since loading BPF programs and attaching LSM
hooks requires elevated privileges.

```
sudo bin/execguard --target-pid <pid> [--enforce]
```

- `--target-pid`: PID of the process to guard. execguard backfills the
  existing process tree under this PID so already-running children are
  tracked too, and new children are tracked automatically as they fork.
- `--enforce`: when set, tracked processes have their `execve` calls
  denied (`-EPERM`) instead of just observed. Omit it to run in
  monitor-only mode.

Each exec attempt by a tracked process is printed as it happens:

```
[ALLOW] pid=1234   ppid=1      comm=python3          path=/usr/bin/id
[DENY ] pid=1234   ppid=1      comm=python3          path=/bin/sh
```

Stop execguard with Ctrl-C (SIGINT) or SIGTERM.

## Demo

`demo/` contains a small Flask app with a `/run-id` endpoint that shells
out to `id` via `subprocess.run`:

```
cd demo
pip install -r requirements.txt
gunicorn -w 4 -b 127.0.0.1:8000 demo:app
```

With the Flask dev server running, find its PID and start execguard
against it in another terminal:

```
sudo bin/execguard --target-pid <app-pid> --enforce
```

Then hit the endpoint:

```
curl http://127.0.0.1:5000/run-id
```

In monitor mode you'll see the `id` exec logged as `ALLOW`. In enforce
mode execguard denies it at the kernel level, the `subprocess.run` call
raises, and the endpoint responds with a 403.

## Limitations and Future Improvements

**Startup race window**: Between the loader starting and hooks attaching, a fork by the target is unobservable by any userspace-triggered mechanism. Backfill (attach-then-walk /proc) closes the race for the /proc walk itself, but not this earlier window. Not solved.

**Blind spots**: In-process network activity and file-based persistence cross no fork/exec boundary and are invisible to this control.

**PID-tree tracking and cgroup-based identity**: Tree propagation via `sched_process_fork` is a workaround for non-containerized deployments.

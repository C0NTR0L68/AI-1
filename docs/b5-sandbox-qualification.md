# Full B5 Windows Sandbox qualification — 2026-11-22

A fresh Windows Sandbox was started with networking, vGPU, clipboard and
device redirection disabled, no mapped folders and 2,560 MB of RAM.
The first attempt to run as the signed-in guest returned 0x80070520.
A standard Windows Sandbox connect established the login and the retry succeeded.

The compound guest probe returned exit 42. The guest was not SYSTEM, could
not see the host-side synthetic marker or redirected C:/D:, reported no active
non-loopback interfaces, completed a loopback TCP exchange and ran a fixed
System32 cmd child with the expected exit status. Both sockets and the listener
were closed. Clipboard was disabled by configuration. This probe does not
qualify CPython's internal socketpair or either frozen child runtime.

The exact 52,434,404-byte offline bundle SHA-256 was rechecked:
`569FD484C31746A0A3A2DA0D133C2EEB8D426C607E71888F2CE113A43F69D8E7`.
The existing B5 harness itself was executed as a readiness check and returned
code 2 with `B5_EXECUTION_REQUIRES_SEPARATE_REVIEW_AND_PERMISSION`.
Its guard still rejects every Python socket event and subprocess launch.
Readiness at the OS level does not qualify reviewed per-test admission.
The original frozen suite also retains its preflight requirements for the
legacy schema, failure-injection trigger and canonical alias cases.

**Full B5: BLOCKED. Original Python/Node execution: NOT_RUN.**
No bundle transfer was started in this guest and no original tests were
imported or collected. The guest created for this check was stopped and
its removal was confirmed through the Windows Sandbox list. The next gate is
execution-enabled admission scoped to the exact asyncio private operation and
the exact frozen child programs and arguments, with immutable test and
release pins and a per-case evidence channel. No change to the host or to
any user archive or database was needed.

## Narrow admission policy

`b5_admission.py` defines a thread-scoped audit adapter. Its one-use child
plan requires the exact pinned Python or Node executable in the archive's
staging layout, the exact Windows command line, canonical test-owned paths,
a fixed working directory and a new allowlisted environment. The original
Python command strings are pinned by SHA-256. Recovery modes, synthetic
database names and gate files have separate exact checks. Node admits only
the original test script and flags. The fallback guard still handles every
event outside that scope.

For asyncio, the policy admits only the construction sequence for the
pinned CPython 3.12 Windows IPv4 self-pipe: three owned stream sockets,
one ephemeral loopback bind and one connect to the listener's actual port.
It checks peer identities and listener closure after construction. It does
not authorize DNS or general loopback connections.

The five actual frozen child plan inputs matched without launching them.
The policy tests use synthetic socket evidence and executable fixtures.
Nothing installs the hook on the host or replaces the original B5 guard.
Guest-only integration still needs a trusted self-pipe call site and cleanup
on partial construction, checked runtime custody through CreateProcess,
bounded process-tree custody and per-test evidence. The immutable full
launcher remains disabled. Original Python/Node tests remain NOT_RUN.

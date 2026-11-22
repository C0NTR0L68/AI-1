# Full B5 Windows Sandbox qualification — 2026-11-22

## Earlier qualification attempt

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

## Guest worker candidate

The new guest entrypoint verifies the original archive and its member hashes,
expands the pinned wheels offline, and checks the original 195-function
inventory. Its preflight exercises the scoped asyncio self-pipe and one
exact pinned Python child. The suite entry requires that preflight result
and captures pytest phase outcomes. Existing frozen files and assertions
are unchanged. The host entrypoint passes inputs through a single qualified
Sandbox session and refuses an incomplete archive.

The supervisor creates the worker suspended with a reduced environment and
no inherited handles, assigns it to a private Job, verifies membership and
resumes. It checks for an empty Job and rejects a nominally successful run
that left processes running. The Job excludes breakaway and is configured
for termination on close. The worker additionally checks its Job limits,
uses finite socket timeouts and only installs the scoped audit adapter while
it owns execution. The guest OS boundary is still required.

Synthetic regressions cover staging, admission, cleanup after partial socket
creation, the fixed child wrapper, suspend-before-assignment, and timeout
cleanup. A separate native guest probe ran a suspended System32 canary,
observed its expected exit and reached an empty Job on retry. Its stricter
total-process count differed from one, so that probe did not fully pass.
Neither the synthetic regressions nor the system canary qualify the frozen
Python and Node launch path.

## Actual frozen Full B5 execution

The no-network, no-shares guest received all 2,384 blocks through the
Windows Sandbox CLI and verified the complete pinned archive SHA-256.
Online services and the host filesystem were unavailable to the tests.
Archive extraction used the in-box .NET ZIP reader after the first
PowerShell archive command failed. The original archive was unchanged.

The real guest preflight reproduced a CPython Windows detail: the accepted
socket descriptor is wrapped without another socket creation audit event.
The worker now adopts only a socket returned by the owned listener and
checks its descriptor uniqueness and both peer addresses. The following
guest preflight passed real asyncio, the out-of-scope socket denial, the
pinned Python child and Job cleanup.

The first real run executed 603 items from all 195 frozen Python functions:
600 passed and 3 failed. The original Node UI subprocess test passed.
The runtime-lock fixture's exact synthetic unused/../identity.sqlite3
alias was refused by the adapter, before the underlying lock could be
tested. The correction permits only this fixture's path while the named
case runs, still refuses it in the SQLite-connect audit, and passes the
original alias unchanged to the runtime lock for native canonicalization.

The repeated original suite ran **603 items, 601 passed, 2 failed,
0 skipped**, pytest exit 1. The runtime-lock alias and original Node UI
test both passed. The remaining failed calls were:

- `test_complete_turn_sqlite_failure_becomes_unknown_without_assistant`.
  The fixture installs its write-failure trigger before startup, while the
  frozen schema gate rejects extra schema objects before turn execution.
- `test_legacy_assistant_model_name_survives_provenance_migration_and_api`.
  The API fixture expects the legacy database to be served, while its
  resulting schema is outside the frozen preflight allowlist.

The two outcomes above are frozen test and release contract conflicts.
An approved follow-up baseline is needed to reconcile them. The old files,
assertions, preflight checks, and the offline archive were preserved.
**Full B5 executed and failed.** Synthetic worker/C7 regression run:
71 passed, 1 Windows symlink skip. Memory V2 remains disabled. The
production trusted head and archive binding are still unqualified.

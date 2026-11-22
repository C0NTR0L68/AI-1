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

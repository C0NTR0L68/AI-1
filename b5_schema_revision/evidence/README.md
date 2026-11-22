# Windows qualification · 2026-11-22

The immutable control remains **601 PASS / 2 FAIL / 603**. The approved
candidate retains 601 expanded control IDs and replaces two scenarios with
eight expanded cases. Both collections were checked against the frozen lock.
The archive was reproduced byte for byte. The production schema preflight,
the seven unaffected Python test files and the Node test file are unchanged.

## Full B5 · PASS

The final guest preflight and full suite ran inside a disposable Windows Sandbox
with networking, redirected folders and clipboard disabled. The verified
offline archive went through the Windows Sandbox command channel. The Python
collection was exactly 609 cases across 198 functions. All 1,827 setup, call and
teardown phases passed, including the eight schema cases. The pinned Node
runner reported 22 pass, zero fail, zero cancelled, zero skipped and zero
todo. The policy reported zero unexpected denials. Sandbox cleanup is recorded.

The first attempt returned 75 despite all 609 Python calls passing. Its
unchanged log records missing Node counters and 192 denied links. The guest
denial counters identify all 192 as link creation. The pinned pytest source
shows its allocator attempts a best-effort current-directory link. The retry
omitted only that shortcut within the run's own numbered scratch directory,
and collected the pinned Node 24 reporter's complete counters. The audit
policy, original Node argv, fixtures, test assertions and archive were
unchanged. The support regressions passed 18/18.

## C7-v1 · BLOCKED for release

The separate Windows synthetic run passed 57 cases with one skip. It exercised
the authoritative head transaction, stale or wrong-generation archive
rejection, native hardlinks and junctions, private archive ACLs and file
replacement checks. The native symlink case could not create its temporary
link in this environment. The code review found no production instantiation
of the trusted head connection factory or the private archive backend. The
next acceptance must qualify their binding, local NTFS namespace and restricted
ACL with synthetic deployment data, and exercise native symlink rejection.

Memory V2 is OFF. No release or activation took place.

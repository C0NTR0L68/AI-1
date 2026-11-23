# Standard Windows client qualification · 2026-11-23

## Process admission

A new disposable Sandbox ran with no networking, mapped folders or
clipboard. A temporary local standard account was created inside the
guest. The successful pilot used the explicit local computer name and
`CreateProcessWithLogonW` from the existing interactive guest session.
Before resuming the new process the fixture checked its actual token:
SID matched the account, integrity was RID 8192, and elevation was zero.
The process ran and returned 42. The account was absent after cleanup.

The first pilot verified the logon token but did not produce a process
receipt. A separate SYSTEM-launched SCM attempt also stopped before it
had a client process. These results do not identify the cause of earlier
Win32 1326. The final SCM fixtures use the proven interactive path and
repeat the suspended-process token check for each client invocation.
The temporary credential stays in the guest launcher process's memory.

## SCM read-only IPC

The preserved high profile denied access to a verified medium client
with Win32 5. Independent native negative operations under that ordinary
token confirmed SCM and NTFS protection. The high profile remains the
application's default.

The separate candidate medium profile requires explicit authority
enrollment. The exact principal DACL, read/write-data rights without
pipe instance creation, protected owner, first-instance guard, remote
rejection and no-write-up policy remain in force. The medium label
admits the enrolled medium process for the existing read-only protocol.
The mutation opcode and local CAS call both remain refused.
[Windows Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)

The last run across 17 guest checkpoints passed on
`55f003f7aa5276f544daa03598151b36bc654325`:

- Start a real restricted SCM service and confirm the read through the
  pipe under a different, attested standard Windows identity.
- Reject an unenrolled principal and a counterfeit same-name endpoint
  created by the ordinary user. The counterfeit case confirms the
  expected owner check runs before the service receives a read request.
- Drop an authorized response in flight. The failed read returned no
  head. An explicit subsequent read worked without elevating the app.
- Deny mutation rights on the SCM entry and attempted file changes to
  the synthetic head, real rollback journal, archive, enrollment and
  runtime image. Deny rename of the relevant protected directories.
- Stop, restart, crash with a real rollback journal, restart again and
  confirm the original head and the database/archive SHA-256.

An earlier medium run passed the IPC scenarios and stopped at a runner
race: the reader noticed the receipt while it was being written. The
final run publishes each receipt using an exclusive temporary file, flush
and same-directory rename. Its receipt and the earlier failure are
both kept. The bridge, guest SCM service and local account were removed
or closed, and the owning Sandbox was stopped.

## Review scope and next gate

Compared exact application diffs and native receipts. The only app
change adds the explicit integrity-profile choice and leaves high as
the default. Existing read-only authentication guards and the pinned
B5 suite are unchanged. The earlier Full B5 and C7-v1 results were not
rerun.

The medium test used the real read-only authority IPC and a protected
synthetic NTFS archive canary. Qualification of the production SCM
identity, actual NTFS paths, a complete activation with DPAPI-owned
archives, and any write-capable CAS remain separate. No FastAPI
elevation or host deployment took place. Memory V2 remains OFF.
Production remains NO-GO.

[Native receipts and SHA-256 manifest](standard-client-evidence).

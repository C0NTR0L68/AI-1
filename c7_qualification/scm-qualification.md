# Disposable SCM qualification

This fixture runs only inside an attested disposable Windows Sandbox guest
with training data. It creates one demand-start service and one standard
local client, then deletes the guest registrations and discards the guest.
The host is not a test target. The compiled service is a test wrapper, not
an installer or a production SCM entry point.

The guest transfers hash-checked sources and the frozen runtime into a
SYSTEM-owned local directory before compiling or executing them. The SCM
registers a quoted absolute executable path and a dedicated virtual account.
The service requires a restricted service SID. The worker checks the actual
token user and that the enrolled SID appears on its restricting SID list.
The desktop client verifies its exact enrolled SID, medium integrity and
non-elevated token before attempting Windows IPC or storage operations.
The client credential is temporary and generated inside the guest.

The production read-only wire implementation from `995717f` has a high
mandatory integrity label with no-write-up. A medium caller's access
denial is a compatibility failure for the requested default user profile.
Keep this failure distinct from confirmation that the access boundary
enforced its policy. The production app is not elevated to bridge it.

If the medium connection is unavailable, the next candidate needs a
separately reviewed medium-integrity IPC profile while retaining the exact
peer SID, verified owner on the connected handle, narrow DACL without pipe
instance creation rights, local-only scope and a read-only opcode. Test
low-integrity refusal, wrong accounts, counterfeit endpoints, abrupt I/O
loss and graceful shutdown under the selected profile. The current
qualified high profile and immutable historic evidence stay separate.
[Windows Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control) ·
[Named pipe permissions](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

The service-controlled archive fixture tests NTFS permission denial and
parent replacement when a qualifying client process is available. It is a
small synthetic archive canary, not a DPAPI
encrypted Memory V2 deployment. A service-controlled archive namespace and
interactive CurrentUser keys still require an agreed ownership design.
Full B5, the prior C7 Sandbox run and prior hot-journal tests are not part
of this attempt. IPC CAS and Memory V2 remain OFF.

## Observed results

The final service lifecycle run tested `6b3f2d8744462c8c77a11d2a73432b99fd4ef244`.
The host supplied verified sources and the previously pinned runtime.
The real guest SCM registered a demand-start virtual account, confirmed
restricted SID type and the quoted image path, and reached Running.
The worker verified the actual token user and restricting SID list
before creating the named pipe. Normal stop drained the worker.
Restart produced a different PID. A controlled worker crash left a real
rollback journal. SCM restarted the service, the registry retained its
trusted head, and the final database and archive matched their baseline
SHA-256. The guest service and account were removed.

An independent read-only descriptor check examined six actual synthetic
NTFS objects. It verified SYSTEM ownership, the protected parent DACLs,
the expected inherited file ACLs, no reparse points in those objects, and
no client mutation grants in the checked DACLs.

The ordinary client gate remains **BLOCKED**. The initial credential
launcher could not supply a reliable process receipt. An explicit handle
attempt observed `0xC0000142` before the Python canary ran. The guest
Task Scheduler refused S4U task registration with Win32 5. The final
native `LogonUserW` path returned Win32 1326 before creating a client
process. The evidence shows those errors and does not determine the cause
of the guest logon rejection. They are not denials by the authority's
named pipe. New cross-account pipe authentication, an in-flight IPC
disconnect, and effective ACL negative tests under the ordinary client
token are **NOT_RUN** on this service deployment.

Earlier runs also exposed `sc.exe` argument error 1639 and a
noncanonical scratch ACL. Native SCM registration replaced the command
argument path. A newly created client scratch directory replaced the
attempt to modify the guest parcel's inherited ACL. Historical run
receipts remain unchanged.

The next useful native gate needs an isolated Windows guest with a
prequalified ordinary interactive account and a tested launch path. Capture
the real token before starting the protocol. Keep the service identity
restricted and the service's runtime/authority state outside the client
writable hierarchy. A separately reviewed medium-integrity read-only
profile is needed if the pinned high-integrity profile rejects the verified
medium client. Do not change the host to establish this qualification.

[Native receipts and exact source SHA-256](scm-evidence).

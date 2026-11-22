# C7-v1 Windows IPC qualification

The dormant factory can read the authoritative head over a local Windows
named pipe from a separately authenticated account. The client checks the
owner of the opened kernel pipe handle before sending anything. The server
admits the enrolled client's Windows SID using a protected DACL and checks
the connecting thread token after receiving the requested opcode. It then
reverts to the authority identity before opening SQLite. The pipe rejects
remote clients and requires the first instance. Client rights omit the
named-pipe instance creation right. The wire has fixed-size frames, finite
overlapped I/O and a single read opcode. Acknowledgement lets the service
close the pipe without losing the last frame. A missing, different-owner or
disconnected authority cannot provide a head.

Current wire access is read-only. There is no remote CAS and no HTTP memory
route. A trusted synthetic administrator advances the head out of band to
demonstrate restart onto a newly authenticated archive. The server refuses a
head outside its enrolled generation. The normal LOCAL CLI has no way to
enable the memory factory by itself.

The tested access policy is for an explicitly enrolled **high-integrity**
guest login and SYSTEM as authority. It is an account boundary, not a claim
about attestation of arbitrary processes running under either identity. The
test launcher stores the pre-enrolled archive identities in a SYSTEM-owned
location and grants the app's profile read access only to that enrollment.
It launches the privilege-bearing runtime from a separate fixed-DACL
directory. No Windows service, host ACL, external listener or production
location was provisioned. Service-account deployment, its binary and
configuration ACL, the actual intended client token and cancellation under
load remain deployment qualifications. A full-system rollback and privileged
administrator compromise are outside C7-v1's accepted threat model.

## Review and regression scope

The initial native attempts stopped at Windows access denied. The final
candidate uses explicit Windows file-generic read access and only
`FILE_WRITE_DATA` for writing protocol bytes. This preserves the SID check
and leaves out `FILE_APPEND_DATA`, which is also
`FILE_CREATE_PIPE_INSTANCE`. The diagnostic attempts and final exact
source receipts are separate. See Microsoft's
[Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
and [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).

The normal app and the archived B5 sources are unchanged from `c3a6af3`.
The focused LOCAL launcher and lifespan regression still covers default-off
behavior and runtime cleanup. The integrated Windows run covers the same
launcher and FastAPI lifespan through a real named pipe and pre-enrolled
NTFS archive. It uses an in-process ASGI client and never binds an HTTP
listener. Full B5 remains PASS at its approved previous revision. For a
future write-capable protocol or new deployment token, repeat the native
IPC matrix and add role-scoped CAS, replay, cancellation and service
restart under the approved account.

## Results · 2026-11-22

| Check | Observed result |
| --- | --- |
| Normal LOCAL lifespan with a real SYSTEM authority | PASS. Startup reads the authenticated archive and the HTTP memory namespace remains absent. |
| Authorization | PASS. The server rejects a wrong client SID and a write opcode. The client rejects a real same-name endpoint with an unexpected owner. |
| Missing authority and disconnect in flight | PASS. Each startup fails before creating its workspace, clears the storage binding and returns no head. |
| Restart and archive identity | PASS. The authority restarts with revision one, the app admits the new matching archive, and rejects a replacement directory with the same name and ACL by its pinned identity. |
| Ordinary-user file operations and rollback | PASS. Replacement, deletion and write attempts on the head, actual rollback journal and enrollment fail. The privileged verifier checks all three hashes and confirms revision one. |
| Cleanup | PASS. All four authority launch scopes exited with their expected code. The owning Sandbox was stopped and was absent from the session list. |

The final run verified 34 phase receipts on `6d56d6f` and three focused
launcher/lifespan pytest cases on the same immutable base runtime.
Independent source review checked the real account identities at both
ends, the scoped protocol, OS access masks, finite operation bounds and
the separation between prior and final results. The earlier diagnostic
rapid-close attempt returned Win32 996, which is retained separately.
The final candidate also handles a peer disappearing before connection
admission, and its positive and negative restart paths passed. Adversarial
load and repeated low-level cancellation stress were not part of this run.

The C7-v1 synthetic integration gate is PASS for the stated read-only
authority and test principals. Host production deployment was not
qualified. Memory V2 remains OFF and production remains NO-GO.

[Native receipts, provenance and SHA-256](ipc-evidence).

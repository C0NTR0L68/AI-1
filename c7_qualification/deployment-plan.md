# Memory V2 read-only deployment gate

## Current production facts

GitHub main is `bf8877b`. The last qualified C7 review tip before this
work was `4058744`. The historical Full B5 result belongs to `d57fe91`.
The primary local checkout has existing unstaged and untracked changes.
This work uses the separate review checkout.

Drive D is visible as a ready fixed NTFS volume. No directory on it was
opened to determine its owner, ACL, reparse status or file identity. The
proposed SCM name `AI1MemoryAuthority` did not resolve in the limited
read-only service lookup. This does not inventory other services. The
managed execution token reports integrity RID 4096. The production LOCAL
launcher's actual account SID, token groups and integrity are unknown.
The qualified IPC uses a high-integrity client. The release gate requires
qualification using the real intended token. Running FastAPI elevated is
not the deployment plan.

## Proposed authority

Use a dedicated non-interactive service identity instead of SYSTEM or the
interactive user's identity. Evaluate an SCM virtual account tied to a
single service and a restricted service SID. Verify the actual token user,
enabled and restricting SIDs, integrity level, privileges and named pipe
owner under the chosen configuration. A service SID in a token and the
token's user SID are different facts. Establish which is the effective
pipe owner and which principal receives each access grant. Verify this on
the candidate account before fixing installer details.

The SCM entry uses an explicit quoted absolute path to a pinned runtime
and entry point. It has a fixed working directory, restricted environment,
no model or cloud access, and no user-profile config discovery. Pin the
runtime, DLLs, Python sources, enrollment and their directory identities.
Check the SCM service DACL and actual client token for denial of service
change, start/stop, delete, write-DACL and write-owner operations. Give the
service access only to its own installation and state. Check access through
all parents, including rename and delete-child. Avoid giving the desktop
client generic write to the pipe and retain exact local peer authentication.
Check the client's intended Windows token against the current high-integrity
IPC requirement. If the ordinary launch token cannot connect, qualify a
separately reviewed profile for it instead of requiring elevation.
[Service SID configuration](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info) ·
[SCM permissions](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ·
[Named pipe permissions](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

Keep the live head and its rollback journal on a distinct service-owned
local NTFS root outside the app's writable and restorable trees. Separate
read-only runtime bits from mutable authority state. The candidate archive
root is `D:\AI-1\data\memory\archives-v2`, subject to independent enrollment
and a path-specific review. Verify fixed NTFS, real volume GUID, every
ancestor identity, the leaf DACL and owner, reparse points, hardlinks and
same-name replacement. Bind archives to the authenticated authority's
current generation and digest. The snapshot comparison in
`deployment_gate.py` expects canonical volume UUID and 16-byte file IDs in
`volume-uuid:file-id-hex` notation. Behavioural observations carry the
SHA-256 of separately reviewed evidence. The evaluator reads no real state
and its maximum outcome is readiness for review.

## Lifecycle and recovery

Provision an empty authority explicitly in a synthetic or approved
deployment step. Normal startup opens the enrolled registry in `mode=rw`
without creating it, checks SQLite schema and lets SQLite recover its
rollback journal under the service identity. It checks the live generation
and held archive identity before exposing readiness. Missing authority,
identity mismatch, unreadable or corrupt registry and an unconfirmed recovery
block the memory binding. Never clear a journal by hand or recreate a missing
head from an archive. Restore of a client archive never imports the authority
head. Authority recovery needs an independently trusted head; uncertainty or
rollback of both roots is a separate recovery decision.
[SQLite rollback journal and crash recovery](https://sqlite.org/atomiccommit.html)

On stop, stop accepting requests, drain accepted work to its deadline,
cancel and reap remaining IPC operations, close SQLite handles, then confirm
the authority process is gone. Report interrupted writes as unconfirmed.
Retry a read only within its approved budget. Roll back binaries and config
in a separate stopped-state procedure, preserving the current generation
and head. If an older binary cannot admit the current schema or enrollment,
hold OFF. Uninstall should deregister only the approved service, retain state
by default, and require separate authorization before data removal.

## Release evidence still required

- Native test of the dedicated SCM account, actual client token, installer
  and service ACL, DLL and configuration provenance.
- Enrollment of the selected host paths, native file/sidecar inspection and
  proof that the client cannot replace the head, journal, config or parents.
- Start, restart and stop through SCM with timeout and interruption
  receipts, recovery on approved synthetic state, then an owner review.
- Separate consent for any changes to host service, account, ACL or data.
  Memory V2 remains OFF throughout this read-only preparation.

## Synthetic qualification · 2026-11-23

Three targeted checks passed in a new offline Windows Sandbox with no mapped
folders or clipboard. The guest ran exact, digest-verified Git blobs and the
previously pinned Python runtime. No host accounts, services, ACLs or folders
were changed.

1. The offline gate rejected missing evidence, a mismatched token, shared
   principals and overlapping storage roots. Complete synthetic evidence
   permitted review while preserving production NO-GO.
2. A child exited in an uncommitted transaction after forcing SQLite cache
   spill. The parent observed a hot rollback journal and changed main-file
   bytes. Recovery restored the original bytes and head. A second child
   committed and exited without returning a receipt. The parent read the
   exact committed revision and a stale CAS was refused.
3. Sixteen native cycles cancelled a pending pipe accept and a pending read,
   then verified successful reuse and closure of both Windows handles.
   This covers the qualified overlapped helper in a bounded loopback-free
   fixture. Native service-control shutdown and adversarial multi-process
   load were outside this test.

The separate test processes and Sandbox exited. The prior full B5 and
C7-v1 runs were not repeated. The IPC and application code are unchanged
from `4058744`. Review confirmed that native test evidence does not qualify
the selected production SCM account, actual client token or host path.

[Run receipts, host observations and SHA-256](deployment-evidence).

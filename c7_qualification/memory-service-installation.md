# Proposed Windows 11 installation and rollback

Scope is a fresh store. Memory V2 stays OFF. The review fixture never runs an
installer or modifies the real Windows service database, ACLs, profiles, D:
or the desktop workspace. There is no command-line or environment switch for
the synthetic HTTP binding.

## Install and preflight, after explicit owner authorization

1. Approve the exact reviewed release manifest, the service name
   `AI1MemoryAuthority`, its restricted Windows service SID/profile and the
   separately enrolled read and write client SIDs. Resolve those SIDs with
   SCM/Windows and compare them with actual process tokens. The ordinary
   LOCAL application remains non-elevated. A full host installation needs
   a separately reviewed SCM wrapper and explicit trusted launcher binding.
2. Install pinned service binaries and runtime in a SYSTEM/admin-controlled
   directory under `C:\Program Files\AI-1\MemoryAuthority`. Give the service
   read/execute there. Deny the interactive client SCM reconfiguration and
   access to its private storage. Keep the named pipe local and pin the
   expected owner, exact per-role client SID, restricted service token and
   integrity profile. Allocate different pipe names for read and write.
   Enable medium and write only through explicit enrollment.
3. The candidate data root is `D:\AI-1\data\memory`, with private
   `authority\head.sqlite3` and `authority\archives`. Before any creation,
   require fixed NTFS, approve owner and DACL of every parent, and hold the
   pinned NTFS namespace against substitution. Refuse junctions, reparse
   aliases, hardlinks, unsafe ancestry or a different physical chat DB
   association. Deny the desktop client filesystem access. Fail closed if
   D: is inadmissible. A different drive requires separate approval.
4. Provision the new DPAPI CurrentUser profile and generation in the
   restricted service itself, only after its SID and approved storage
   namespace match. Verify ciphertext reopen under that same profile,
   archive/head/receipt integrity, positive and negative pipe roles, native
   service and LOCAL restart, loopback-only HTTP, and timeout/unknown
   reconciliation. Keep the old readonly profile and the chat DB out of
   provisioning. Any import or reseal of prior ciphertext needs its own
   reviewed migration.

## Backup and rollback

- Gate activation on an independently restorable backup. Stop accepting
  mutations, allow in-flight requests to finish, reconcile unknown
  outcomes and drain the service. Record the current generation, revision,
  digest and executable manifest. Take a consistent snapshot of the private
  journal and the referenced, sealed immutable archives. Validate every
  referenced digest and check the copy can be opened under the approved
  CurrentUser profile recovery procedure. Store the backup protected from
  the desktop SID. Do not assume that ciphertext alone survives loss of the
  service profile or the machine.
- On fault disable the write binding, drain the service and preserve the
  newest confirmed head, archives, receipt rows and original installed
  binaries. A missing receipt stays unknown. Restoring older binaries does
  not entail rolling back the head. Restore into an alternate isolated
  namespace, validate it before switching, and treat a data recovery as an
  explicitly authorized new generation. Preserve both versions.
- Deleting a note removes it from the current trusted image. Historical
  encrypted archives and backups still require a separately approved
  retention and deletion policy.

Separate owner permissions are required for installation/service and profile
provisioning, named NTFS roots and ACLs, backup/recovery material, and final
feature activation. Until the exact host plan is approved and qualified,
do not enroll or enable Memory V2.

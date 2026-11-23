# Memory V2 host installation gate

Production remains OFF. Use the release manifest in this directory to
reconcile the reviewed source and frozen dependency pack. The previously
qualified transport and the synthetic SCM wrapper have different deployment
responsibilities. An installer must pin the built service binary, its runtime
and worker, its executable/argument configuration, and the admin-owned
enrollment before placing any file on the host.

Windows Sandbox qualification at `ed6bfc25893c54d8a5bdc8a331b645e40ea31648`
passed all 19 checkpoints. The real LOCAL entry point resolved the fixed
service SID and exercised actual loopback HTTP. The fixture supplied an
in-memory console and lifecycle control only. The service reopened the
restored SQLite journal and its two pinned archive revisions in a
different namespace. Removing the dedicated guest SID's DPAPI key files
caused the SCM worker to fail closed. Restoring those key files, owner,
group and DACL from a separately hashed copy allowed a new SCM worker to
decrypt the backup. The original key directory was retained in quarantine.
This qualifies recovery within the same Windows installation and SID.
Loss of the Windows installation, DPAPI system secrets, or the host service
profile has not been exercised. The fixture SCM executable is sandbox-only.

## Opt-in and expected effect

The LOCAL entry point accepts `--memory-v2` only with `--workspace`. It
requires a trusted Windows console and a non-elevated client. It resolves
`NT SERVICE\AI1MemoryAuthority` using Windows and connects to the two fixed
local named pipes. It shuts down startup before creating the workspace if
the enrolled authority cannot authenticate or return a valid head. Pairing
is a one-time 120-second console challenge and session bearer/CSRF values
are held in client memory. A lost mutation response requires status
reconciliation. Ordinary launch exposes no memory routes.

## Owner approval before any host change

1. **Executable and SCM.** Approve the exact executable and Python/runtime
   SHA-256, dependencies, privileged installer and destination under
   `C:\Program Files\AI-1\MemoryAuthority`. Install a demand-start SCM
   service named `AI1MemoryAuthority`, resolve its virtual account SID and
   independently confirm restricted service SID mode. Pin the actual
   ImagePath and arguments. Keep binaries and enrollment writable only
   by SYSTEM/approved administrators. Test ordinary-token denial of service
   reconfiguration. No elevation of LOCAL.
2. **Filesystem and pipe enrollment.** Authorize inspection and then
   explicit creation/ACL setup of `D:\AI-1\data\memory\authority` and its
   archive directory. Confirm D: is local fixed NTFS. Record each root and
   ancestor by volume/file ID and check the final handle identity. Reject
   reparse points, junctions, symlinks, file hardlinks, alias/device paths,
   mutable ancestors and any chat DB collision. Do not create SQLite in a
   location that an ordinary client can replace. Inspect the actual owner,
   effective ACL, sidecar access boundaries and fresh genesis admission.
   The private namespace must be writable only by the approved restricted
   service and trusted provisioning identity, and deny desktop read/write.
   Authorize the exact read and write SIDs separately. Pin pipe owner to the
   SCM SID, prohibit remote clients and exact DACL writes by readers, preserve
   no-write-up and require independent approval for a medium enrollment.
   An unsuitable D: is an installation refusal.
3. **Profile and backup.** Authorize creation/loading of the dedicated
   service's DPAPI CurrentUser profile, its recovery boundary and backup
   destination. Verify the exact SID after service restart. A sealed archive
   and SQLite backup are insufficient evidence of profile-loss recovery.
   Before real activation, require a clean-profile recovery rehearsal with
   native proof of missing-key refusal and recovery under the approved SID,
   or an independently reviewed portable recovery design. Document which
   system/profile recovery material is required and who controls it.
4. **Activation.** Authorize the checked host preflight and a synthetic
   smoke first. Separately authorize the first `--memory-v2` run with
   owner pairing. Archived deletions need an approved retention policy.

The installation receipt must contain the successful results of
`sc.exe qc AI1MemoryAuthority`, `sc.exe qsidtype AI1MemoryAuthority` and
`sc.exe sdshow AI1MemoryAuthority`, the running SCM and worker token SIDs,
the volume/filesystem and native handle facts for all admitted ancestors,
the SHA-256 audit of installed executables and modules, and both pipe ACL
and negative-access receipts. A read-only host preflight and any privilege
needed to obtain these facts have to be separately approved beforehand.
Startup with the flag removed must return 404 for memory routes.

## Recovery and rollback

Drain writes and reconcile every unknown response before a backup. Under a
stopped, verified service take a consistent journal snapshot and every
referenced immutable archive. Hash each member, validate integrity and the
authoritative generation/revision/digest chain. Verify a restored candidate
in a separate namespace under the approved DPAPI recovery identity. A backup
candidate may never silently replace the live head. Preserve source,
current backup, and recovered candidate. Restore past content only through
an independently authorized new generation.

On regression remove the launcher opt-in first and stop the enrolled
service after it drains. Preserve the newest verified head and receipts,
the protected ciphertext and profile. Restore the pinned previous binaries
only if the operator authorizes executable rollback. If the older binaries
cannot read this write schema, leave Memory V2 OFF. On lost DPAPI access or
an unresolved COMMIT, freeze operations and retain both versions. Neither
uninstall nor rollback deletes the journal, archives or profile.

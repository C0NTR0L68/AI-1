# AI1MemoryAuthority host approval and installation contract

The service is demand-start and runs using the virtual account
`NT SERVICE\AI1MemoryAuthority` with restricted SCM SID mode. The
non-elevated LOCAL process requests access through the named pipes. A
fresh store uses the service's own DPAPI CurrentUser profile.

## Authorize host metadata as a separate operation

The reviewed command is:

```powershell
& '<approved Python 3.12 x64 path>' -I -S -B '<review checkout>\service\preflight_storage.py' --inspect-approved-path
```

The scope is the fixed local D: NTFS volume, the exact ancestors of
`D:\AI-1\data\memory`, and the candidate authority and archives directories.
If present, the scope includes metadata of `archive-pin.json`,
`head.sqlite3` and its three known sidecars. The command lists owners,
owner/group/DACL SDDL, reparse/type checks, volume identities, native file
IDs and file link counts. It neither enumerates unrelated folders nor
reads file contents or opens SQLite. Absent paths are recorded without
creation. Access failure, conflicting identity, unsafe link or sidecar
requires review. No report implies authorization to modify ACLs or create
a directory. Keep host ACL/SID output private.

## Authorize each set of host writes separately

1. **Install the exact reviewed files.** Copy the approved SHA-256 pinned
   `Authority.exe`, `inputs.sha256`, and its 665 named runtime/worker
   members into `C:\Program Files\AI-1\MemoryAuthority`. Ensure every
   parent is on the expected local filesystem and controlled by SYSTEM
   and approved administrators. The service gets read/execute. Ordinary
   users must have no write, delete-child, ownership or DACL authority.
   The SCM ImagePath is the quoted executable path with no fixed arguments.
   Verify `sc.exe qc AI1MemoryAuthority`, `sc.exe qsidtype AI1MemoryAuthority`
   and `sc.exe sdshow AI1MemoryAuthority`. Guest executable hashes prove
   byte identity for the guest binary. Any rebuilt or signed binary
   needs its own hash and an exact-binary qualification.
2. **Provision the namespace and SIDs.** Authorize creation and ACLs for
   `D:\AI-1\data\memory\authority` and future `archives`. Stop if D: or
   any existing parent fails the reviewed identity or ACL requirements.
   Establish parent and leaf NTFS file ID pins, confirm no alternative
   parent path or reparse point, and exclude hardlinks to any existing
   database. Under the protected install root create a SYSTEM-owned
   `authority-enrollment.json` with version, new generation, literal state
   path, ancestor volume/file IDs, exact read SID, exact write SID,
   approved integrity label and receipt budget. Verify the service can
   read but cannot mutate the file. The service SID and SYSTEM alone
   control the data directory. Pipe DACLs grant the separately enrolled
   exact SID for each role, exclude remote clients and pipe-instance
   creation, and retain no-write-up. Approve a medium enrollment
   explicitly. Do not redirect to C: on a D: failure.
3. **Initialize the new service profile and data.** Start with the
   one-time administrator SCM argument `provision` only after confirming
   an empty approved authority domain. The service creates its Windows
   CurrentUser key, sealed genesis archive and trusted SQLite head. An
   ordinary service start without the argument requires admitted existing
   data. A partial provisioning state is retained for review. The chat
   SQLite and earlier profile-owned archives stay outside this domain.
4. **Back up and qualify recovery before activation.** Approve a separate
   protected backup destination, encryption, recovery operator and
   associated access. With SCM drained, capture the exact SQLite state,
   sealed archive members, manifest and owner/DACL evidence. Verify a
   restored candidate in an alternate namespace with native DPAPI and
   validate the latest confirmed head and receipts. Require deliberate
   approval of the separate activation step after the host gates pass.

## Recovery after loss of Windows

The same-installation rehearsal covered missing service profile key files
and their restoration under the same service SID. Complete Windows loss
can also destroy machine DPAPI material needed to unwrap those files. The
head, ciphertext and copied profile directory alone do not establish that
recovery will succeed. Preserve the original installation while creating
an approved encrypted offline Windows system image that includes its
DPAPI/system state and the matching service profile. Rehearse image recovery
on an isolated machine or VM under the approved recovery identity and
check native decrypt, the expected receipt and the backup manifest. Hold
the production gate until this path passes, or require an independently
reviewed portable recovery format with separately managed recovery keys.
Never substitute machine-wide DPAPI to make a backup appear portable.

## Rollback

Disable the LOCAL opt-in, drain requests, reconcile pending receipts and
stop the explicitly enrolled SCM service. Restore approved binaries or
remove the installed SCM entry only after an explicit owner decision.
Retain the current journal, ciphertext, profile, backups and protected
metadata. Reverting code leaves the current head in place. A recovered
older archive must remain separate until the owner approves adoption into
a fresh generation. An unknown commit or failed DPAPI recovery keeps the
memory service unavailable pending evidence.

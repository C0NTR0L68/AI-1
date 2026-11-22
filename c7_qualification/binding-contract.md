# Dormant memory storage binding

The standard LOCAL launcher accepts an explicit Python-level
`MemoryStorageFactory` only together with an explicit workspace. Its ordinary
CLI and environment configuration supply no factory. FastAPI opens the
factory during its locked lifespan before creating the workspace, checks the
live generation and the current authenticated archive, and releases the
session on startup failure or shutdown. The factory cannot mount HTTP
routes. The synthetic HTTP test binding and the storage factory are mutually
exclusive.

The archive path and all of its directory identities must be enrolled
independently of startup, then passed in a `PrivateArchiveDirectory`. No
path, connection string or factory name is accepted from HTTP, the CLI or
environment configuration. The authority session is trusted deployment
input. The factory never discovers a local SQLite path or provisions a
replacement registry when the authority fails.

A qualified deployment must run the live authority under a distinct Windows
principal, keep the database and any journal in a namespace the application
client cannot write or replace, and authenticate the connection to that
authority. It must scope read and CAS to the enrolled store. The authority
is also responsible for replay resistance and recovery of ambiguous writes.
This change does not provide a service installation or authenticate an IPC
transport. The native guest fixture checks the filesystem boundary of a
separately owned authority. The lifecycle test uses an explicit synthetic
authority session to exercise application wiring.

The components are tested without enabling Memory V2. Full B5 remains pinned
to the previously qualified frozen revision. Production activation requires
qualification of the actual trusted authority transport and enrolled NTFS
root, followed by the owner's separate approval.

## Windows qualification · 2026-11-22

- Previous transport provenance reconciled all 15 application files against
  the Git objects and original verified archive. Eight were identical.
  Seven were exactly the LF-to-CRLF conversion performed in the checkout.
  The new bundle reads 717 members including exact Git source blobs, pinned
  Python runtime files and original dependency wheels. A second build matched.
- Three focused tests passed, covering the LOCAL launcher, startup and
  shutdown of the explicitly supplied factory, application behavior with
  memory routes absent, and failed admission without workspace creation.
  The first run failed at collection because the PRE-EPOCH wheel set omitted
  python-dotenv. The retry used the existing version 1.2.4 package, separately
  pinned against its RECORD and delivered only inside the guest.
- The exact app blobs passed Windows NTFS and DPAPI reopen and both native
  symlink probes. An archive directory substituted at the same name with
  an equally private DACL was also denied by the enrolled identity check.
- Separate native authority test: guest SYSTEM staged its interpreter and
  code in a private directory from a verified copy of the package. It
  created a synthetic head, saved revision zero in the disposable client
  parcel, committed revision one, then left a real rollback journal. A
  different guest principal could neither open, remove, rename, overwrite
  or replace the head and journal nor replace their parent directory. The
  privileged verifier confirmed both byte hashes unchanged, revision one
  and rejection of a stale compare-and-advance.

The lifecycle test and separate-account filesystem test prove two distinct
parts of the design. No deployed IPC transport connects them. The exact
production authority and enrolled archive location still require release
acceptance. The disposable guest was stopped and its absence verified.

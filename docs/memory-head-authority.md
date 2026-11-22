# Memory V2 head authority

The isolated registry records a generation UUID, a monotonic revision and a
SHA-256 digest. The authority provisions it once and uses SQLite rollback
journaling, FULL synchronization and BEGIN IMMEDIATE for compare-and-advance.
Normal operation opens an existing registry only. A write error may leave the
new head committed. Resolve it by reading the live authority. A caller must
never automatically retry it. Restore to another generation is a separate
administrative operation and is currently unavailable.

## Trust and deployment requirements

- Keep the registry and its journal outside the client's writable root and out
  of client archive import, backup and restore. A deployment must prove that
  the client can neither replace the registry nor replay its older storage.
  The process owns its SQLite connection factory and the entire local path.
- A local Windows service with a distinct service SID, tightly scoped
  privileges and a private NTFS directory is a candidate against an ordinary
  desktop-user rollback of the archive tree. Pin the volume and protected
  ancestor identities, reject reparse points and hardlinks, and qualify ACLs
  for the main DB and any journal. Service binaries and configuration must
  also be outside the user's write and service-control permissions.
- A service on the same Windows image cannot detect an administrator or
  snapshot rolling back the entire image. Protection against that threat
  requires an independent authority outside that snapshot or a hardware
  freshness protocol that binds each committed revision to its digest and
  survives interruption. DPAPI and encryption alone supply no freshness.
  No production anchor or TPM protocol is provisioned or qualified here.
- An authenticated local IPC endpoint would expose live read and CAS, bound
  to a fixed store identity and authenticated principals. Use replay-resistant
  replies bound to a client nonce and strict message size limits. Reject a
  missing authority, wrong generation, stale revision or digest mismatch.
  Authentication and client permission to advance need separate qualification.
- Publish and verify the sealed archive before advancing the head. Future
  archive reads must hash bytes read through the inspected handle and compare
  with the live digest. No local cached head or newest-on-disk search grants
  permission to read or publish. An orphaned archive remains unpublished.
- The isolated backend adapter checks the generation inside the candidate
  archive before submitting CAS. A Windows synthetic integration test reopens
  the registry and serves a formerly valid sealed archive to the reader to
  confirm rejection. It uses a test authority in temporary storage.

Service creation and DACL setup need a separate owner authorization. See
[service SID modes](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
and [SCM access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
Before activation qualify IPC identity, ordinary-user denial, directory and
sidecar replacement, partial filesystem and registry rollback, power loss and
ambiguity after commit. This module is intentionally outside FastAPI and
leaves Memory V2 OFF.

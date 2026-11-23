# Memory V2 write deployment gate

The offline writer keeps the DPAPI archive reducer and the SQLite authority
transaction behind a trusted caller. It adds no launcher binding, memory
route or pipe opcode. The current read-only Windows deployment is unchanged.

## Required identity decision

The previous guest proved that the desktop user's CurrentUser archive is
opaque to the separate SCM SID. A write-capable service must validate a
semantic command and derive the next image from the trusted head. It cannot
accept a desktop-supplied archive or digest as evidence of that transition.

For a fresh store, the proposed writer is a restricted SCM service with its
own qualified profile and CurrentUser key. Its SID owns the reducer, archive
publication and registry. A separate local desktop role receives only
authorized semantic reads or mutations over authenticated pipe operations.
Qualify the service profile across restart and recovery before accepting
enrollment. If existing owner-profile ciphertext must be retained, require a
separately reviewed export/reseal procedure from that profile. Do not switch
to machine-scoped DPAPI or infer write authority from a desktop SID or an
HTTP session. Any old read-only registry is refused by the new schema.

## Production checklist, pending approval

1. Approve the policy for the service-owned profile and read/write roles in a
   synthetic guest first. Test separately enabled write enrollment, pipe
   SID/owner/integrity, malformed and replayed requests, desktop filesystem
   refusal, reducer recovery, and local HTTP with consent and memory OFF
   at default startup.
2. In a distinct host approval, name the exact service/SID/profile,
   archive and registry parent paths, DACLs, pipe ACL, and installation
   account. Require fixed local NTFS, pinned parent identities and
   reparse/link rejection. Never provision through the desktop launcher.
3. Before activation, with the owning service drained, record the current
   head and all manifest pins. Take a service-owned, validated backup of the
   consistent registry and referenced sealed archive set with the approved
   DPAPI profile recovery material under access control. Verify that exact
   backup with a supported recovery exercise on synthetic data before real
   activation. Keep an offline rollback that disables the new write route,
   drains the service and preserves the newest verified generation in
   place. Suspend on mismatch or unknown commit. Recover data via a separately
   authorized new generation, without moving the existing head backward or
   dropping a newer user's archive.
4. Changes on the real host would register/configure the restricted SCM
   service, provision its profile and key, apply explicit NTFS/pipe ACLs and
   provision the enrolled namespace. Require a second explicit owner
   approval to enable Memory V2 after the exact host tests pass.

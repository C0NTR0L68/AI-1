# Memory V2 — synthetic LOCAL → SCM → DPAPI qualification

Date: 2026-11-23. Tested source: `cb5324864dd1510ff855e188e9b48cdf4c0efcb9`.
Baseline report: `9e58189325c2d705e1d8480df37b26b095f56ba1`. Earlier medium test: `55f003f7aa5276f544daa03598151b36bc654325`.

## Result

**PASS — 30/30 native guest checkpoints.** Production remains **NO-GO** and Memory V2 stays **OFF**. The change is confined to synthetic qualification. No application code or original tests changed. Full B5 and historical C7-v1 were not repeated.

| Scope | Evidence |
| --- | --- |
| Isolation | A new 2560 MB Windows Sandbox with network, clipboard, vGPU, audio, video and printer redirection disabled and no mapped folders. The guest independently checked network interfaces and C:/D: mappings. Offline runtime SHA-256 was confirmed after transfer. |
| Standard client | The bridge verified the local credentials, checked the SID, integrity RID 8192 and elevation flag on the suspended child, then checked the child's receipt and termination. |
| SCM authority | Real SCM service launched under its named virtual service account with a restricted service SID. Actual named-pipe operations enforced owner SID, client SID, read-only commands and the configured integrity boundary. Wrong SID, an impostor owner and both mutation attempts were rejected. |
| LOCAL, FastAPI and archive | Invoked the real LOCAL launcher with an explicit factory and synthetic workspace. Executed the resulting FastAPI lifespan and used ASGITransport for the 404 check on the disabled notes endpoint. Uvicorn's network entry point was intercepted. Native IPC, NTFS handle inspection and DPAPI ran in the respective Windows processes. |
| DPAPI | The standard user created an encrypted archive with a synthetic note and a separate CurrentUser canary. A later process under that SID decrypted both. The restricted service read the exact ciphertext, verified SHA-256 and was denied decryption of both. The canary returned HRESULT `0x8009000B`. |
| Trust binding | A privileged synthetic enrollment placed the expected generation and historical/current SHA-256 values in protected configuration. The authority returned revision 1, and the client accepted only the current digest under the enrolled generation and NTFS identity chain. The ordinary process was denied mutation of the trusted head, its rollback journal, the authority-owned archive copy, protected enrollment, the service binary and their protected directories. |
| Fail closed | Wrong generation, changed ciphertext, a valid older archive under the current name and a replacement directory with the same ACL and correct ciphertext all caused startup refusal. A stopped authority, a dropped reply and a native IPC deadline also caused refusal. Failed startup did not expose storage or create a workspace database. |
| Recovery | The service crashed with a genuine SQLite rollback journal. The subsequent service and launcher processes returned the enrolled head and decrypted the expected note. Snapshot hashes and cleanup were checked. SCM service and temporary account were removed. An independent host inventory confirmed the owned Sandbox session was absent after stop. |
| High default | The previously tested pipe source is byte-identical and defaults to high integrity RID 12288. Published native high-profile denial of medium remains applicable to that code. This run explicitly selected medium. The host runner separately rejected missing medium enrollment before any guest operation. |

## Authority and DPAPI boundary

The service can authenticate the caller and attest the enrolled tuple (generation, revision, digest). It verified ciphertext against the sealed enrollment in this fixture. That does not prove which principal sealed a newly submitted archive or establish the semantic validity of its contents. The owner process verifies the CurrentUser archive itself. Standard-user access to its own archive permits denial of availability by that same Windows identity. The independently protected head and digest stop acceptance of older or arbitrary content.

The tested enrollment is an out-of-band synthetic fixture with a known creator and approved bytes. It is not a production enrollment tool or a remote CAS implementation. Keep CurrentUser and independent protected head ownership. Do not use machine-wide DPAPI, authority impersonation or escalation of FastAPI to bridge this boundary.

## Evidence review

The verification utility reconciles the exact test commit with the prior eleven published receipt hashes, source SHA-256 values, archive CRC and manifest, 30 checkpoint identities, and both cleanup receipts. It does not rerun Windows. The checked source set covers every application file and the imported fixture helper, with a separate pin for the SCM wrapper, bridge, guest script and transferred probe. The launchers preserve the reviewed high profile. Python and PowerShell parsed successfully on the host.

[Receipt manifest](scm-dpapi-e2e-evidence/qualification.json) SHA-256: `3BAA0C828379FE6A9262D1A599AC2D86D510F1C3BB3623E4A958C6EE3CC58483`.

An initial host transport stopped on Windows checkout CRLF before the guest test. The next guest attempt stopped at archive ancestor inspection. This failure was preserved. The fix granted the enrolled client execute/read access only on the synthetic parcel directory, without inheritance, and retained all archive pin and ACL checks. The guest then passed with the corrected source revision.

## Remaining production gates

**NOT_RUN:** deployment against a real approved Windows SID/profile and protected NTFS namespace, production enrollment and recovery, a real loopback HTTP listener on this revision, write-capable IPC and CAS, and activation. Keep Memory V2 OFF. Before writable production use, qualify an independently approved enrollment and publication transaction, reconciliation after ambiguous outcomes, profile recovery, and separate user consent. Production uses its own exact path and ACL evidence. This Sandbox result does not authorize real host service, identity, ACL or data changes.

Microsoft references: [DPAPI CurrentUser scope](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) and [loading the test user's profile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw).

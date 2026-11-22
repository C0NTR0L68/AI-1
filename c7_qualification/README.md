# C7-v1 independent qualification · 2026-11-22

Reviewed baseline `d57fe91d600c509d0cb5c5b0c190361ff3453ca3`. This directory
adds qualification code and evidence only. Full B5 retains its recorded PASS
on the frozen revision and was not rerun.

| Scope | Result | Evidence |
| --- | --- | --- |
| Local NTFS archive and synthetic head | PASS | Explicit private DACLs, pinned directory chain, real DPAPI archive publication, CAS, deduplication and the same decision after reopening. |
| Reopen in a separate Windows process | PASS | Live revision and digest match, the note decrypts under the guest user, and an absent `mode=rw` head is refused without creating a database. |
| Native file and directory symlink | PASS | Guest SYSTEM created real symbolic links under the owned scratch directory; the application inspector ran in ExistingLogin and returned `reparse` for both. |
| Symlink at the current archive's final name | PASS | The target was the authentic archive. The image ledger declined the read and the live generation, revision and digest were unchanged. |
| Production application binding | BLOCKED | `app/main.py` constructs the default app without a memory binding. The optional binding only installs the synthetic middleware. There is no startup factory for a separately trusted head and no enrolled production archive namespace. |

The native sequence ran in a new Windows Sandbox without network, host
folder mapping or clipboard. The login context confirmed there were no C:
or D: drive redirects. SYSTEM was scoped to fixture creation. Stopping the
guest and checking that it was absent from the session list completed cleanup.

The first payload lacked the archive namespace module. It was supplied as a
separately hashed member. The next setup exposed the distinction between a
directory's default owner and the current token's user SID in this guest.
The fixture now supplies the explicit user SID when creating protected files
and directories. An RDP drive probe failed in the guest SYSTEM context. The
final fixture launcher verifies those drives through ExistingLogin and still
checks the network and SYSTEM SID in the fixture process. The earlier exit
receipts are retained. No application check, host setting or privilege
assignment changed.

The production gate still needs a trusted connection factory that proves
the head database and its journal stay outside the client's writable and
restorable namespace, plus independently enrolled directory identities and
ACLs for the configured archive root. The synthetic boot used a separate
scratch directory and the guest's own account for the SQLite head; it does
not establish production authority separation. The accepted threat-model
limits for rollback of both the archive and authority remain in
[`docs/c7-v1.md`](../docs/c7-v1.md).

Memory V2 remains **OFF**. Production remains **NO-GO**.

The per-file SHA-256 manifest, application blob comparisons, pinned runtime,
dual-context receipts and cleanup result are under [evidence](evidence).

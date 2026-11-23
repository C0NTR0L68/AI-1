# Future write capability for Memory V2

The current Windows wire opcode remains read-only. A future write protocol
needs its own approval and qualification.

## Authority and admission

Use a versioned write capability, separated from general head readers
by an explicit Windows principal or an equally strong separately reviewed
credential. A history HTTP session alone grants no authority permission.
Bind the capability to a single enrolled store and generation. No caller
may choose an arbitrary path, forward SQL, request restore or select a new
generation. Authenticate both IPC peers and validate a bounded frame before
opening storage. Use an authority-issued session challenge and an
operation UUID. Bind the UUID, expected head, exact mutation and digest
to that challenge. Keep authentication and note material out of logs.

Resolve the boundary between client DPAPI and a separate writing principal
before implementing the wire. If stale valid note contents must be rejected
even when a desktop process is compromised, validating a new digest alone is
insufficient: an authorized process could republish old logical contents.
Prefer a trusted reducer that interprets an authorized mutation and controls
archive sealing. Review key ownership and an explicit DPAPI migration. Do
not assume the service can decrypt the desktop user's CurrentUser data.

## Durable sequence

1. Validate operation identity, codec and role. Verify the expected current
   head, reject stale generation/revision or an ID bound to different input.
2. Write and flush an immutable new archive within the enrolled namespace.
   Reopen by verified handle and check generation, digest and durability
   before advancing. An unreferenced file from an interrupted publication
   remains an orphan, never the basis for fallback.
3. Under one authority `BEGIN IMMEDIATE`, enforce current tuple equality
   and unused digest, insert the next revision and its operation receipt,
   then commit. Duplicate same-input operation IDs return the committed
   receipt without publication or mutation. Quotas and receipt retention
   must define when replay is refused rather than treated as new.
4. If the response is lost or COMMIT is ambiguous, return UNKNOWN (or
   let the IPC fail). The client uses a separately authenticated status
   read by operation UUID, checking its immutable operation binding. No
   automatic write resend or implied success from an archive file.
5. A known pre-commit rejection has no receipt and leaves the live head
   unchanged. A head advance without the matching archive is a recovery
   incident. Never roll back head to make an older archive acceptable.

## Required tests

Use two genuinely distinct native principals. Cover wrong role/SID,
replayed challenge, malformed/overlong frame, expiry, wrong generation,
stale expected revision, two competing writers, duplicate operations,
same ID with different input and exhausted receipts. Verify actual
filesystem denial and authority restart. Inject interruption before archive
publication, after publication, during SQLite commit and after commit but
before acknowledgement. Confirm exact recovery and protected bytes.
Performance, filesystem power-loss guarantees, and the threat of rolling
back both the authority and archives need separate qualifications.

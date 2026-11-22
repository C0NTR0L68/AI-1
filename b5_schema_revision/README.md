# Proposed frozen B5 schema revision

Base: review commit `622755d1455bf709c650da315b8eee37056c85b6`. The original
archive, release preflight and eight original test files are immutable.
The existing control evidence remains 601 passed and 2 failed out of 603.

## Disposition

| Frozen control | Root cause | Proposal | Preserved guarantee |
| --- | --- | --- | --- |
| `test_complete_turn_sqlite_failure_becomes_unknown_without_assistant` | Its fixture installs a persistent trigger before `create_app` first enters lifespan. The accepted preflight rejects unknown schema objects before store or provider work. The failure-injection fixture never reaches the transaction it is meant to test. | Keep an explicit before-startup refusal check. Exercise the unchanged `complete_turn` with an actual SQLite `RAISE(ABORT)` from a TEMP trigger on the completion connection after admission. | Unknown schema leaves source bytes unchanged and provider untouched. A failure after dispatch yields HTTP 500, one provider invocation, one unknown user message, zero assistant messages, a null reply, history and status consistency, and survival after reopening. The READY fingerprint stays unchanged. |
| `test_legacy_assistant_model_name_survives_provenance_migration_and_api` | The old helper adds columns and indexes. It leaves the legacy table without the required role/status CHECKs. That is a missing explicit conversion from the recognized predecessor into READY, rather than a reason for the runtime to admit a different schema. | Add an offline export for the exact predecessor and the exact add-columns intermediate. Use a caller-supplied query-only SQLite connection and a fresh destination. Validate output with the unchanged READY preflight before exercising API. | The predecessor still fails read-only admission. Its bytes and existing target data stay unchanged. Both API reads preserve historical provider/model provenance, nullable newer fields, reply and status after reopening. Row IDs and the AUTOINCREMENT high-water mark are preserved. Unknown objects, invalid rows and duplicate request identities are refused and destination writes roll back. |

The export is a frozen proposal overlay and is never selected by production
startup. It rejects extra source schema objects, altered indexes, WAL/version
mismatches, attached schemas and nonempty destinations. A caller must
independently protect and select its source and target files, close the export,
run file-based postflight, and request separate approval before any real
migration or database replacement. Memory V2 remains OFF.

## Qualification to approve

Keep reporting the original suite and its result under its original digest.
For the proposed revision apply only the overlay recorded in
`revision-manifest.json`. Replace exactly the two affected scenarios in the
candidate inventory with the verified counterparts and explicit negative cases
in `test_schema_contract.py`. Both originals stay in the separate immutable
control artifact. No skips, loosened assertions or extra runtime-admitted
schema profiles. Verify collected IDs before execution and run the complete
candidate Python and Node qualification inside the same isolated Windows
Sandbox workflow. Report both baseline and candidate identifiers.

The focused runner uses the exact baseline release and bundled dependency
wheels. It stages a new scratch directory, denies socket and subprocess
audit events, and runs the new tests against synthetic SQLite and in-process
HTTPX ASGI requests. Usage from the candidate checkout:

```powershell
python -I -S -B b5_schema_revision/run_focused.py --archive <absolute-baseline-zip> --scratch-parent <absolute-owned-scratch>
```

A successful focused result qualifies only these cases. The new full B5
revision and C7-v1 acceptance follow the approval of this exact delta.

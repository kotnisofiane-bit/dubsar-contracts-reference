# Exact-action private IPC

Python supervises one Node process with private stdin/stdout pipes and no shell.
The executable and composition module are explicit administrator-owned paths.
No request selects a module, command, endpoint or administrative operation.

Each frame is a four-byte big-endian length followed by UTF-8 JSON, at most
4 MiB. The envelope is closed: schema dubsar.exact-ipc/1, generation, request_id,
operation and params. Responses mirror schema/generation/request_id with ok and
exactly one of result/error. One request is in flight, queue capacity 32, total
request deadline at most ten seconds. A broken/timed-out channel is stopped;
no automatic mutation retry. New process means a fresh generation.

Operations prepare/view/decide pass a cryptographically verified human proof to
ApprovalService. The private channel authenticates the server composition, not
the human. Test-only fixture controls are confined to the qualification module.
Production must never load that module or the Backend fixture snapshot.

The Backend returns uncertain on lost responses. Re-query presentation using the
same still-valid session to recover committed results. A complete content change
requires a new presentation. The canonical manifest is the version served and
confirmed, not proof of comprehension or a completed external action.

The cross-repository fixture snapshot is generated from an exact contracts commit,
not edited independently. Its hashes are checked before extraction/execution and
its source is independently compared against GitHub before qualification closure.
It is only a test distribution mechanism, not production package installation.

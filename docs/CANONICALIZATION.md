# Canonical representation and hashing

## Input domain

Contract values are JSON only. Numbers are safe integers; non-finite numbers,
floating-point values, `-0`, duplicate object keys and non-JSON values are not
admitted. Strings are preserved exactly and are not Unicode-normalized.

## Canonical representation

The implementation uses the following deterministic profile:

1. validate the instance against its closed schema and semantic invariants;
2. serialize `null`, booleans, safe integers and strings using JSON syntax;
3. sort every object key lexicographically by UTF-16 code units;
4. preserve array order;
5. emit no insignificant whitespace;
6. encode the result as UTF-8.

Array order is therefore business-significant. Workflow `nodes` and
`transitions` carry an explicit, contiguous `order` and must already be sorted
by that field. Reordering object keys never changes a digest; changing a field,
an array order, a node, a bound or a connector version does.

## Domain separation

For contract kind `K`, the SHA-256 preimage is:

```text
UTF8(domain_separator[K]) || 0x00 || canonical_json_bytes
```

Domain separators are closed in `contracts/v1/contract-set.json`. Digests are
rendered as lowercase `sha256:<64 hex characters>`. A value from one contract
domain cannot be substituted into another domain with the same JSON bytes.

Payload digests use the separate domain `dubsar.payload.v1` and the same
canonical JSON profile. Task profile and runtime lock digests use
`dubsar.task-profile.v1` and `dubsar.runtime-lock.v1`.

## Compact signed envelopes

Two reference envelopes reuse this canonical profile without defining a
general-purpose token format. Each is `base64url(canonical_json(header)) "."
base64url(canonical_json(payload)) "." base64url(ed25519_signature)`, where the
signature covers the ASCII bytes of the first two segments and every segment
must decode back to its canonical encoding:

| Envelope | `typ` | payload `schema` | audience |
| --- | --- | --- | --- |
| signed capability (Lot 2C) | `DUBSAR-CAPABILITY+JSON` | `dubsar.signed-capability.v1` | `dubsar-action-broker` |
| signed task lease (Compose S0) | `DUBSAR-TASK-LEASE+JSON` | `dubsar.signed-task-lease.v1` | `dubsar-task-manager` |

Both headers are exactly `{alg: "EdDSA", kid, typ, v: 1}`. Verifiers check the
header, the closed payload key set, the temporal envelope, the issuer, the
audience, the embedded contract and its domain-separated digest before the
signature, and fail closed on any deviation. The task-lease signature segment
must also be the canonical base64url encoding of the 64-byte signature.
Task-lease mount paths are already POSIX-canonical: `path.posix.normalize(p)`
equals `p`, every segment matches `[a-z0-9][a-z0-9_-]*`, and `.` / `..` /
empty segments / `//` are refused before the closed allowlist
(`/run`, `/tmp`, `/workspace`) is applied.

## Workflow approval binding

The workflow digest is computed over the complete Workflow IR. An Approval
Record stores that digest and exact workflow version. A consumer must recompute
the digest and reject a mismatch before honoring the approval. Expired or
revoked approvals also fail closed.

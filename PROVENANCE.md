# Provenance

Source: private canonical repository `kotnisofiane-bit/dubsar-contracts`,
commit `05fe80e7a4f3765ac0552e1eab1319780a400a90`,
tree `61a3767cf489cc6a61f75437cd858bb261132f9c`.

This repository starts from a single root commit. No private history, refs or
objects were imported.

`public-source-manifest.json` records, for every exported file: public path,
source path, source blob SHA, source commit, SHA-256 of the source bytes,
SHA-256 of the public bytes, `identical` or `adapted`, the transformation, its
provenance and redistribution status. It also lists every new public file.
Excluded source files are reported only as categories with counts; their
per-path classification is kept privately and bound here by
`private_classification_digest`.
`public-allowlist.json` is the exact list of public paths.

Verify the public side with:

```bash
npm run verify:public-manifest
```

Verifying the source side requires read access to the private commit and
comparing each `source_blob_sha` / `source_digest`.

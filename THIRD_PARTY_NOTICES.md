# Third-party notices

No third-party source file is included in this repository. The dependencies
below are resolved by `package-lock.json` from the public npm registry and are
installed by `npm ci`; they are **not** relicensed under Apache-2.0 and remain
under their own licenses.

| Package | Version | License | Copyright notice (from the package) |
| --- | --- | --- | --- |
| pg | 8.16.3 | MIT | Copyright (c) 2010 - 2021 Brian Carlson |
| pg-cloudflare | 1.4.0 | MIT | Copyright (c) 2010 - 2021 Brian Carlson |
| pg-connection-string | 2.14.0 | MIT | Copyright (c) 2014 Iced Development |
| pg-int8 | 1.0.1 | ISC | Copyright © 2017, Charmander |
| pg-pool | 3.14.0 | MIT | Copyright (c) 2017 Brian M. Carlson |
| pg-protocol | 1.16.0 | MIT | Copyright (c) 2010 - 2021 Brian Carlson |
| pg-types | 2.2.0 | MIT | Copyright (c) 2014 Brian M. Carlson (license in README) |
| pgpass | 1.0.5 | MIT | Copyright (c) 2013-2016 Hannes Hörl (license in README) |
| postgres-array | 2.0.0 | MIT | Copyright (c) Ben Drucker |
| postgres-bytea | 1.0.1 | MIT | Copyright (c) Ben Drucker |
| postgres-date | 1.0.7 | MIT | Copyright (c) Ben Drucker |
| postgres-interval | 1.2.0 | MIT | Copyright (c) Ben Drucker |
| split2 | 4.2.0 | ISC | Copyright (c) 2014-2018, Matteo Collina |
| xtend | 4.0.2 | MIT | Copyright (c) 2012-2014 Raynos |

Totals: 12 MIT, 2 ISC.

The full license text of each package ships inside the package
(`node_modules/<name>/LICENSE`, or the README license section for `pg-types`
and `pgpass`). Anyone redistributing an installed `node_modules` tree must keep
those notices.

## Tooling referenced but not distributed

- GitHub Actions `actions/checkout` and `actions/setup-node` (MIT), pinned by
  commit SHA in `.github/workflows/ci.yml`.
- The `postgres:16.10-bookworm` container image, used only as a disposable CI
  service (PostgreSQL License and Debian package licenses).

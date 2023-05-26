---
'@backstage/plugin-catalog-backend': minor
---

Defer stitching to a separate loop, instead of always executing it immediately. This should make performance smoother when ingesting large amounts of entities or when fan-out/fan-in in terms of relations is very large.

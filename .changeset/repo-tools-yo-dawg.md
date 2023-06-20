---
'@backstage/repo-tools': patch
---

Introducing a new command `backstage-repo-tools create-fix-package-info-yamls`, which can be used to create standardized `catalog-info.yaml` files for each Backstage package in a Backstage monorepo. It can also be used to automatically fix existing `catalog-info.yaml` files with the correct metadata (including `metadata.name`, `metadata.title`, and `metadata.description` introspected from the package's `package.json`, as well as `spec.owner` introspected from `CODEOWNERS`), e.g. in a post-commit hook.

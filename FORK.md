# Chelabase Fork of Neon

This is Chelabase's hard fork of [neondatabase/neon](https://github.com/neondatabase/neon), based on upstream commit fa504217 (2026-08-31, main HEAD when upstream froze). PostgreSQL sources are pulled from [chelabase/postgres](https://github.com/chelabase/postgres) branches `REL_14_STABLE_chelabase` through `REL_17_STABLE_chelabase`.

## License

Apache License 2.0, unchanged. NOTICE file and upstream copyright are retained.

## Policy

We do not rewrite the core engine (pageserver, safekeepers, or Neon's PostgreSQL patches). We replace specific components only when our needs genuinely differ from upstream. Performance improvements must have supporting profiling evidence.

## PostgreSQL Minors

When a new PostgreSQL minor release becomes available:

1. Merge the `postgres/postgres REL_x_y` tag into `REL_x_STABLE_chelabase` in chelabase/postgres (pull request, run `make check`).
2. Bump the submodule commit here and update `vendor/revisions.json` (pull request). The gate is `.github/scripts/ci-local.sh` (lint, build, Rust tests) on the bump, plus a local `make check` for that major in chelabase/postgres.
3. Publish dev images with `.github/scripts/publish-dev.sh` and run chelabase's e2e against them.
4. Process oldest minors first.

Neon's own `REL_x_STABLE_neon` branches remain read-only references; we do not track them.

## Tests

CI quarantines known test failures in `test_runner/known_failures.txt`, each with a reason. This list may only shrink.

## Checks

The gate for every PR is `.github/scripts/ci-local.sh`: lint (self-tests, actionlint, fmt, clippy, cargo deny, ruff, mypy), build, and the Rust tests. It runs on a developer machine inside the same `ghcr.io/chelabase/neon-build-tools` image as `.github/workflows/pr.yml` (pulling the image needs no login: the GHCR packages are public), with caches in the Docker volumes `chela-neon-cargo` and `chela-neon-target` and logs under `.ci-local/` (git-ignored). Use `--pg v14|v15|v16` for the older majors.

GitHub CI is manual-only, as standing policy: `pr.yml` is `workflow_dispatch` only, and branch protection on `main` requires a PR but no status check. `images.yml` runs only for `v*` tags and the platform images, by hand.

Neon's pytest regression suite is opt-in and required for no PR: `ci-local.sh --regress [-k <expr>] [-n <workers>]` runs it for a targeted check, for example to debug one test. When an image changes, chelabase's own e2e covers the parts we use. The regression run deselects `test_runner/known_failures.txt` (fails on GitHub's runners too) and `test_runner/known_failures.local.txt` (fails only in the local run); both use the `<nodeid>  # <reason>` format and may only shrink.

Quick mode, for patch work: `ci-local.sh --only build,rust-tests,regress` runs just the listed steps (in pipeline order, lint skipped; `regress` implies `--regress`), and `--test-filter <nextest expr>` (needs `rust-tests` in `--only`) narrows `cargo nextest run` with `-E`, ANDed with the quarantine filter. `CHELA_NEON_VOLUME_SUFFIX=<suffix>` (`^[a-z0-9-]+$`) switches to the volumes `chela-neon-cargo-<suffix>` and `chela-neon-target-<suffix>`, so parallel clones keep separate build state and stamps.

## Publishing dev images

The Postgres 17 dev images are built on a developer machine and pushed from there (the GitHub job took 111 minutes): `.github/scripts/publish-dev.sh [--no-push] [--only storage|compute]` builds `ghcr.io/chelabase/neon-storage:<sha12>-dev` and `ghcr.io/chelabase/neon-compute-v17:<sha12>-dev` from the checked-out commit (`<sha12>` = chelabase's `neon_tag`), runs `image_variant_test.sh` on the storage image, and only then pushes. It needs a clean tree at a commit on `origin/main`, initialised submodules, and `docker login ghcr.io` for the push (the packages are public: pulling needs no login, pushing does), and it refuses to overwrite an existing tag without `--force-retag`. The images carry no SBOM or provenance attestations. `images.yml` stays for `v*` tags and the platform images, run by hand; its dev jobs remain as a manual fallback (`variant=dev`) but fail when `<sha12>-dev` already exists unless the `force_retag` input is true, so a CI run cannot retag a locally published image. After a push, pin the printed `...:<sha12>-dev@sha256:<digest>` references in chelabase as the Compose defaults of `NEON_IMAGE` (storage) and `COMPUTE_NODE_IMAGE` (compute), then run chelabase's e2e against them.

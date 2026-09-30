# Contributing to Guard Agent PHP

Thanks for considering a contribution to Guard Agent PHP, part of the Guard ecosystem (this repo follows the conventions of the Python baseline: guard-core and fastapi-guard).

## Development Setup

Requirements:

- PHP ^8.2 (the library supports 8.2, 8.3, and 8.4)
- Composer 2
- Docker (Redis runs as a CI service locally too, via `docker run -p 6379:6379 redis:7-alpine`; hosts without a PHP toolchain run everything through the `php:8.3-cli` and `composer:2` images, see the Makefile)

```bash
composer install
composer test          # the repo's test suite (bin/test_*.php)
composer lint          # syntax sweep over src/ and bin/
```

## Quality Gates

Run before pushing (CI enforces the same checks):

- `composer lint` (php -l sweep over src and bin)
- the test suite (`composer test`, Redis needed for the guard suites)
- `composer audit` (dependency vulnerability check, also on the weekly schedule)

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).

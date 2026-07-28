# Contributing to BrowseWeave

BrowseWeave welcomes focused bug fixes, tests, documentation improvements, and compatibility work.

## Before opening a change

- Use Node.js 22.14 or newer.
- Search existing issues before creating a new one.
- Keep changes limited to one problem.
- Never include pairing secrets, npm tokens, screenshots of private pages, credentials, or personal browsing data.
- Report vulnerabilities through GitHub private vulnerability reporting, not a public issue.

BrowseWeave will not accept CAPTCHA solving, fingerprint spoofing, proxy rotation, stealth claims, security-control bypasses, or code that silently closes user-owned tabs.

## Local checks

```bash
npm ci --ignore-scripts
npm run verify:release
```

For browser-specific work, state the exact operating system, browser name/version, extension target, and MCP client you tested. A build or headless test is not evidence that a native service or browser flow works.

## Architecture boundaries

Read `docs/ARCHITECTURE.md` before adding a source module. Keep the four Node.js and four extension root files as thin executable facades, place implementation code in the declared domain directories, and preserve inward-only dependency direction. `npm run check:architecture` rejects undeclared folders, cross-layer imports, dependency cycles, missing relative modules, oversized facades, and extension access outside the shared protocol/version contract.

## Maintainer releases

Do not keep npm authentication active while installing dependencies, building, testing, or running tagged package scripts. The reviewed first-publication bootstrap refuses that state, prepares one fixed tarball and removes its detached git worktree before asking for an isolated interactive npm login, publishes only that tarball, and automatically logs out and proves the temporary credential inactive. If that final proof fails, revoke the newest token in npm's Access Tokens page. Configure the repository's npm trusted publisher immediately afterward. All later releases must use the reviewed GitHub OIDC workflow.

## Pull requests

Explain the user-visible problem, the chosen fix, and the evidence. Add or update tests for behavior changes. Keep public text in clear English and preserve the security and privacy boundaries in `SECURITY.md`.

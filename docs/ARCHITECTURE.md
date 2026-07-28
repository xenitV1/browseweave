# BrowseWeave architecture

BrowseWeave uses two explicit, acyclic module graphs: the local Node.js runtime and the browser extension. The files at each source root are executable facades only. Product logic belongs in a named module directory.

## Server/runtime modules

```text
src/
├── cli.ts, daemon.ts, mcp.ts, native-host.ts  executable facades
├── core/       protocol, configuration, and version contracts
├── bridge/     authenticated IPC client and setup status parsing
├── clients/    MCP client configuration and trusted executable discovery
├── native/     native messaging, service plans, install guards, and cleanup
├── setup/      browser discovery, setup page flow, and platform integration
├── daemon/     WebSocket/IPC orchestration and browser session runtime
├── mcp/        MCP schemas, tools, and stdio server composition
└── cli/        command parsing and user-facing workflow orchestration
```

Dependencies point inward. `core` has no product-module dependency. `bridge`, `clients`, and `setup` depend only on their own module and their declared lower-level contracts. `native`, `daemon`, and `mcp` compose those lower layers. Only `cli` may orchestrate all server modules.

## Extension modules

```text
extension/src/
├── background.ts, content.ts, popup.ts, options.ts  bundle facades
├── shared/      DOM-independent helpers and common page utilities
├── security/    credentials, approvals, and authenticated handshakes
├── setup/       guided and native setup protocols
├── background/  privileged extension runtime composition
├── content/     page-bound automation runtime composition
└── ui/          popup and settings views
```

The extension may share only `src/core/protocol.ts` and `src/core/version.ts` with the Node.js runtime. It cannot import daemon, filesystem, native-host, client-configuration, or setup implementation modules.

## Stable public surface

The npm executable and module paths remain stable:

- `dist/src/cli.js`
- `dist/src/daemon.js`
- `dist/src/mcp.js`
- `dist/src/native-host.js`

Those files delegate to nested implementation modules. Consumers should use the documented commands rather than importing internal paths.

## Enforcement

`npm run check:architecture` validates the exact module directories, thin entrypoint facades, allowed dependency directions, shared extension contracts, source-file budgets, missing relative imports, and cycles. It runs before every build, so CI and release packaging cannot silently return to the former flat structure.

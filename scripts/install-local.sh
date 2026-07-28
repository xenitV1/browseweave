#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'BrowseWeave install error: %s\n' "$*" >&2
  exit 1
}

if (( EUID == 0 )); then
  die "run this command from your normal user account, not as root"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(cd -- "${script_dir}/.." && pwd -P)"
local_cli="${project_dir}/dist/src/cli.js"

if command -v node >/dev/null 2>&1 && [[ -f "${local_cli}" && ! -L "${local_cli}" ]]; then
  node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 14) ? 0 : 1)' || \
    die "Node.js 22.14.0 or newer is required"
  exec node "${local_cli}" local-install
fi

if command -v browseweave >/dev/null 2>&1; then
  exec browseweave local-install
fi

die "BrowseWeave is not built or installed. Run 'npm install && npm run build' here, or install the global package first."

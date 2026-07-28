#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'BrowseWeave uninstall error: %s\n' "$*" >&2
  exit 1
}

if (( EUID == 0 )); then
  die "run this command from your normal user account, not as root"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(cd -- "${script_dir}/.." && pwd -P)"
local_cli="${project_dir}/dist/src/cli.js"

if command -v node >/dev/null 2>&1 && [[ -f "${local_cli}" && ! -L "${local_cli}" ]]; then
  exec node "${local_cli}" local-uninstall
fi

if command -v browseweave >/dev/null 2>&1; then
  exec browseweave local-uninstall
fi

die "BrowseWeave is not built or installed. No service or user data was changed."

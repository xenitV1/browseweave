#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'BrowseWeave setup error: %s\n' "$*" >&2
  exit 1
}

if (( EUID == 0 )); then
  die "run this command from your normal user account, not as root"
fi

if [[ ! -t 0 || ! -t 1 ]]; then
  die "run this script in a visible interactive terminal so browser approval remains yours"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(cd -- "${script_dir}/.." && pwd -P)"

command -v node >/dev/null 2>&1 || die "Node.js 22.14.0 or newer is required"
command -v npm >/dev/null 2>&1 || die "npm is required"
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 14) ? 0 : 1)' || \
  die "Node.js 22.14.0 or newer is required"

[[ -f "${project_dir}/package.json" && -f "${project_dir}/package-lock.json" ]] || \
  die "run the script from a complete BrowseWeave source checkout"

cd -- "${project_dir}"
printf 'Installing the exact source dependencies…\n'
npm ci --ignore-scripts
printf 'Building BrowseWeave and both extension packages…\n'
npm run build
exec node dist/src/cli.js setup --from-source --all-browsers "$@"

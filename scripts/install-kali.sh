#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly INSTALL_BIN_DIR="${HOME}/.local/bin"
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROVIDER="openai"
DRY_RUN=false
FORCE=false
CONFIGURE=false

usage() {
  cat <<EOF
Install react-recon and its validated reconnaissance tools on Kali Linux.

Usage: ${SCRIPT_NAME} [OPTIONS]

Options:
  --provider VALUE  Model SDK to install: openai, anthropic, both, or none
                    (default: openai)
  --dry-run         Print the planned commands without changing the system
  --force           Reinstall the pinned Go reconnaissance binaries
  --configure       Interactively create a protected .env for LLM analysis
  -h, --help        Show this help text

The script uses sudo only for apt, installs user-owned binaries under
~/.local/bin, and requests an API key only when --configure is supplied.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

quote_command() {
  printf '%q ' "$@"
  printf '\n'
}

run() {
  if [[ "${DRY_RUN}" == true ]]; then
    printf '+ '
    quote_command "$@"
    return 0
  fi
  "$@"
}

while (($#)); do
  case "$1" in
    --provider)
      (($# >= 2)) || die "--provider requires a value"
      PROVIDER="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --configure)
      CONFIGURE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "${PROVIDER}" in
  openai|anthropic|both|none) ;;
  *) die "unsupported provider '${PROVIDER}'; use openai, anthropic, both, or none" ;;
esac

if [[ "${CONFIGURE}" == true && "${PROVIDER}" == "none" ]]; then
  die "--configure requires --provider openai, anthropic, or both"
fi

cd "${REPO_ROOT}"

# A dry run is intentionally portable so maintainers can test the installer on
# CI and non-Kali development hosts without invoking apt.
if [[ "${DRY_RUN}" != true ]]; then
  [[ "${EUID}" -ne 0 ]] || die "run this script as a normal user; it invokes sudo only for apt"
  [[ -r /etc/os-release ]] || die "cannot identify the operating system"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "kali" ]] || die "this installer supports Kali Linux; detected '${ID:-unknown}'"
  command -v sudo >/dev/null 2>&1 || die "sudo is required for apt package installation"
fi

printf 'Installing Kali prerequisites...\n'
run sudo apt-get update
run sudo apt-get install -y ca-certificates curl git golang-go nmap

run mkdir -p "${INSTALL_BIN_DIR}"
export PATH="${INSTALL_BIN_DIR}:${PATH}"
export GOBIN="${INSTALL_BIN_DIR}"

if [[ "${DRY_RUN}" == true ]] || ! command -v uv >/dev/null 2>&1 || [[ "${FORCE}" == true ]]; then
  if [[ "${DRY_RUN}" == true ]]; then
    printf '+ curl -LsSf https://astral.sh/uv/install.sh -o TEMP_FILE\n'
    printf '+ env UV_INSTALL_DIR=%q sh TEMP_FILE\n' "${INSTALL_BIN_DIR}"
  else
    uv_installer="$(mktemp)"
    trap 'rm -f "${uv_installer}"' EXIT
    curl -LsSf https://astral.sh/uv/install.sh -o "${uv_installer}"
    env UV_INSTALL_DIR="${INSTALL_BIN_DIR}" sh "${uv_installer}"
  fi
else
  printf 'Using existing uv: %s\n' "$(command -v uv)"
fi

install_go_tool() {
  local binary="$1"
  local module="$2"
  local installed_path="${INSTALL_BIN_DIR}/${binary}"

  if [[ "${DRY_RUN}" != true && -x "${installed_path}" && "${FORCE}" != true ]]; then
    printf 'Using existing %s: %s\n' "${binary}" "${installed_path}"
    return 0
  fi
  run env GOBIN="${INSTALL_BIN_DIR}" go install "${module}"
}

printf 'Installing validated reconnaissance binaries...\n'
install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0
install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0
install_go_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1
install_go_tool gau github.com/lc/gau/v2/cmd/gau@v2.2.4

sync_args=(sync --extra test)
case "${PROVIDER}" in
  openai) sync_args+=(--extra openai) ;;
  anthropic) sync_args+=(--extra anthropic) ;;
  both) sync_args+=(--extra all-models) ;;
  none) ;;
esac

printf 'Installing react-recon...\n'
run uv "${sync_args[@]}"

if [[ "${CONFIGURE}" == true ]]; then
  printf 'Configuring optional LLM analysis...\n'
  if [[ "${DRY_RUN}" == true ]]; then
    printf '+ %q --provider %q\n' "${REPO_ROOT}/scripts/configure-provider.sh" "${PROVIDER}"
  else
    "${REPO_ROOT}/scripts/configure-provider.sh" --provider "${PROVIDER}"
    # The generated file contains shell-escaped values and is safe to load for
    # the non-networking preflight check performed below.
    set -a
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.env"
    set +a
  fi
fi

printf 'Validating the installation...\n'
run uv run react-recon preflight
run uv run pytest

cat <<EOF

Installation complete.

Ensure this line is present in your shell profile before opening a new shell:
  export PATH="\$HOME/.local/bin:\$PATH"

Collection works without an API key. If analysis was configured, load its
settings in each new shell with: set -a; source .env; set +a
EOF

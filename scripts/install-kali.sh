#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly INSTALL_BIN_DIR="${HOME}/.local/bin"
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly UV_VERSION="0.12.7"
readonly UV_X86_64_SHA256="788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21"
readonly UV_AARCH64_SHA256="66393193038dd7eb108abd7a218d9cec04ac70ab98242b0720fa94de19223b7c"

PROVIDER="openai"
DRY_RUN=false
FORCE=false
CONFIGURE=false

# Provider credentials are not inputs to apt, Go builds, preflight, or tests.
# Remove inherited values before any child process is started; optional model
# configuration happens at the very end in a separate masked prompt.
unset OPENAI_API_KEY ANTHROPIC_API_KEY

usage() {
  cat <<EOF
Install react-recon and its validated reconnaissance tools on Kali Linux.

Usage: ${SCRIPT_NAME} [OPTIONS]

Options:
  --provider VALUE  Model SDK to install: openai, anthropic, both, or none
                    (default: openai)
  --dry-run         Print the planned commands without changing the system
  --force           Reinstall pinned uv and Go reconnaissance binaries
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

require_command() {
  local command_name="$1"
  local remediation="$2"

  command -v "${command_name}" >/dev/null 2>&1 || die "${command_name} is required. ${remediation}"
}

require_go_version() {
  local minimum_minor="25"
  local version_output version major minor
  version_output="$(go version)" || die "could not determine the installed Go version"
  version="$(printf '%s\n' "${version_output}" | /usr/bin/sed -n 's/.* go\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p')"
  read -r major minor <<<"${version}"
  [[ -n "${major:-}" && -n "${minor:-}" ]] || die "could not parse Go version from: ${version_output}"
  if ((major < 1 || (major == 1 && minor < minimum_minor))); then
    die "Go 1.${minimum_minor}+ is required by the pinned dnsx release; found Go ${major}.${minor}. Install a current Go toolchain and rerun the installer."
  fi
}

verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual checksum_output

  if [[ -x /usr/bin/sha256sum ]]; then
    checksum_output="$(/usr/bin/sha256sum -- "${file}")" || die "could not calculate SHA-256 for ${file}"
  elif [[ -x /usr/bin/shasum ]]; then
    # macOS uses shasum for local fixture validation; Kali supplies
    # /usr/bin/sha256sum through the explicitly installed coreutils package.
    checksum_output="$(/usr/bin/shasum -a 256 -- "${file}")" || die "could not calculate SHA-256 for ${file}"
  else
    die "a trusted system SHA-256 utility is required to verify the uv release"
  fi
  actual="${checksum_output%% *}"
  [[ "${actual}" == "${expected}" ]] || die "SHA-256 verification failed for ${file}"
}

select_uv_release() {
  case "$1" in
    x86_64|amd64) printf '%s %s\n' "x86_64-unknown-linux-gnu" "${UV_X86_64_SHA256}" ;;
    aarch64|arm64) printf '%s %s\n' "aarch64-unknown-linux-gnu" "${UV_AARCH64_SHA256}" ;;
    *) die "unsupported architecture for pinned uv release: $1" ;;
  esac
}

install_pinned_uv() (
  local architecture release target expected_sha256 asset url temporary_dir archive

  architecture="$(/usr/bin/uname -m)"
  release="$(select_uv_release "${architecture}")" || exit 1
  read -r target expected_sha256 <<<"${release}"

  asset="uv-${target}.tar.gz"
  url="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${asset}"
  temporary_dir="$(/usr/bin/mktemp -d)"
  archive="${temporary_dir}/${asset}"

  cleanup_uv_download() {
    /bin/rm -f -- "${archive}" "${temporary_dir}/uv-${target}/uv" "${temporary_dir}/uv-${target}/uvx"
    /bin/rmdir -- "${temporary_dir}/uv-${target}" "${temporary_dir}" 2>/dev/null || true
  }
  trap cleanup_uv_download EXIT

  /usr/bin/curl -LsSf "${url}" -o "${archive}"
  verify_sha256 "${archive}" "${expected_sha256}"
  /usr/bin/tar -xzf "${archive}" -C "${temporary_dir}" "uv-${target}/uv" "uv-${target}/uvx"
  /usr/bin/install -m 0755 "${temporary_dir}/uv-${target}/uv" "${INSTALL_BIN_DIR}/uv"
  /usr/bin/install -m 0755 "${temporary_dir}/uv-${target}/uvx" "${INSTALL_BIN_DIR}/uvx"
)

main() {
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
run sudo apt-get install -y ca-certificates coreutils curl git golang-go nmap tar

if [[ "${DRY_RUN}" == true ]]; then
  printf '+ verify go 1.25 or newer is installed and available in PATH\n'
else
  require_command go "Install a supported Go toolchain, ensure go is available in PATH, then rerun this installer."
  require_go_version
fi

run mkdir -p "${INSTALL_BIN_DIR}"
export PATH="${INSTALL_BIN_DIR}:${PATH}"
export GOBIN="${INSTALL_BIN_DIR}"

if [[ "${DRY_RUN}" == true ]] || ! command -v uv >/dev/null 2>&1 || [[ "${FORCE}" == true ]]; then
  if [[ "${DRY_RUN}" == true ]]; then
    printf '+ download uv %s release archive for x86_64 or aarch64 Linux\n' "${UV_VERSION}"
    printf '+ verify archive SHA-256 against pinned architecture digest\n'
    printf '+ install verified uv and uvx into %q\n' "${INSTALL_BIN_DIR}"
  else
    install_pinned_uv
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
install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0
install_go_tool alterx github.com/projectdiscovery/alterx/cmd/alterx@v0.1.0
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

printf 'Validating the installation...\n'
run uv run react-recon preflight
run uv run pytest

# Collect credentials only after every installer, dependency, preflight, and
# test process has exited. The generated file is never sourced by this script,
# so provider keys cannot leak into unrelated validation subprocesses.
if [[ "${CONFIGURE}" == true ]]; then
  printf 'Configuring optional LLM analysis...\n'
  if [[ "${DRY_RUN}" == true ]]; then
    printf '+ %q --provider %q\n' "${REPO_ROOT}/scripts/configure-provider.sh" "${PROVIDER}"
  else
    "${REPO_ROOT}/scripts/configure-provider.sh" --provider "${PROVIDER}"
  fi
fi

cat <<EOF

Installation complete.

Ensure this line is present in your shell profile before opening a new shell:
  export PATH="\$HOME/.local/bin:\$PATH"

Collection works without an API key. If analysis was configured, load its
settings in each new shell with: set -a; source .env; set +a
EOF
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

# Installation

## Supported environment

The tested development environment is macOS on Apple Silicon with Python 3.14. The package declares Python 3.11+ and CI tests Python 3.11, 3.12, and 3.13 on Linux. Linux and WSL2 should use the same `uv` and Go-based installation flow.

Native Windows without WSL2 has not been validated.

### Kali Linux bootstrap

From a cloned repository, the idempotent installer can install the system
prerequisites, pinned reconnaissance binaries, Python environment, and selected
model-provider SDK:

```bash
./scripts/install-kali.sh --provider openai
```

To optionally choose a model and enter the matching API key during setup, add
`--configure`. The key prompt is masked, no API request is made, and the local
`.env` file is created with mode `600`:

```bash
./scripts/install-kali.sh --provider openai --configure
```

Available providers are `openai`, `anthropic`, `both`, and `none`. Review the
planned commands without changing the system:

```bash
./scripts/install-kali.sh --provider openai --dry-run
```

The script must be run as a normal user. It uses `sudo` only for `apt`, places
Go and uv binaries in `~/.local/bin`, and does not configure Docker, Linux
capabilities, or shell profiles. API-key configuration occurs only with
`--configure`. Use `--force` only when you intend to reinstall pinned uv and
the validated Go-tool versions. The bootstrap pins uv `0.12.7` and verifies the official
architecture-specific SHA-256 digest before installing `uv` or `uvx`; an
unknown architecture or digest mismatch stops installation.

After `apt` completes, the installer verifies that `go` is available in
`PATH`. If Go installation failed or the executable cannot be resolved, setup
stops before installing any reconnaissance tools and prints an actionable error.

## 1. Install system prerequisites

### macOS with Homebrew

```bash
brew install uv go
```

Install Docker Desktop if you want the Nmap fallback. Native Nmap is also supported:

```bash
brew install nmap
```

### Debian, Ubuntu, or WSL2

Install Python 3.11+, Go, Git, and optionally Nmap/Docker using your distribution's supported packages. Install `uv` from its official documentation, then confirm:

```bash
python3 --version
go version
uv --version
```

## 2. Install reconnaissance binaries

The host-binary path is the most predictable installation method:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

Ensure Go's binary directory is in `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

Versions validated during the initial alpha build:

| Tool | Validated version |
| --- | --- |
| Subfinder | 2.16.0 |
| dnsx | 1.2.3 |
| httpx | 1.10.0 |
| Naabu | 2.6.1 |
| gau | 2.2.4 |
| Nmap Docker image | `instrumentisto/nmap:latest` reporting Nmap 7.98 |

The versions are compatibility evidence, not mandatory pins. Run the fixture suite after upgrading a tool because command flags and JSON schemas can change.

Nmap service fingerprinting prefers a host `nmap` binary. If it is absent and Docker is running, the controller uses `instrumentisto/nmap:latest`. ProjectDiscovery collectors can use their Docker images when the host binary is unavailable. gau should be installed as a host binary unless you explicitly configure and validate another image.

## 3. Install react-recon

```bash
git clone https://github.com/KonTr3versy/react-recon.git
cd react-recon
uv sync --extra openai --extra test
```

Validate the package and external tools:

```bash
uv run react-recon --help
uv run react-recon preflight
uv run pytest
```

## 4. Configure model analysis

Collection works without a model-provider key. Install the provider you intend to use:

```bash
uv sync --extra openai
uv sync --extra anthropic
# Or install both:
uv sync --extra all-models
```

To enable the post-run targeting brief:

```bash
cp .env.example .env
chmod 600 .env
```

Set `REACT_RECON_AI_PROVIDER`, `REACT_RECON_AI_MODEL`, and the matching `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in `.env`, then load it into the current shell:

```bash
set -a
source .env
set +a
```

Do not commit `.env`, shell history containing a key, assessment databases, evidence, or reports.

See [Model providers](MODEL_PROVIDERS.md) for provider-specific commands and defaults.

## Troubleshooting

If `preflight` reports a missing binary, confirm the correct path first:

```bash
command -v subfinder dnsx httpx naabu gau
go env GOPATH
```

If Nmap fallback fails, verify Docker is running and the image can be inspected:

```bash
docker image inspect instrumentisto/nmap:latest
```

Tool failures are recorded as collection failures. They do not mean the target lacks the tested service or exposure.

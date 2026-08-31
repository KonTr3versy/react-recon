# Security policy

## Intended use

`react-recon` is intended for authorized reconnaissance and analyst support. Operators are responsible for written authorization, accurate scope, timing restrictions, rate limits, evidence handling, and applicable law.

The project deliberately excludes exploitation, credential attacks, phishing, persistence, post-exploitation, arbitrary shell tools, and model-generated commands.

## Sensitive data

Run databases, evidence, reports, `.env` files, and API keys must not be committed. The repository's `.gitignore` excludes the standard local paths, but operators must review staged files before every commit.

The optional `analyze` command sends normalized reconnaissance context to the selected OpenAI or Anthropic API. Do not use it when client terms prohibit external processing. Passive/active collection, reprocessing, and deterministic report generation do not require an API key.

## Reporting a vulnerability

Do not open a public issue containing API keys, target data, client evidence, or a working exploit against a deployed operator environment. Use GitHub's private vulnerability reporting feature if it is enabled for the repository. Otherwise, contact the repository owner through a private channel listed on their GitHub profile.

Include the affected version, impact, reproduction conditions, and a sanitized proof of concept. Maintainers should acknowledge a report before public disclosure.

## Execution boundary

Changes to scope validation, subprocess construction, Docker mounts, evidence paths, reprocessing, or the model/tool boundary require focused tests. Never introduce `shell=True`, arbitrary command arguments, unrestricted filesystem paths, or automatic scope expansion.

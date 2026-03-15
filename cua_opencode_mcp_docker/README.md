# cua_opencode_mcp_docker

## Introduction

`cua_opencode_mcp_docker` is a thin wrapper around the official `cua-mcp-server` package.

The stock local MCP server currently instantiates `Computer()` with its default backend, which is not a good fit for a Linux host that should run CUA inside a Docker sandbox. This wrapper keeps the official MCP server implementation, but replaces its session `ComputerPool` with a Docker-backed pool so each session starts an isolated Linux desktop container based on `trycua/cua-ubuntu:latest`.

In short, this script gives OpenCode a practical local CUA MCP server on Linux without patching the installed upstream package.

## Get Started

### 1. Prerequisites

- Docker must be installed and running.
- The official `cua-mcp-server` package must already be installed.
- A supported model provider key must be available through environment variables.
- If you use `omniparser+...`, install `cua-som` into the same Python environment as `cua-mcp-server`.

Example setup:

```bash
uv python install 3.12
uv tool install --python 3.12 cua-mcp-server
uv pip install --python ~/.local/share/uv/tools/cua-mcp-server/bin/python cua-som
docker pull --platform=linux/amd64 trycua/cua-ubuntu:latest
```

### 2. Add it to OpenCode

An example config is included at `opencode.example.json`.

Example `opencode.json` snippet:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "cua": {
      "type": "local",
      "command": [
        "/root/batch-process-scripts/cua_opencode_mcp_docker/cua_mcp_server_docker.py"
      ],
      "enabled": true,
      "timeout": 600000,
      "environment": {
        "CUA_MODEL_NAME": "omniparser+openai/rightcode/gpt-5.4",
        "OPENAI_API_KEY": "{env:OPENAI_API_KEY}",
        "OPENAI_BASE_URL": "{env:OPENAI_BASE_URL}",
        "CUA_SANDBOX_OS": "linux",
        "CUA_DOCKER_IMAGE": "trycua/cua-ubuntu:latest",
        "CUA_DOCKER_EPHEMERAL": "true",
        "CUA_TELEMETRY_ENABLED": "false"
      }
    }
  }
}
```

### 3. Verify the connection

```bash
opencode mcp list
```

You should see the `cua` server in the `connected` state.

If you want a starting point without embedded secrets, copy `opencode.example.json` and replace the model/provider environment entries to match your setup.

### 4. OpenAI-compatible endpoints and `cliproxy-codex`

If your target model is exposed through an OpenAI-compatible API, keep the provider prefix in the composed model string. For example:

```json
{
  "CUA_MODEL_NAME": "omniparser+openai/rightcode/gpt-5.4",
  "OPENAI_API_KEY": "{env:OPENAI_API_KEY}",
  "OPENAI_BASE_URL": "{env:OPENAI_BASE_URL}"
}
```

For a local OpenCode setup that already has a `cliproxy-codex` provider block, use the same endpoint and key values for the `mcp.cua.environment` section. Do not commit those literal values into source control; keep them in shell environment variables or a machine-local OpenCode config.

## Parameter Configuration

The wrapper reads the following environment variables.

### Required in practice

- `CUA_MODEL_NAME`: The model string used by CUA. This can be a single model such as `openai/computer-use-preview`, or a composed model such as `omniparser+openai/gpt-4o`.
- Provider credentials for the selected model, for example:
  - `OPENAI_API_KEY`
  - `ANTHROPIC_API_KEY`
  - `OPENROUTER_API_KEY`
  - `OPENAI_BASE_URL` for OpenAI-compatible endpoints

For `omniparser+openai/rightcode/gpt-5.4`, the minimum practical set is:

- `CUA_MODEL_NAME=omniparser+openai/rightcode/gpt-5.4`
- `OPENAI_API_KEY=...`
- `OPENAI_BASE_URL=...`

### Wrapper-specific parameters

| Variable | Default | Description |
| --- | --- | --- |
| `CUA_SANDBOX_OS` | `linux` | Target OS passed to `Computer(...)`. This wrapper is intended for Linux sandboxes. |
| `CUA_DOCKER_IMAGE` | `trycua/cua-ubuntu:latest` | Docker image used for the sandbox. |
| `CUA_DOCKER_NAME` | `opencode-cua-docker` | Prefix used when generating container names. A short random suffix is appended automatically. |
| `CUA_DOCKER_HOST` | `localhost` | Host used by the computer interface after the container is started. |
| `CUA_DOCKER_API_PORT` | auto-selected | Fixed host API port for the container. If unset, the wrapper picks a free local port. |
| `CUA_DOCKER_VNC_PORT` | auto-selected | Fixed host VNC/noVNC port. If unset, the wrapper picks a free local port. |
| `CUA_DOCKER_MEMORY` | `8GB` | Memory passed to the Docker-backed `Computer(...)`. |
| `CUA_DOCKER_CPU` | `4` | CPU count passed to the Docker-backed `Computer(...)`. |
| `CUA_DOCKER_EPHEMERAL` | `true` | If `true`, containers are disposable and are removed after stop. |
| `CUA_TELEMETRY_ENABLED` | `false` | Enables or disables CUA telemetry. The wrapper defaults it to `false`. |
| `CUA_MAX_IMAGES` | upstream default | Standard official CUA setting that controls how many screenshots stay in context. |

## Notes

- This wrapper does not replace the official MCP server logic. It imports the installed `cua-mcp-server` package and only swaps out the session pool implementation.
- The wrapper is Linux-oriented because it forces `provider_type=DOCKER` and `os_type=linux` by default.
- If you need a composed model, set it directly in `CUA_MODEL_NAME`. Example values:
  - `omniparser+openai/rightcode/gpt-5.4`
  - `omniparser+openai/gpt-4o`
  - `moondream3+anthropic/claude-sonnet-4-5-20250929`
  - `huggingface-local/HelloKKMe/GTA1-7B+anthropic/claude-sonnet-4-5-20250929`
- Some composed modes need extra dependencies beyond the base `cua-mcp-server` install. For example, `omniparser+...` typically requires `cua-som`.

## Troubleshooting

- `Connection closed` during MCP startup:
  - Make sure `cua-mcp-server` is installed in the Python environment referenced by the shebang.
  - Run the script directly to inspect stderr output.
- Docker sandbox fails to boot:
  - Confirm Docker is running.
  - Confirm the image can be pulled: `docker pull --platform=linux/amd64 trycua/cua-ubuntu:latest`
- Task execution fails after MCP connects:
  - Check that `CUA_MODEL_NAME` and the matching provider credentials are set.
  - If using an OpenAI-compatible endpoint, confirm `OPENAI_BASE_URL` and `OPENAI_API_KEY` are correct.
  - If using `omniparser+...`, confirm `cua-som` is installed in the same Python environment as `cua-mcp-server`.

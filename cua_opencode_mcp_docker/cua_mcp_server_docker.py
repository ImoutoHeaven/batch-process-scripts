#!/root/.local/share/uv/tools/cua-mcp-server/bin/python
import asyncio
import importlib
import logging
import os
import socket
import uuid
from typing import Any

os.environ.setdefault("CUA_TELEMETRY_ENABLED", "false")

from computer import Computer
from computer.providers.base import VMProviderType

cua_server = importlib.import_module("mcp_server.server")
cua_sessions = importlib.import_module("mcp_server.session_manager")


def env_bool(key: str, default: bool) -> bool:
    value = os.getenv(key)
    if value is None or value == "":
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def env_int(key: str, default: int) -> int:
    value = os.getenv(key)
    if value is None or value == "":
        return default
    return int(value)


def pick_port(env_key: str, fallback: int) -> int:
    value = os.getenv(env_key)
    if value:
        return int(value)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    return port or fallback


class DockerComputerPool(cua_sessions.ComputerPool):
    def __init__(self, max_size: int = 1, idle_timeout: float = 300.0):
        super().__init__(max_size=max_size, idle_timeout=idle_timeout)

    async def acquire(self) -> Any:
        if self._available:
            computer = self._available.pop()
            self._in_use.add(computer)
            logging.getLogger("cua-mcp-docker").debug("Reusing pooled Docker sandbox")
            return computer

        async with self._creation_lock:
            if len(self._in_use) < self.max_size:
                base_name = os.getenv("CUA_DOCKER_NAME", "opencode-cua-docker")
                sandbox_name = f"{base_name}-{uuid.uuid4().hex[:8]}"
                api_port = pick_port("CUA_DOCKER_API_PORT", 18000)
                vnc_port = pick_port("CUA_DOCKER_VNC_PORT", 18006)
                logging.getLogger("cua-mcp-docker").info(
                    "Starting Docker sandbox %s on api=%s vnc=%s",
                    sandbox_name,
                    api_port,
                    vnc_port,
                )
                computer = Computer(
                    os_type=os.getenv("CUA_SANDBOX_OS", "linux"),
                    provider_type=VMProviderType.DOCKER,
                    image=os.getenv("CUA_DOCKER_IMAGE", "trycua/cua-ubuntu:latest"),
                    name=sandbox_name,
                    host=os.getenv("CUA_DOCKER_HOST", "localhost"),
                    api_port=api_port,
                    noVNC_port=vnc_port,
                    memory=os.getenv("CUA_DOCKER_MEMORY", "8GB"),
                    cpu=os.getenv("CUA_DOCKER_CPU", "4"),
                    ephemeral=env_bool("CUA_DOCKER_EPHEMERAL", True),
                    verbosity=logging.INFO,
                    telemetry_enabled=env_bool("CUA_TELEMETRY_ENABLED", False),
                )
                await computer.run()
                self._in_use.add(computer)
                return computer

        while not self._available:
            await asyncio.sleep(0.1)

        computer = self._available.pop()
        self._in_use.add(computer)
        return computer


setattr(cua_sessions, "ComputerPool", DockerComputerPool)


if __name__ == "__main__":
    cua_server.main()

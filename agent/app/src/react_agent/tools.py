"""This module provides example tools.

These tools are intended as free examples to get started. For production use,
consider implementing more robust and specialized tools tailored to your needs.
"""

from typing import Any, Callable, List
import asyncio
import json
from langchain_mcp_adapters.client import MultiServerMCPClient

MCP_FILE = "mcp.json"


def read_config_file() -> dict:
    config = {}
    with open(MCP_FILE, "r") as f:
        tools_spec = f.read()
        tools_json = json.loads(tools_spec)
        config = tools_json["mcpServers"] or config
    return config


config = read_config_file()

client = MultiServerMCPClient(config)

tools = asyncio.run(client.get_tools())

TOOLS: List[Callable[..., Any]] = tools

"""MCP server exposing the five integrity primitives over stdio.

Note: there is deliberately NO delete / shell / arbitrary-write tool (least privilege).
"""
from mcp.server.fastmcp import FastMCP

import tools

mcp = FastMCP("file-integrity")


@mcp.tool()
def list_directory(path: str) -> dict:
    """Recursively list files (size and modified time) in a directory inside the workspace."""
    return tools.list_directory(path)


@mcp.tool()
def hash_directory(path: str) -> dict:
    """Compute SHA-256 digests for every non-excluded file in a directory using native sha256sum."""
    return tools.hash_directory(path)


@mcp.tool()
def read_json_state(path: str) -> dict:
    """Read the stored baseline manifest (.integrity_manifest.json) for a directory. Read-only."""
    return tools.read_json_state(path)


@mcp.tool()
def write_snapshot(path: str) -> dict:
    """Create or overwrite the baseline manifest for a directory. STATE-CHANGING: requires operator approval."""
    return tools.write_snapshot(path)


@mcp.tool()
def compare_diffs(path: str) -> dict:
    """Hash the directory now and compare against the stored baseline; returns added, modified and removed files."""
    return tools.compare_diffs(path)


if __name__ == "__main__":
    mcp.run()

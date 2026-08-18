from __future__ import annotations

from importlib.resources import as_file, files

from .invariants import DeclarativeInvariantEngine, load_invariants
from .policy import Policy, load_policy
from .mcp import MCPProfile, load_mcp_profile


def load_default_policy() -> Policy:
    resource = files("vais.data").joinpath("default_policy.yaml")
    with as_file(resource) as path:
        return load_policy(path)


def load_default_invariants() -> DeclarativeInvariantEngine:
    resource = files("vais.data").joinpath("default_invariants.yaml")
    with as_file(resource) as path:
        return load_invariants(path)


def load_example_mcp_profile() -> MCPProfile:
    resource = files("vais.data").joinpath("mcp_example_profile.yaml")
    with as_file(resource) as path:
        return load_mcp_profile(path)

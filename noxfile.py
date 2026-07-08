from __future__ import annotations

import os
from pathlib import Path

import nox

DIR = Path(__file__).parent.resolve()

nox.needs_version = ">=2024.3.2"
# Typing `nox` with no arguments will automatically run these two sessions
nox.options.sessions = ["typecheck", "tests"]
nox.options.default_venv_backend = "uv|virtualenv"

if os.environ.get("ENVIRONMENT") == "dev":
    # Use existing venvs where possible in dev
    nox.options.reuse_existing_virtualenvs = True
else:
    # All other envs should have the nox venvs recreated.
    nox.options.reuse_existing_virtualenvs = False

nox.options.stop_on_first_error = True


@nox.session(python="3.11")
def typecheck(session: nox.Session) -> None:
    """Run typechecker (mypy)."""
    session.install("mypy", ".[flask,fastapi,starlette]")
    run_args = session.posargs if session.posargs else ["src"]
    session.run("mypy", *run_args)


@nox.session(python="3.11")
def tests(session: nox.Session) -> None:
    """Run all tests."""
    session.install("pytest", ".")
    run_args = session.posargs if session.posargs else ["tests"]
    session.run("pytest", *run_args)
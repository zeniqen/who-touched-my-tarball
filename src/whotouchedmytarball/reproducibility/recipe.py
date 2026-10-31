"""Build recipe discovery from project metadata."""

from __future__ import annotations

import configparser
import json
from pathlib import Path

from .models import BuildRecipe

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py<3.11
    import tomli as tomllib  # type: ignore


NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
PYPI_BUILD_SYSTEMS = ("setuptools", "hatchling", "flit_core", "poetry.core", "pdm-backend", "mesonpy", "maturin")


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _read_toml(path: Path) -> dict | None:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def discover_npm_recipe(source_root: Path) -> BuildRecipe:
    recipe = BuildRecipe(ecosystem="npm", build_system="npm")
    notes = recipe.notes
    pkg_path = _find_file(source_root, "package.json")
    pkg = _read_json(pkg_path) if pkg_path else None
    if not pkg:
        notes.append("package.json not found or unreadable")
        return recipe

    scripts = pkg.get("scripts") or {}
    workspaces = pkg.get("workspaces")
    if workspaces:
        recipe.notes.append(f"workspace configuration detected: {workspaces}")

    # Lockfile preference
    for lock in NPM_LOCKFILES:
        p = _find_file(source_root, lock)
        if p:
            recipe.lockfile = str(p)
            break

    # Build commands
    for key in ("build", "prepare", "prepublishOnly", "prepack"):
        if key in scripts:
            recipe.build_commands.append(f"npm run {key}")
    if "build" not in scripts and not recipe.build_commands:
        # No explicit build script; could be pure JS package.
        recipe.notes.append("no build script found in package.json")

    if scripts.get("preinstall") or scripts.get("install") or scripts.get("postinstall"):
        recipe.required_tools.append("npm")
        recipe.notes.append("install scripts present; build execution must be isolated")

    recipe.required_tools = list(dict.fromkeys(["node", "npm"] + recipe.required_tools))
    # Confidence
    if recipe.build_commands or pkg.get("main"):
        recipe.confidence = 0.6 if recipe.build_commands else 0.4
    if recipe.lockfile:
        recipe.confidence = min(1.0, recipe.confidence + 0.2)
    return recipe


def discover_pypi_recipe(source_root: Path) -> BuildRecipe:
    recipe = BuildRecipe(ecosystem="pypi", build_system="unknown")
    notes = recipe.notes
    pyproject = _find_file(source_root, "pyproject.toml")
    setup_cfg = _find_file(source_root, "setup.cfg")
    setup_py = _find_file(source_root, "setup.py")

    build_backend = None
    if pyproject:
        data = _read_toml(pyproject)
        if data:
            bs = (data.get("build-system") or {})
            reqs = bs.get("requires") or []
            build_backend = bs.get("build-backend")
            recipe.required_tools = list(reqs)
            if build_backend:
                recipe.build_system = build_backend
            # Poetry / hatch / flit hints
            if "tool" in data:
                tools = data["tool"]
                if "poetry" in tools:
                    recipe.build_system = recipe.build_system or "poetry.core.masonry.api"
                if "hatch" in tools:
                    recipe.build_system = recipe.build_system or "hatchling"
                if "flit" in tools:
                    recipe.build_system = recipe.build_system or "flit_core.buildapi"
                if "pdm" in tools:
                    recipe.build_system = recipe.build_system or "pdm.backend"
    if setup_cfg and not build_backend:
        cp = configparser.ConfigParser()
        try:
            cp.read(setup_cfg)
            if cp.has_section("metadata"):
                recipe.notes.append("setup.cfg metadata found")
        except configparser.Error:
            pass
    if setup_py and not build_backend:
        recipe.build_system = recipe.build_system or "setuptools"
        recipe.notes.append("setup.py present")

    if recipe.build_system == "unknown" and not (pyproject or setup_cfg or setup_py):
        notes.append("no pyproject.toml, setup.cfg or setup.py found")
        return recipe

    if recipe.build_system == "unknown":
        recipe.build_system = "setuptools"

    # Supported check
    if not any(s in recipe.build_system for s in PYPI_BUILD_SYSTEMS):
        notes.append(f"build backend {recipe.build_system} may be unsupported")

    recipe.build_commands = ["python -m build"]  # default PEP 517 build
    # Prefer lockfile-pinned deps recorded as required_tools already (build-system requires)
    # Check requirements files
    for reqname in ("requirements.txt", "requirements-dev.txt", "requirements-build.txt"):
        p = _find_file(source_root, reqname)
        if p:
            recipe.lockfile = recipe.lockfile or str(p)
            break

    recipe.confidence = 0.5
    if pyproject:
        recipe.confidence += 0.2
    if recipe.required_tools:
        recipe.confidence += 0.1
    if recipe.lockfile:
        recipe.confidence += 0.1
    recipe.confidence = min(1.0, recipe.confidence)
    return recipe


def discover_recipe(source_root: Path, ecosystem: str) -> BuildRecipe:
    if ecosystem == "npm":
        return discover_npm_recipe(source_root)
    if ecosystem == "pypi":
        return discover_pypi_recipe(source_root)
    recipe = BuildRecipe(ecosystem=ecosystem, build_system="unknown")
    recipe.notes.append(f"unsupported ecosystem: {ecosystem}")
    return recipe


def _find_file(root: Path, name: str) -> Path | None:
    for p in root.rglob(name):
        if p.is_file():
            return p
    return None


def is_supported_build_system(recipe: BuildRecipe) -> bool:
    if recipe.ecosystem == "npm":
        return True
    if recipe.ecosystem == "pypi":
        bs = (recipe.build_system or "").lower()
        if bs in ("", "unknown"):
            return False
        return any(s in bs for s in PYPI_BUILD_SYSTEMS)
    return False


def has_sufficient_information(recipe: BuildRecipe) -> bool:
    if not recipe.build_commands:
        return False
    if recipe.confidence < 0.3:
        return False
    return True

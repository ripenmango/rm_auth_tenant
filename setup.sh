#!/usr/bin/env bash
#
# setup.sh — Python dev environment bootstrapper
#
# Assumes this repo already provides: pyproject.toml, .env, Dockerfile,
# docker-compose.yml. This script just wires them together.
#
# What this does:
#   1. Always: create/activate venv, install dependencies from pyproject.toml
#   2. --build        : build the local Python package (wheel/sdist) into dist/
#   3. --docker-build : build the Docker image(s) via docker compose
#   4. --up           : start the stack with docker compose up
#
# Usage:
#   ./setup.sh                              # venv + install deps only
#   ./setup.sh --build                      # + build python package
#   ./setup.sh --docker-build               # + build docker image(s)
#   ./setup.sh --up                         # + docker compose up
#   ./setup.sh --build --docker-build --up  # do everything
#   ./setup.sh -h | --help
#
set -euo pipefail

VENV_DIR=".venv"
PYTHON_BIN="python3"

DO_BUILD=false
DO_DOCKER_BUILD=false
DO_UP=false
DO_PUBLISH=false
DO_CLEAN=false
DO_REINSTALL=false

log()   { printf '\033[1;34m[setup]\033[0m %s\n' "$1"; }
error() { printf '\033[1;31m[error]\033[0m %s\n' "$1" >&2; }
die()   { error "$1"; exit 1; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
setup.sh — Python dev environment bootstrapper

Assumes this repo already provides: pyproject.toml, .env, Dockerfile,
docker-compose.yml. This script just wires them together.

Usage:
  ./setup.sh [OPTIONS]

Options:
  --build           Build the local Python package (wheel/sdist) into dist/
  --publish         Upload dist/* to PyPI via twine (requires --build or an
                     existing dist/, plus PyPI credentials/token)
  --docker-build    Build the Docker image(s) via 'docker compose build'
  --up              Start the stack via 'docker compose up'
  --clean           Remove build artifacts (dist/, build/, *.egg-info,
                     __pycache__/, .pytest_cache/) and exit
  --reinstall       Uninstall all local rm-* and drf-base packages from the
                     venv (so they get reinstalled fresh from pyproject.toml),
                     then build a wheel-only artifact via
                     'python -m build --wheel'
  -h, --help        Show this help message and exit

Always runs (no flag needed):
  Create/activate .venv and install dependencies from pyproject.toml

Publishing/local-use notes:
  'pip install -e .' (the default install this script does) only creates
  a *.egg-info/ folder — that's editable-install metadata, not something
  you can hand to PyPI or another project. To get a shareable artifact,
  use --build, which produces dist/*.whl and dist/*.tar.gz. You can then:
    - install it elsewhere:  pip install /path/to/dist/yourpkg-0.1.0-py3-none-any.whl
    - publish it:            ./setup.sh --build --publish

Examples:
  ./setup.sh                              # venv + install deps only
  ./setup.sh --build                      # + build python package
  ./setup.sh --build --publish            # + upload to PyPI
  ./setup.sh --docker-build               # + build docker image(s)
  ./setup.sh --up                         # + docker compose up
  ./setup.sh --build --docker-build --up  # do everything
  ./setup.sh --clean                      # wipe build artifacts, then exit
  ./setup.sh --reinstall                  # drop local rm-*/drf-base pkgs, reinstall, build wheel
EOF
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    --build)        DO_BUILD=true ;;
    --publish)      DO_PUBLISH=true ;;
    --docker-build) DO_DOCKER_BUILD=true ;;
    --up)           DO_UP=true ;;
    --clean)        DO_CLEAN=true ;;
    --reinstall)    DO_REINSTALL=true ;;
    -h|--help)      usage ;;
    *) die "Unknown argument: $arg (use --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# 0. Clean (standalone action — runs first and exits)
# ---------------------------------------------------------------------------
if [ "$DO_CLEAN" = true ]; then
  log "Cleaning build artifacts..."
  rm -rf dist/ build/
  find . -type d -name "*.egg-info" -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
  find . -type d -name "__pycache__" -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
  rm -rf .pytest_cache/
  log "Clean complete (dist/, build/, *.egg-info, __pycache__/, .pytest_cache/ removed)."
  log "Note: .venv/ was left untouched — pass no other flags needed to rebuild it, or 'rm -rf .venv' to reset it too."
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Venv + install dependencies (always runs)
# ---------------------------------------------------------------------------
[ -f "pyproject.toml" ] || die "pyproject.toml not found in $(pwd)."

has_cmd "$PYTHON_BIN" || die "python3 is required but was not found."

if [ ! -d "$VENV_DIR" ]; then
  log "Creating virtual environment in $VENV_DIR..."
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
log "Virtual environment activated."

# ---------------------------------------------------------------------------
# 1b. Reinstall: drop local rm-*/drf-base packages so they get reinstalled fresh
# ---------------------------------------------------------------------------
if [ "$DO_REINSTALL" = true ]; then
  log "Removing existing rm-* and drf-base packages from $VENV_DIR..."
  LOCAL_PKGS="$(pip list --format=freeze 2>/dev/null | cut -d= -f1 | grep -iE '^(rm-|drf-base)' || true)"
  if [ -n "$LOCAL_PKGS" ]; then
    # shellcheck disable=SC2086
    pip uninstall -y $LOCAL_PKGS
    log "Removed: $(echo "$LOCAL_PKGS" | tr '\n' ' ')"
  else
    log "No installed rm-* or drf-base packages found; nothing to remove."
  fi
fi

log "Installing dependencies from pyproject.toml..."
pip install --upgrade pip >/dev/null
pip install -e ".[dev]" 2>/dev/null || pip install -e . || pip install .
log "Dependencies installed."

# ---------------------------------------------------------------------------
# 2. Build local Python package
# ---------------------------------------------------------------------------
if [ "$DO_BUILD" = true ]; then
  log "Building Python package (wheel/sdist)..."
  pip install --upgrade build >/dev/null
  $PYTHON_BIN -m build --outdir dist/
  log "Build artifacts written to ./dist/"
fi

# ---------------------------------------------------------------------------
# 2b. Publish to PyPI
# ---------------------------------------------------------------------------
if [ "$DO_PUBLISH" = true ]; then
  [ -d "dist" ] && [ -n "$(ls -A dist 2>/dev/null)" ] || die "No dist/ artifacts found. Run with --build first (or alongside --publish)."
  pip install --upgrade twine >/dev/null
  log "Uploading dist/* to PyPI via twine..."
  log "(Set TWINE_USERNAME/TWINE_PASSWORD, or use a __token__ API key, as env vars to skip the interactive prompt.)"
  twine upload dist/*
  log "Published to PyPI."
fi

# ---------------------------------------------------------------------------
# 2c. Reinstall: build wheel-only artifact
# ---------------------------------------------------------------------------
if [ "$DO_REINSTALL" = true ]; then
  log "Building wheel-only package (python -m build --wheel)..."
  pip install --upgrade build >/dev/null
  $PYTHON_BIN -m build --wheel --outdir dist/
  log "Wheel written to ./dist/"
fi

# ---------------------------------------------------------------------------
# 3. Docker build
# ---------------------------------------------------------------------------
DOCKER_COMPOSE_CMD=""
if [ "$DO_DOCKER_BUILD" = true ] || [ "$DO_UP" = true ]; then
  has_cmd docker || die "Docker is required for --docker-build/--up but was not found."
  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
  elif has_cmd docker-compose; then
    DOCKER_COMPOSE_CMD="docker-compose"
  else
    die "Docker is installed but no compose plugin/binary found."
  fi
  [ -f "docker-compose.yml" ] || die "docker-compose.yml not found in $(pwd)."
fi

if [ "$DO_DOCKER_BUILD" = true ]; then
  log "Building Docker image(s) with '$DOCKER_COMPOSE_CMD build'..."
  $DOCKER_COMPOSE_CMD build
  log "Docker image(s) built."
fi

# ---------------------------------------------------------------------------
# 4. docker compose up
# ---------------------------------------------------------------------------
if [ "$DO_UP" = true ]; then
  log "Starting stack with '$DOCKER_COMPOSE_CMD up'..."
  $DOCKER_COMPOSE_CMD up
fi

log "Done."

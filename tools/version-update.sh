#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Client Hub Open Project - Comprehensive Version Update Script
# - Updates version references across the repo
# - Runs npm install/build/test, go mod tidy/test, python venv + pip install
# - Uses versions detected on the local machine unless overridden by env vars
#
# Usage:
#   ./tools/version-update.sh
#
# Optional overrides:
#   GO_VERSION=1.25.6 \
#   NODE_VERSION=24.11.1 \
#   PYTHON_VERSION=3.13.9 \
#   REACT_VERSION=19.2.4 \
#   VITE_VERSION=7.3.1 \
#   PIN_FRONTEND_DEPS=true \
#   PIN_TEST_REQUIREMENTS=true \
#   RUN_NPM_AUDIT=true \
#   RUN_FRONTEND_TESTS=true \
#   RUN_BACKEND_TESTS=true \
#   RUN_COMPOSE_CONFIG=true \
#   RUN_PYTEST=true \
#   ./tools/version-update.sh
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS_RUNBOOK="${ROOT_DIR}/docs/version-update.txt"
FRONTEND_DIR="${ROOT_DIR}/frontend"
BACKEND_DIR="${ROOT_DIR}/backend"
TESTS_DIR="${ROOT_DIR}/tests"
TOOLS_DIR="${ROOT_DIR}/tools"

log() {
  printf "\n\033[1;34m[version-update]\033[0m %s\n" "$*"
}

warn() {
  printf "\n\033[1;33m[version-update]\033[0m %s\n" "$*"
}

die() {
  printf "\n\033[1;31m[version-update]\033[0m %s\n" "$*"
  exit 1
}

require_cmd() {
  local cmd="$1"
  local install_hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    if [[ -n "${install_hint}" ]]; then
      die "Required command not found: ${cmd}. Install: ${install_hint}"
    fi
    die "Required command not found: ${cmd}"
  fi
}

print_prereqs() {
  log "Prerequisites: go, node, npm, python3, pip, docker-compose, rg, sed, find"
  log "Missing commands will cause the script to stop with install hints."
}

read_doc_version() {
  local key="$1"
  local default_value="$2"
  if [[ -f "${DOCS_RUNBOOK}" ]]; then
    local val
    val="$(rg -m 1 -e "^- ${key}:" "${DOCS_RUNBOOK}" | head -n1 | sed -E "s/^- ${key}:[[:space:]]*//")"
    if [[ -n "${val}" ]]; then
      echo "${val}"
      return
    fi
  fi
  echo "${default_value}"
}

# Determine local runtime versions (fallbacks)
detect_go_version() {
  if command -v go >/dev/null 2>&1; then
    go version | awk '{print $3}' | sed 's/^go//'
  else
    echo ""
  fi
}

detect_node_version() {
  if command -v node >/dev/null 2>&1; then
    node --version | sed 's/^v//'
  else
    echo ""
  fi
}

detect_python_version() {
  if command -v python >/dev/null 2>&1; then
    python --version | awk '{print $2}'
  elif command -v python3 >/dev/null 2>&1; then
    python3 --version | awk '{print $2}'
  else
    echo ""
  fi
}

parse_version_major() {
  echo "${1:-}" | awk -F. '{print $1}'
}

is_major_upgrade() {
  local current_major
  local target_major
  current_major="$(parse_version_major "${1:-}")"
  target_major="$(parse_version_major "${2:-}")"
  if [[ -z "${current_major}" || -z "${target_major}" ]]; then
    echo "false"
    return
  fi
  if [[ "${target_major}" -gt "${current_major}" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

# Defaults
DEFAULT_GO_VERSION="$(read_doc_version "Go" "$(detect_go_version)")"
DEFAULT_NODE_VERSION="$(read_doc_version "Node.js" "$(detect_node_version)")"
DEFAULT_PY_VERSION="$(read_doc_version "Python" "$(detect_python_version)")"
DEFAULT_REACT_VERSION="$(read_doc_version "React" "")"
DEFAULT_VITE_VERSION="$(read_doc_version "Vite" "")"

GO_VERSION="${GO_VERSION:-${DEFAULT_GO_VERSION}}"
NODE_VERSION="${NODE_VERSION:-${DEFAULT_NODE_VERSION}}"
PYTHON_VERSION="${PYTHON_VERSION:-${DEFAULT_PY_VERSION}}"
REACT_VERSION="${REACT_VERSION:-${DEFAULT_REACT_VERSION}}"
VITE_VERSION="${VITE_VERSION:-${DEFAULT_VITE_VERSION}}"
PIN_FRONTEND_DEPS="${PIN_FRONTEND_DEPS:-true}"
PIN_TEST_REQUIREMENTS="${PIN_TEST_REQUIREMENTS:-true}"
RUN_NPM_AUDIT="${RUN_NPM_AUDIT:-false}"
RUN_FRONTEND_TESTS="${RUN_FRONTEND_TESTS:-true}"
RUN_BACKEND_TESTS="${RUN_BACKEND_TESTS:-true}"
RUN_COMPOSE_CONFIG="${RUN_COMPOSE_CONFIG:-true}"
RUN_PYTEST="${RUN_PYTEST:-false}"

if [[ "$(is_major_upgrade "${DEFAULT_PY_VERSION}" "${PYTHON_VERSION}")" == "true" ]]; then
  local_py_version="$(detect_python_version)"
  if [[ "${RUN_PYTEST}" == "true" && -n "${local_py_version}" ]]; then
    log "Python major upgrade detected (${DEFAULT_PY_VERSION} -> ${PYTHON_VERSION}). Using local Python ${local_py_version} for validation."
    PYTHON_VERSION="${local_py_version}"
  else
    warn "Python major upgrade detected (${DEFAULT_PY_VERSION} -> ${PYTHON_VERSION}). Set RUN_PYTEST=true to validate; keeping ${DEFAULT_PY_VERSION}."
    PYTHON_VERSION="${DEFAULT_PY_VERSION}"
  fi
fi

log "Using versions:"
log "  Go:      ${GO_VERSION:-<not set>}"
log "  Node.js: ${NODE_VERSION:-<not set>}"
log "  Python:  ${PYTHON_VERSION:-<not set>}"
log "  React:   ${REACT_VERSION:-<not set>}"
log "  Vite:    ${VITE_VERSION:-<not set>}"
log "  Pin frontend deps: ${PIN_FRONTEND_DEPS}"
log "  Pin test requirements: ${PIN_TEST_REQUIREMENTS}"
log "  Run npm audit: ${RUN_NPM_AUDIT}"
log "  Run frontend tests: ${RUN_FRONTEND_TESTS}"
log "  Run backend tests: ${RUN_BACKEND_TESTS}"
log "  Run compose config: ${RUN_COMPOSE_CONFIG}"
log "  Run pytest: ${RUN_PYTEST}"

if [[ -z "${GO_VERSION}" || -z "${NODE_VERSION}" || -z "${PYTHON_VERSION}" ]]; then
  warn "Some runtime versions are empty. Consider exporting GO_VERSION/NODE_VERSION/PYTHON_VERSION."
fi

print_prereqs

# Sanity checks
require_cmd sed "brew install gnu-sed | apt-get install -y sed"
require_cmd find "brew install findutils | apt-get install -y findutils"
require_cmd rg "brew install ripgrep | apt-get install -y ripgrep"

# ------------------------------------------------------------------------------
# Helpers to update text
# ------------------------------------------------------------------------------
replace_in_file() {
  local file="$1"
  local search="$2"
  local replace="$3"
  if [[ -f "${file}" ]]; then
    sed -i.bak -e "${search//\//\\/}" "${file}"
    rm -f "${file}.bak"
  fi
}

replace_simple() {
  local file="$1"
  local old="$2"
  local new="$3"
  if [[ -f "${file}" ]]; then
    sed -i.bak -e "s/${old}/${new}/g" "${file}"
    rm -f "${file}.bak"
  fi
}

pin_frontend_versions() {
  if [[ "${PIN_FRONTEND_DEPS}" != "true" ]]; then
    log "Skipping frontend dependency pinning."
    return
  fi
  require_cmd node
  if [[ ! -f "${FRONTEND_DIR}/package-lock.json" ]]; then
    warn "package-lock.json not found; cannot pin frontend dependencies."
    return
  fi
  FRONTEND_DIR="${FRONTEND_DIR}" node <<'NODE'
const fs = require("fs");
const path = require("path");

const frontendDir = process.env.FRONTEND_DIR;
const pkgPath = path.join(frontendDir, "package.json");
const lockPath = path.join(frontendDir, "package-lock.json");

const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));

function resolvedVersion(name) {
  const key = `node_modules/${name}`;
  if (lock.packages && lock.packages[key] && lock.packages[key].version) {
    return lock.packages[key].version;
  }
  if (lock.dependencies && lock.dependencies[name] && lock.dependencies[name].version) {
    return lock.dependencies[name].version;
  }
  return null;
}

function pinSection(section) {
  if (!pkg[section]) return;
  for (const name of Object.keys(pkg[section])) {
    const version = resolvedVersion(name);
    if (version) {
      pkg[section][name] = version;
    }
  }
}

pinSection("dependencies");
pinSection("devDependencies");

fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 4) + "\n");
NODE
}

pin_test_requirements() {
  if [[ "${PIN_TEST_REQUIREMENTS}" != "true" ]]; then
    log "Skipping test requirements pinning."
    return
  fi
  if [[ ! -f "${TESTS_DIR}/requirements.txt" ]]; then
    warn "requirements.txt not found; cannot pin test requirements."
    return
  fi
  TESTS_DIR="${TESTS_DIR}" python - <<'PY'
import os
import re
import subprocess
import sys
from pathlib import Path

req_path = Path(os.environ["TESTS_DIR"]) / "requirements.txt"
text = req_path.read_text()

freeze = subprocess.check_output([sys.executable, "-m", "pip", "freeze"]).decode().splitlines()
versions = {}
for line in freeze:
    if "==" in line:
        name, ver = line.split("==", 1)
        versions[name.lower()] = ver

pattern = re.compile(r"^([A-Za-z0-9_.-]+(?:\\[[^\\]]+\\])?)==([A-Za-z0-9_.-]+)$", re.M)

def repl(match):
    name = match.group(1)
    base = name.split("[")[0].lower()
    if base in versions:
        return f"{name}=={versions[base]}"
    return match.group(0)

req_path.write_text(pattern.sub(repl, text))
PY
}

# ------------------------------------------------------------------------------
# Step 1: Update Go version references
# ------------------------------------------------------------------------------
if [[ -n "${GO_VERSION}" ]]; then
  log "Updating Go version references..."
  # go.mod
  if [[ -f "${BACKEND_DIR}/go.mod" ]]; then
    sed -i.bak -E "s/^go [0-9]+\.[0-9]+(\.[0-9]+)?/go ${GO_VERSION}/" "${BACKEND_DIR}/go.mod"
    rm -f "${BACKEND_DIR}/go.mod.bak"
  fi

  # Dockerfiles + compose build args + docs
  find "${ROOT_DIR}" -type f \( -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "*.md" -o -name "Makefile" \) \
    -print0 | xargs -0 sed -i.bak -E "s/Go [0-9]+\.[0-9]+(\.[0-9]+)?/Go ${GO_VERSION}/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete

  # Replace golang image tags (best-effort)
  find "${ROOT_DIR}" -type f \( -name "Dockerfile*" -o -name "docker-compose*.yml" \) \
    -print0 | xargs -0 sed -i.bak -E "s/golang:[0-9]+\.[0-9]+(\.[0-9]+)?-alpine/golang:${GO_VERSION}-alpine/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete

  # Replace GO_VERSION build args
  find "${ROOT_DIR}" -type f -name "docker-compose*.yml" -print0 | xargs -0 sed -i.bak -E "s/GO_VERSION: \"[0-9]+\.[0-9]+(\.[0-9]+)?\"/GO_VERSION: \"${GO_VERSION}\"/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete
fi

# ------------------------------------------------------------------------------
# Step 2: Update Node.js version references
# ------------------------------------------------------------------------------
if [[ -n "${NODE_VERSION}" ]]; then
  log "Updating Node.js version references..."
  # .nvmrc
  if [[ -f "${FRONTEND_DIR}/.nvmrc" ]]; then
    printf "%s\n" "${NODE_VERSION}" > "${FRONTEND_DIR}/.nvmrc"
  fi

  # Dockerfiles + compose build args + docs
  find "${ROOT_DIR}" -type f \( -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "*.md" \) \
    -print0 | xargs -0 sed -i.bak -E "s/Node\.js [0-9]+\.[0-9]+(\.[0-9]+)?/Node.js ${NODE_VERSION}/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete

  # Replace node image tags (best-effort)
  find "${ROOT_DIR}" -type f \( -name "Dockerfile*" -o -name "docker-compose*.yml" \) \
    -print0 | xargs -0 sed -i.bak -E "s/node:[0-9]+\.[0-9]+(\.[0-9]+)?-alpine/node:${NODE_VERSION}-alpine/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete

  # Replace NODE_VERSION build args
  find "${ROOT_DIR}" -type f -name "docker-compose*.yml" -print0 | xargs -0 sed -i.bak -E "s/NODE_VERSION: \"[0-9]+\.[0-9]+(\.[0-9]+)?\"/NODE_VERSION: \"${NODE_VERSION}\"/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete
fi

# ------------------------------------------------------------------------------
# Step 3: Update Python version references
# ------------------------------------------------------------------------------
if [[ -n "${PYTHON_VERSION}" ]]; then
  log "Updating Python version references..."
  # Update docs
  find "${ROOT_DIR}" -type f \( -name "*.md" -o -name "Makefile" \) \
    -print0 | xargs -0 sed -i.bak -E "s/Python [0-9]+\.[0-9]+(\.[0-9]+)?/Python ${PYTHON_VERSION}/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete

  # Update python image tags in docker compose/dockerfiles
  find "${ROOT_DIR}" -type f \( -name "Dockerfile*" -o -name "docker-compose*.yml" \) \
    -print0 | xargs -0 sed -i.bak -E "s/python:[0-9]+\.[0-9]+(\.[0-9]+)?-slim/python:${PYTHON_VERSION}-slim/g"
  find "${ROOT_DIR}" -type f -name "*.bak" -delete
fi

# ------------------------------------------------------------------------------
# Step 4: Update frontend dependency versions (React/Vite) if specified
# ------------------------------------------------------------------------------
if [[ -n "${REACT_VERSION}" || -n "${VITE_VERSION}" ]]; then
  log "Updating frontend dependency versions..."
  if [[ -f "${FRONTEND_DIR}/package.json" ]]; then
    if [[ -n "${REACT_VERSION}" ]]; then
      sed -i.bak -E "s/\"react\": \"[0-9]+\.[0-9]+\.[0-9]+\"/\"react\": \"${REACT_VERSION}\"/g" "${FRONTEND_DIR}/package.json"
      sed -i.bak -E "s/\"react-dom\": \"[0-9]+\.[0-9]+\.[0-9]+\"/\"react-dom\": \"${REACT_VERSION}\"/g" "${FRONTEND_DIR}/package.json"
      rm -f "${FRONTEND_DIR}/package.json.bak"
    fi
    if [[ -n "${VITE_VERSION}" ]]; then
      sed -i.bak -E "s/\"vite\": \"[0-9]+\.[0-9]+\.[0-9]+\"/\"vite\": \"${VITE_VERSION}\"/g" "${FRONTEND_DIR}/package.json"
      rm -f "${FRONTEND_DIR}/package.json.bak"
    fi
  fi
fi

# ------------------------------------------------------------------------------
# Step 5: Update docker-compose config (remove deprecated version key)
# ------------------------------------------------------------------------------
if [[ -f "${TESTS_DIR}/docker-compose.test.yml" ]]; then
  log "Ensuring docker-compose.test.yml has no deprecated version key..."
  sed -i.bak -E "/^version: \"[0-9]+\.[0-9]+\"/d" "${TESTS_DIR}/docker-compose.test.yml"
  rm -f "${TESTS_DIR}/docker-compose.test.yml.bak"
fi

# ------------------------------------------------------------------------------
# Step 6: Run dependency installs and tidies
# ------------------------------------------------------------------------------
log "Running npm install (frontend)..."
if [[ -d "${FRONTEND_DIR}" ]]; then
  (cd "${FRONTEND_DIR}" && npm install)
  (cd "${FRONTEND_DIR}" && pin_frontend_versions)
  (cd "${FRONTEND_DIR}" && npm install)
  if [[ "${RUN_NPM_AUDIT}" == "true" ]]; then
    log "Running npm audit fix (frontend)..."
    (cd "${FRONTEND_DIR}" && npm audit fix || true)
  else
    log "Skipping npm audit."
  fi
else
  warn "Frontend directory not found: ${FRONTEND_DIR}"
fi

if [[ "${RUN_FRONTEND_TESTS}" == "true" ]]; then
  log "Running npm test (frontend)..."
  if [[ -d "${FRONTEND_DIR}" ]]; then
    (cd "${FRONTEND_DIR}" && npm test)
  fi
else
  log "Skipping frontend tests."
fi

log "Running go mod tidy + go test (backend)..."
if [[ -d "${BACKEND_DIR}" ]]; then
  (cd "${BACKEND_DIR}" && go mod tidy)
  if [[ "${RUN_BACKEND_TESTS}" == "true" ]]; then
    (cd "${BACKEND_DIR}" && go test ./...)
  else
    log "Skipping backend tests."
  fi
else
  warn "Backend directory not found: ${BACKEND_DIR}"
fi

log "Recreating Python venv and installing requirements..."
if [[ -d "${TESTS_DIR}" ]]; then
  PYTHON_BIN=""
  if [[ -n "${PYTHON_VERSION}" ]]; then
    if command -v pyenv >/dev/null 2>&1; then
      if pyenv versions --bare | rg -qx "${PYTHON_VERSION}"; then
        PYTHON_BIN="$(pyenv root)/versions/${PYTHON_VERSION}/bin/python"
      fi
    fi
    if [[ -z "${PYTHON_BIN}" ]]; then
      PY_SHORT="$(echo "${PYTHON_VERSION}" | awk -F. '{print $1 "." $2}')"
      if command -v "python${PY_SHORT}" >/dev/null 2>&1; then
        PYTHON_BIN="python${PY_SHORT}"
      fi
    fi
  fi
  if [[ -z "${PYTHON_BIN}" ]]; then
    if command -v python >/dev/null 2>&1; then
      PYTHON_BIN="python"
    elif command -v python3 >/dev/null 2>&1; then
      PYTHON_BIN="python3"
    else
      die "Python not found on PATH."
    fi
  fi

  VENV_DIR="${ROOT_DIR}/.venv"
  rm -rf "${VENV_DIR}"
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  python -m pip install --upgrade pip
  python -m pip install -r "${TESTS_DIR}/requirements.txt" --upgrade
  pin_test_requirements
  if [[ "${RUN_PYTEST}" == "true" ]]; then
    log "Running full test runner (tests)..."
    "${TESTS_DIR}/run_all_tests.sh"
  else
    log "Skipping pytest."
  fi
  deactivate
else
  warn "Tests directory not found: ${TESTS_DIR}"
fi

# ------------------------------------------------------------------------------

# Step 7: Docker compose config validation (non-blocking)
# ------------------------------------------------------------------------------
if [[ "${RUN_COMPOSE_CONFIG}" == "true" ]]; then
  if command -v docker-compose >/dev/null 2>&1; then
    log "Validating docker-compose configs..."
    if [[ -f "${ROOT_DIR}/deploy/docker/docker-compose.yml" ]]; then
      docker-compose -f "${ROOT_DIR}/deploy/docker/docker-compose.yml" config >/dev/null
    fi
    if [[ -f "${TESTS_DIR}/docker-compose.test.yml" ]]; then
      docker-compose -f "${TESTS_DIR}/docker-compose.test.yml" config >/dev/null
    fi
  else
    warn "docker-compose not found; skipping compose config validation."
  fi
else
  log "Skipping docker-compose config validation."
fi

log "Version update complete. Review changes and run any additional checks as needed."

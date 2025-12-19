#!/bin/bash

## @file
#  Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
#  SPDX-License-Identifier : Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##

set -euo pipefail

# Unified RME ACS OOB script for FVP (bm|uefi) and RD-V3 (uefi)

# Internal guard to know if we activated shrinkwrap venv in this process
__SW_VENV_ACTIVE=""

# Paths
# - SCRIPT_DIR: this script's directory (tools/scripts)
# - REPO_ROOT: repo root two levels above
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

# Centralized locations per your structure
CONFIGS_ROOT="${REPO_ROOT}/tools/configs/shrinkwrap"
PATCHES_ROOT="${REPO_ROOT}/tools/patches"

# RDV3 install/work directory handling
# - No default; RDV3_WORKDIR must be provided via environment
RDV3_WORKDIR="${RDV3_WORKDIR:-}"

# RDV3 stack tag (RDInfra) to use for repo init; fixed version
RDV3_STACK_TAG="RD-INFRA-2025.02.04"

LOG_FILE="${REPO_ROOT}/rme_sysarch_acs.log"

SUPPORTED_PLATFORMS=("aemfvp-a" "rdv3")
SUPPORTED_ENVS=("bm" "uefi")
PLATFORM=""
ENVIRONMENT=""
ACTION=""

log() {
  echo "["$(date '+%Y-%m-%d %H:%M:%S')"] $*" | tee -a "$LOG_FILE"
}

usage() {
  cat <<EOF
Usage:
  $0 -p <aemfvp-a|rdv3> -env <bm|uefi> --install-prerequisites
  $0 -p <aemfvp-a|rdv3> -env <bm|uefi> build
  $0 -p <aemfvp-a|rdv3> -env <bm|uefi> run

Notes:
  - If -p rdv3, -env is forced to uefi.

  - AEM FVP-A environment variables (required for -p aemfvp-a):
    shrinkwrap               Path to shrinkwrap binary installed in PATH variable.
    SHRIKWRAP_BUILD /        Path to build and package directories for shrinkwrap.
    SHRIKWRAP_PACKAGE
    ACS_UEFI_IMAGE           Path to ACS UEFI IMAGE when -env uefi is set.

  - RD-V3 environment variables (required for -p rdv3):
    RDV3_WORKDIR             Install/work directory for RD-V3 model and stack (required)
    ACS_UEFI_IMAGE           Path to ACS UEFI Image
EOF
}

# ------------------------ AEM FVP-A (bm|uefi) ------------------------

fvp_install_prereqs() {
  log "Installing prerequisites for AEM FVP-A (bm|uefi)"
  local TOOLS_DIR="${REPO_ROOT}/tools"
  local TOOLCHAIN_VERSION="13.2.rel1"
  local FVP_TAR="FVP_Base_RevC-2xAEMvA_11.29_27_Linux64.tgz"
  local FVP_URL="https://developer.arm.com/-/cdn-downloads/permalink/FVPs-Architecture/FM-11.29/${FVP_TAR}"
  local FVP_DIR_NAME="Base_RevC_AEMvA_pkg"
  local SHRINKWRAP_DIR="shrinkwrap"
  # Place venv at tools/.venv (not inside shrinkwrap)
  local TOOLS_VENV=".venv"

  mkdir -p "$TOOLS_DIR"
  pushd "$TOOLS_DIR" >/dev/null

  # Install host packages (Debian/Ubuntu) needed for shrinkwrap, TF-A, EDK2
  if command -v apt-get >/dev/null 2>&1; then
    log "Installing host packages via apt-get (may require sudo)"
    sudo apt-get update -y || true
    # Base packages common to all hosts
    sudo apt-get install -y \
      git acpica-tools bc bison build-essential curl debhelper flex genext2fs \
      gperf libxml2 libxml2-dev libxml2-utils libxml-libxml-perl make \
      openssh-server openssh-client expect bridge-utils python3 python3-pip \
      device-tree-compiler autopoint doxygen xterm ninja-build \
      uuid-dev wget zip mtools autoconf locales sbsigntool pkg-config gdisk \
      srecord libssl-dev libelf-dev virtualenv ninja-build tmux cmake \
      netcat-openbsd python3-venv telnet || true


  else
    log "apt-get not found; ensure packages are installed per prerequisites list"
  fi

  # Determine if shrinkwrap already available
  if command -v shrinkwrap >/dev/null 2>&1; then
    log "shrinkwrap found in PATH; skipping local clone and venv setup"
  else
    # Install shrinkwrap into tools/ only if absent
    if [ ! -d "$SHRINKWRAP_DIR" ]; then
      log "Cloning shrinkwrap into tools/"
      git clone https://git.gitlab.arm.com/tooling/shrinkwrap.git "$SHRINKWRAP_DIR"
    else
      log "shrinkwrap already present in tools/, skipping clone"
    fi
  fi

  # Create and update a Python virtual environment for shrinkwrap deps at tools/.venv
  if [ ! -d "$TOOLS_VENV" ]; then
    log "Creating virtual environment at tools/.venv"
    python3 -m venv "$TOOLS_VENV"
  fi
  log "Installing/updating shrinkwrap Python dependencies in tools/.venv"
  (
    source "$TOOLS_VENV/bin/activate"
    python -m pip install --upgrade pip
    python -m pip install pyyaml termcolor tuxmake
    deactivate
  )

  if [ ! -d "arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-elf" ]; then
    log "Downloading aarch64-none-elf toolchain..."
    curl -LO "https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-aarch64-none-elf.tar.xz"
    tar -xf "arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-aarch64-none-elf.tar.xz"
  fi

  if [ ! -d "arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu" ]; then
    log "Downloading aarch64-none-linux-gnu toolchain..."
    curl -LO "https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-aarch64-none-linux-gnu.tar.xz"
    tar -xf "arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-aarch64-none-linux-gnu.tar.xz"
  fi

  if [ ! -d "$FVP_DIR_NAME" ]; then
    log "Downloading Base RevC FVP model..."
    curl -LO "$FVP_URL"
    tar -xf "$FVP_TAR"
    chmod +x "$FVP_DIR_NAME"/models/Linux64_GCC-9.3/FVP_Base_RevC-2xAEMvA
  fi

  popd >/dev/null
  log "AEM FVP-A prerequisites installed"
}

fvp_preflight() {
  log "AEM FVP-A preflight checks"

  local ACS_PATH_DEFAULT="${REPO_ROOT}"
  local ACS_PATH_VAL="${ACS_PATH:-$ACS_PATH_DEFAULT}"

  [[ -d "$CONFIGS_ROOT" ]] || { log "Missing ${CONFIGS_ROOT}"; exit 1; }
  [[ -d "$ACS_PATH_VAL" ]] || { log "Missing ACS_PATH: $ACS_PATH_VAL"; exit 1; }
  [[ -d "${SHRINKWRAP_BUILD:-}" ]] || { log "Missing SHRINKWRAP_BUILD: ${SHRINKWRAP_BUILD:-<unset>}"; exit 1; }
  [[ -d "${SHRINKWRAP_PACKAGE:-}" ]] || { log "Missing SHRINKWRAP_PACKAGE: ${SHRINKWRAP_PACKAGE:-<unset>}"; exit 1; }
  [[ -f "${REPO_ROOT}/tools/configs/pcie/aemfvp-a/pcie_hierarchy.json" ]] || { log "Missing ${REPO_ROOT}/tools/configs/pcie/aemfvp-a/pcie_hierarchy.json"; exit 1; }

  # Verify shrinkwrap presence in tools/ and its venv; then activate once
  local TOOLS_DIR="${REPO_ROOT}/tools"
  local SW_DIR="${TOOLS_DIR}/shrinkwrap"
  local LOCAL_SW_BIN_PATH="${SW_DIR}/shrinkwrap/"
  local TOOLS_VENV="${TOOLS_DIR}/.venv"

  # Prefer system shrinkwrap if available; otherwise use local checkout
  if command -v shrinkwrap >/dev/null 2>&1; then
    log "Using shrinkwrap from PATH: $(command -v shrinkwrap)"
  else
    [[ -f "${LOCAL_SW_BIN_PATH}/shrinkwrap" ]] || { log "shrinkwrap not found in PATH or at ${LOCAL_SW_BIN_PATH}. Run --install-prerequisites"; exit 1; }
    # Ensure tools/.venv exists for local shrinkwrap usage
    [[ -x "${TOOLS_VENV}/bin/python" ]] || { log "venv missing: ${TOOLS_VENV}/bin/python. Run --install-prerequisites"; exit 1; }

    # Activate venv and export local shrinkwrap bin into PATH
    if [[ "${VIRTUAL_ENV:-}" != "${TOOLS_VENV}" ]]; then
      . "${TOOLS_VENV}/bin/activate"
      __SW_VENV_ACTIVE=1
      trap '[[ -n "${__SW_VENV_ACTIVE:-}" ]] && deactivate || true' EXIT
    fi
    export PATH="${LOCAL_SW_BIN_PATH}:$PATH"
  fi

  # Add toolchains & AEM FVP-A paths if present
  export PATH="$TOOLS_DIR/arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-elf/bin:$PATH"
  export PATH="$TOOLS_DIR/arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu/bin:$PATH"
  export PATH="$TOOLS_DIR/Base_RevC_AEMvA_pkg/models/Linux64_GCC-9.3:$PATH"
}

fvp_build() {
  local env="$1"  # bm|uefi

  local ACS_PATH_DEFAULT="${REPO_ROOT}"
  local ACS_PATH_VAL="${ACS_PATH:-$ACS_PATH_DEFAULT}"

  local EL3_CONFIG="${ACS_PATH_VAL}/pal_el3/include/pal_el3_config.h"
  if [[ ! -f "$EL3_CONFIG" ]]; then
    log "pal_el3_config.h not found: $EL3_CONFIG";popd >/dev/null; exit 1
  fi

  log "Ensuring PLATFORM_BASEFVP=1 in $EL3_CONFIG"
  if grep -Eq '^[[:space:]]*#define[[:space:]]+PLATFORM_BASEFVP' "$EL3_CONFIG"; then
    sed -i -E 's/(^[[:space:]]*#define[[:space:]]+PLATFORM_BASEFVP[[:space:]]+)[0-9]+/\1 1/' "$EL3_CONFIG"
  else
    printf '\n#define PLATFORM_BASEFVP 1\n' >> "$EL3_CONFIG"
  fi

  fvp_preflight

  log "Building AEM FVP-A stack for env: $env"
  case "$env" in
    bm)
      shrinkwrap --runtime=null build \
        "${CONFIGS_ROOT}/rme-acs-stack-bm.yaml" \
        --btvar ACS_PATH="$ACS_PATH_VAL" \
        --btvar TFA_PATCHES="${PATCHES_ROOT}/aemfvp-a/tfa"
      ;;
    uefi)
      shrinkwrap --runtime=null build \
        "${CONFIGS_ROOT}/rme-acs-stack-uefi.yaml" \
        --btvar ACS_PATH="$ACS_PATH_VAL" \
        --btvar TFA_PATCHES="${PATCHES_ROOT}/aemfvp-a/tfa"
      ;;
    *)
      log "Unknown env for AEM FVP-A: $env"; exit 1
      ;;
  esac

  log "AEM FVP-A build complete: $env"
}

fvp_run() {
  local env="$1"
  fvp_preflight

  log "Running AEM FVP-A env: $env"
  case "$env" in
    bm)
      shrinkwrap --runtime=null run \
        --rtvar=JSON_FILE="${REPO_ROOT}/tools/configs/pcie/aemfvp-a/pcie_hierarchy.json" \
        "rme-acs-stack-bm.yaml"
      ;;
    uefi)
      if [[ -z "${ACS_UEFI_IMAGE:-}" ]]; then
        log "ACS_UEFI_IMAGE not set for uefi run"; exit 1
      fi
      shrinkwrap --runtime=null run \
        --rtvar=JSON_FILE="${REPO_ROOT}/tools/configs/pcie/aemfvp-a/pcie_hierarchy.json" \
        --rtvar=ROOTFS="$ACS_UEFI_IMAGE" \
        --rtvar=KERNEL="$ACS_UEFI_IMAGE" \
        "rme-acs-stack-uefi.yaml"
      ;;
    *) log "Unknown env for AEM FVP-A: $env"; exit 1 ;;
  esac

  log "AEM FVP-A run complete: $env"
}

rdv3_select_workdir() {
  # Validate RDV3_WORKDIR is provided via environment
  if [[ -z "${RDV3_WORKDIR:-}" ]]; then
    log "RDV3_WORKDIR is not set. Please export RDV3_WORKDIR to the desired install path."
    exit 1
  fi
  log "Using RD-V3 install directory: ${RDV3_WORKDIR}"
}

# ------------------------------ RD-V3 ------------------------------

rdv3_install_prereqs() {
  rdv3_select_workdir
  # Install the RD-V3 model into the repo tools directory (same convention as FVP)
  local TOOLS_DIR="${REPO_ROOT}/tools"
  log "Installing prerequisites for RD-V3 model (in ${TOOLS_DIR})"
  mkdir -p "${TOOLS_DIR}"
  pushd "$TOOLS_DIR" >/dev/null

  local MODEL_URL="https://developer.arm.com/-/cdn-downloads/permalink/FVPs-Neoverse-Infrastructure/RD-V3/FVP_RD_V3_11.27_51_Linux64.tgz"
  local MODEL_TGZ="FVP_RD_V3_11.27_51_Linux64.tgz"
  local MODEL_DIR="FVP_RD_V3"
  local INSTALLER_SCRIPT="${MODEL_DIR}/FVP_RD_V3.sh"

  if [ ! -f "$MODEL_TGZ" ]; then
    log "Downloading RD-V3 model..."
    curl -L -o "$MODEL_TGZ" "$MODEL_URL"
  fi

  if [ ! -d "$MODEL_DIR" ]; then
    log "Extracting RD-V3 model..."
    mkdir -p "$MODEL_DIR"
    tar -xzf "$MODEL_TGZ" -C "$MODEL_DIR"
  fi

  if [ -f "$INSTALLER_SCRIPT" ]; then
    chmod +x "$INSTALLER_SCRIPT"
    "$INSTALLER_SCRIPT" --i-agree-to-the-contained-eula --no-interactive --force --destination "$MODEL_DIR"
  else
    log "Installer not found: $INSTALLER_SCRIPT"; exit 1
  fi

  log "RD-V3 model installed"
  popd >/dev/null
}

rdv3_apply_patches() {
  local STACK_DIR="$1"
  local PATCH_DIR="${PATCHES_ROOT}/rdv3"
  log "Applying RD-V3 patches into: $STACK_DIR"

  pushd "$STACK_DIR" >/dev/null
  apply_patch() {
    local repo_path="$1"; local patch_path="$2"; local strip_level="$3"
    [[ -f "$patch_path" ]] || { log "Patch not found: $patch_path"; popd >/dev/null; exit 1; }
    [[ -d "$repo_path" ]] || { log "Repo dir not found: $repo_path"; popd >/dev/null; exit 1; }
    log "Applying $(basename "$patch_path") to $repo_path"
    if patch -d "$repo_path" -p"$strip_level" < "$patch_path"; then
      log "Applied to $repo_path"
    else
      log "Failed patch in $repo_path"; popd >/dev/null; exit 1
    fi
  }

  apply_patch "tf-a" "${PATCH_DIR}/tfa/tfa_rdv3.patch" 1
  apply_patch "build-scripts" "${PATCH_DIR}/build-scripts/build-script-rdv3.patch" 1
  apply_patch "uefi/edk2" "${PATCH_DIR}/edk2/edk2_rdv3.patch" 1

  popd >/dev/null
}

rdv3_build() {
  rdv3_select_workdir
  log "Building RD-V3 stack (in ${RDV3_WORKDIR}) with tag ${RDV3_STACK_TAG}"
  mkdir -p "${RDV3_WORKDIR}"
  pushd "$RDV3_WORKDIR" >/dev/null

  # Derive ACS path like FVP and export ACS_HOME
  local ACS_PATH_DEFAULT="${REPO_ROOT}"
  local ACS_PATH_VAL="${ACS_PATH:-$ACS_PATH_DEFAULT}"
  export ACS_HOME="$ACS_PATH_VAL"

  # Ensure PLATFORM_BASEFVP is 0 for RDV3 builds (idempotent)
  local EL3_CONFIG="${ACS_HOME}/pal_el3/include/pal_el3_config.h"
  if [[ ! -f "$EL3_CONFIG" ]]; then
    log "pal_el3_config.h not found: $EL3_CONFIG";popd >/dev/null; exit 1
  fi

  log "Ensuring PLATFORM_BASEFVP=0 in $EL3_CONFIG"
  if grep -Eq '^[[:space:]]*#define[[:space:]]+PLATFORM_BASEFVP' "$EL3_CONFIG"; then
    sed -i -E 's/(^[[:space:]]*#define[[:space:]]+PLATFORM_BASEFVP[[:space:]]+)[0-9]+/\1 0/' "$EL3_CONFIG"
  else
    printf '\n#define PLATFORM_BASEFVP 0\n' >> "$EL3_CONFIG"
  fi


  mkdir -p "${HOME}/.bin"; export PATH="${HOME}/.bin:${PATH}"
  if [ ! -f "${HOME}/.bin/repo" ]; then
    log "Installing repo tool to ~/.bin"
    curl -s https://storage.googleapis.com/git-repo-downloads/repo -o "${HOME}/.bin/repo"
    chmod a+rx "${HOME}/.bin/repo"
  fi

  local STACK_DIR="${RDV3_WORKDIR}"
  # Initialize only if not already a repo (presence of .repo)
  if [ ! -d "$STACK_DIR/.repo" ]; then
    log "Initializing RDInfra manifest in $STACK_DIR"
    mkdir -p "$STACK_DIR"
    pushd "$STACK_DIR" >/dev/null
    repo init -u https://git.gitlab.arm.com/infra-solutions/reference-design/infra-refdesign-manifests.git \
              -m pinned-rdv3.xml -b "refs/tags/${RDV3_STACK_TAG}"
    repo sync -c -j "$(nproc)" --fetch-submodules --force-sync --no-clone-bundle
    popd >/dev/null
  else
    log "Stack already initialized: $STACK_DIR"
  fi

  # Always reset stack to the requested RDV3 tag and clean local changes
  log "Resetting RD-V3 stack to ${RDV3_STACK_TAG} and cleaning local changes"
  pushd "$STACK_DIR" >/dev/null
  repo init -u https://git.gitlab.arm.com/infra-solutions/reference-design/infra-refdesign-manifests.git \
            -m pinned-rdv3.xml -b "refs/tags/${RDV3_STACK_TAG}"
  # Discard any previous local edits/patches
  repo forall -c 'git reset --hard; git clean -fdx'
  # Force sync to manifest tag, detach from any branches
  repo sync -c -j "$(nproc)" --fetch-submodules --force-sync --no-clone-bundle -d
  popd >/dev/null

  rdv3_apply_patches "$STACK_DIR"

  log "Installing RDInfra stack prerequisites"
  pushd "$STACK_DIR" >/dev/null
  ./build-scripts/rdinfra/install_prerequisites.sh || { \
    log "RDInfra prerequisites installation failed"; \
    popd >/dev/null; \
    exit 1; \
  }

  log "Building RDV3 UEFI stack"
  ./build-scripts/build-test-uefi.sh -p rdv3 all

  log "Copying example PCIe hierarchy JSON"
  cp "${REPO_ROOT}/tools/configs/pcie/rdv3/example_pcie_hierarchy_1.json" model-scripts/rdinfra/platforms/rdv3/
  popd >/dev/null

  popd >/dev/null
  log "RD-V3 build complete"
}

rdv3_run() {
  rdv3_select_workdir
  log "Running RD-V3 model (stack in ${RDV3_WORKDIR})"
  # Model is installed under tools dir
  local TOOLS_DIR="${REPO_ROOT}/tools"
  local MODEL_BIN_PATH="${TOOLS_DIR}/FVP_RD_V3/models/Linux64_GCC-9.3/FVP_RD_V3"
  export MODEL="$MODEL_BIN_PATH"
  [[ -x "$MODEL" ]] || { log "Model binary not found/executable: $MODEL"; popd >/dev/null; exit 1; }
  # Work within RDV3 working directory for stack/model scripts
  pushd "$RDV3_WORKDIR" >/dev/null
  local STACK_DIR="${RDV3_WORKDIR}"
  local PLATFORM_MODEL_DIR="${STACK_DIR}/model-scripts/rdinfra/platforms/rdv3"

  [[ -f "${ACS_UEFI_IMAGE:-}" ]] || { log "ACS_UEFI_IMAGE not found: ${ACS_UEFI_IMAGE:-<unset>}"; popd >/dev/null; exit 1; }
  [[ -x "${PLATFORM_MODEL_DIR}/run_model.sh" ]] || { log "run_model.sh missing: ${PLATFORM_MODEL_DIR}/run_model.sh"; popd >/dev/null; exit 1; }

  ( cd "$PLATFORM_MODEL_DIR" && ./run_model.sh -v "$ACS_UEFI_IMAGE" )

  popd >/dev/null
  log "RD-V3 run complete"
}

# ---------------------------- Arg Parsing ---------------------------

if [[ $# -eq 0 ]]; then usage; exit 1; fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--platform)
      PLATFORM="$2"; shift 2 ;;
    -env|--environment)
      ENVIRONMENT="$2"; shift 2 ;;
    --install-prerequisites)
      ACTION="install"; shift ;;
    build)
      ACTION="build"; shift ;;
    run)
      ACTION="run"; shift ;;
    *)
      log "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$PLATFORM" || -z "$ACTION" ]]; then usage; exit 1; fi
if [[ ! " ${SUPPORTED_PLATFORMS[*]} " =~ " ${PLATFORM} " ]]; then
  log "Unsupported platform: $PLATFORM"; usage; exit 1
fi

# Normalize/validate env
if [[ "$PLATFORM" == "rdv3" ]]; then
  ENVIRONMENT="uefi"
elif [[ -z "${ENVIRONMENT}" ]]; then
  log "Missing -env for platform $PLATFORM"; usage; exit 1
elif [[ ! " ${SUPPORTED_ENVS[*]} " =~ " ${ENVIRONMENT} " ]]; then
  log "Unsupported env: $ENVIRONMENT"; usage; exit 1
fi

# ---------------------------- Dispatch -----------------------------

case "$PLATFORM" in
  aemfvp-a)
    case "$ACTION" in
      install) fvp_install_prereqs ;;
      build)   fvp_build "$ENVIRONMENT" ;;
      run)     fvp_run   "$ENVIRONMENT" ;;
      *) usage; exit 1 ;;
    esac
    ;;
  rdv3)
    case "$ACTION" in
      install) rdv3_install_prereqs ;;
      build)   rdv3_build ;;
      run)     rdv3_run ;;
      *) usage; exit 1 ;;
    esac
    ;;
esac

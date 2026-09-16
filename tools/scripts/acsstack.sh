#!/bin/bash

## @file
#  Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

set -Eeuo pipefail

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
RDV3_STACK_TAG="RD-INFRA-2025.07.03"

LOG_FILE="${REPO_ROOT}/rme_sysarch_acs.log"

SUPPORTED_PLATFORMS=("aemfvp-a" "rdv3")
SUPPORTED_ENVS=("bm" "uefi")
PLATFORM=""
ENVIRONMENT=""
ACTION=""
BUILD_RUNTIME="${ACS_BUILD_RUNTIME:-docker}"

log() {
    echo "["$(date '+%Y-%m-%d %H:%M:%S')"] $*" | tee -a "$LOG_FILE"
}

error_handler() {
    local status="$1"
    local line="$2"
    local command="$3"

    # Avoid recursively invoking this handler if reporting the error fails.
    trap - ERR
    set +e
    log "ERROR: command failed with status ${status} at line ${line}: ${command}"
    exit "$status"
}

trap 'error_handler "$?" "$LINENO" "$BASH_COMMAND"' ERR

usage() {
  cat <<EOF
Usage:
  $0 -p <aemfvp-a|rdv3> -env <bm|uefi> [--runtime <docker|native>] --install-prerequisites
  $0 -p <aemfvp-a|rdv3> -env <bm|uefi> [--runtime <docker|native>] build
  $0 -p <aemfvp-a|rdv3> -env <bm|uefi> run

Notes:
  - If -p rdv3, -env is forced to uefi.
  - Builds use Docker by default. Use --runtime native or set
    ACS_BUILD_RUNTIME=native to use the host toolchain and dependencies.
  - Model runs remain native regardless of the selected build runtime.

  - AEM FVP-A environment variables (required for -p aemfvp-a):
    SHRINKWRAP_BUILD /       Path to build and package directories for shrinkwrap.
    SHRINKWRAP_PACKAGE
    ACS_UEFI_IMAGE           Path to ACS UEFI IMAGE when -env uefi is set.
    FVP_BASE_MODEL           Optional Base FVP binary override.
    SHRINKWRAP_IMAGE         Optional Shrinkwrap build container image.

  - RD-V3 environment variables (required for -p rdv3):
    RDV3_WORKDIR             Install/work directory for RD-V3 model and stack (required)
    ACS_UEFI_IMAGE           Path to ACS UEFI Image
    RDV3_MODEL               Optional RD-V3 FVP binary override.
    RDV3_DOCKER_IMAGE        Optional RDInfra build container image.
    RDV3_DOCKER_REBUILD      Set to 1 to rebuild the RDInfra image.
EOF
}

offer_native_build() {
    local reason="$1"
    local response=""

    log "$reason"
    if [[ -t 0 && -t 1 ]]; then
        printf 'Continue with the native build path? [y/N] '
        if read -r response; then
            case "$response" in
                y|Y|yes|YES)
                    BUILD_RUNTIME="native"
                    export ACS_BUILD_RUNTIME="$BUILD_RUNTIME"
                    log "Continuing with explicitly approved native build"
                    return 0
                    ;;
            esac
        fi
    fi

    log "Re-run with --runtime native or ACS_BUILD_RUNTIME=native to use the host build path"
    return 1
}

prepare_build_runtime() {
    case "$BUILD_RUNTIME" in
        native)
            log "Using native build runtime"
            return 0
            ;;
        docker)
            ;;
        *)
            log "Unsupported build runtime: $BUILD_RUNTIME (use docker or native)"
            exit 1
            ;;
    esac

    if ! command -v docker >/dev/null 2>&1; then
        offer_native_build "Docker was not found in PATH"
        return
    fi

    local docker_error=""
    if ! docker_error="$(docker info 2>&1)"; then
        case "$docker_error" in
            *[Pp]ermission\ denied*)
                offer_native_build "Docker is installed, but this user cannot access the daemon"
                ;;
            *[Cc]annot\ connect*|*[Dd]aemon*not*running*)
                offer_native_build "Docker is installed, but the daemon is unavailable"
                ;;
            *)
                offer_native_build "Docker is installed, but it is not usable"
                ;;
        esac
        return
    fi

    log "Using Docker build runtime"
}

# ------------------------ AEM FVP-A (bm|uefi) ------------------------

fvp_install_prereqs() {
    log "Installing prerequisites for AEM FVP-A (bm|uefi)"
    local TOOLS_DIR="${REPO_ROOT}/tools"
    local TOOLCHAIN_VERSION="13.2.rel1"
    local GNU_DOWNLOAD_BASE="https://developer.arm.com/-/media/Files/"
    GNU_DOWNLOAD_BASE+="downloads/gnu"
    local FVP_TAR="FVP_Base_RevC_AEMvA_11.32_19_Linux_x86.tar.gz"
    local FVP_URL="https://developer.arm.com/-/cdn-downloads/permalink/"
    FVP_URL+="FVPs-Architecture/FM-11.32/${FVP_TAR}"
    local FVP_DIR_NAME="Base_RevC_AEMvA_pkg"
    local FVP_INSTALLER="FVP_Base_RevC_AEMvA_11.32_19_Linux_x86.sh"
    local FVP_VERSION="11.32.19"
    local FVP_VERSION_FILE="${FVP_DIR_NAME}/.acs-model-version"
    local INSTALLED_FVP_VERSION=""
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
            git acpica-tools bc bison build-essential curl debhelper \
            flex genext2fs \
            gperf libxml2 libxml2-dev libxml2-utils libxml-libxml-perl make \
            openssh-server openssh-client expect bridge-utils python3 \
            python3-pip \
            device-tree-compiler autopoint doxygen xterm ninja-build \
            uuid-dev wget zip mtools autoconf locales sbsigntool \
            pkg-config gdisk \
            srecord libssl-dev libelf-dev virtualenv ninja-build tmux cmake \
            netcat-openbsd python3-venv telnet \
            || true


    else
        log \
            "apt-get not found; ensure packages are installed" \
            "per prerequisites list"
    fi

    # Validated with both UEFI and bare-metal stacks. Release 2026.6.0 lacks
    # the pip installation support used below, so pin this later commit.
    local SHRINKWRAP_REVISION="${SHRINKWRAP_REVISION:-f91e589ba8a61dab6ff6ca7b0904ac0e1755d71c}"

    # Use a pinned repository-local shrinkwrap checkout. This avoids silently
    # using a stale system installation when one happens to be present in PATH.
    if [ ! -d "${SHRINKWRAP_DIR}/.git" ]; then
        log "Cloning shrinkwrap into tools/"
        git clone \
            https://git.gitlab.arm.com/tooling/shrinkwrap.git \
            "$SHRINKWRAP_DIR"
    else
        log "Updating shrinkwrap checkout in tools/"
    fi
    git -C "$SHRINKWRAP_DIR" fetch --prune --tags origin
    log "Checking out shrinkwrap revision: ${SHRINKWRAP_REVISION}"
    git -C "$SHRINKWRAP_DIR" checkout --detach "$SHRINKWRAP_REVISION"
    log "Using shrinkwrap commit $(git -C "$SHRINKWRAP_DIR" rev-parse HEAD)"

    # Create and update a Python virtual environment
    # for shrinkwrap deps at tools/.venv
    if [ ! -d "$TOOLS_VENV" ]; then
        log "Creating virtual environment at tools/.venv"
        python3 -m venv "$TOOLS_VENV"
    fi
    log "Installing/updating shrinkwrap Python dependencies in tools/.venv"
    (
        source "$TOOLS_VENV/bin/activate"
        python -m pip install --upgrade pip
        python -m pip install --upgrade "./${SHRINKWRAP_DIR}"
        deactivate
    )

    if [[ "$BUILD_RUNTIME" == "native" ]]; then
        local elf_toolchain_tar="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-"
        elf_toolchain_tar+="x86_64-aarch64-none-elf.tar.xz"
        if [[ ! -d \
            "arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-elf" \
        ]]; then
            log "Downloading aarch64-none-elf toolchain..."
            local elf_toolchain_url="${GNU_DOWNLOAD_BASE}/"
            elf_toolchain_url+="${TOOLCHAIN_VERSION}/binrel/${elf_toolchain_tar}"
            curl -LO "$elf_toolchain_url"
            tar -xf "$elf_toolchain_tar"
        fi

        local linux_toolchain_tar="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-"
        linux_toolchain_tar+="x86_64-aarch64-none-linux-gnu.tar.xz"
        if [[ ! -d \
            "arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu" \
        ]]; then
            log "Downloading aarch64-none-linux-gnu toolchain..."
            local linux_toolchain_url="${GNU_DOWNLOAD_BASE}/"
            linux_toolchain_url+="${TOOLCHAIN_VERSION}/binrel/"
            linux_toolchain_url+="$linux_toolchain_tar"
            curl -LO "$linux_toolchain_url"
            tar -xf "$linux_toolchain_tar"
        fi
    else
        log "Docker supplies the build toolchains; skipping host toolchain downloads"
    fi

    if [[ -f "$FVP_VERSION_FILE" ]]; then
        INSTALLED_FVP_VERSION="$(<"$FVP_VERSION_FILE")"
    fi
    if [[ "$INSTALLED_FVP_VERSION" != "$FVP_VERSION" ]]; then
        log "Installing Base RevC FVP model ${FVP_VERSION}..."
        if [[ ! -f "$FVP_TAR" ]]; then
            curl -L -o "$FVP_TAR" "$FVP_URL"
        fi
        tar -xf "$FVP_TAR" "$FVP_INSTALLER"
        chmod +x "$FVP_INSTALLER"
        "./$FVP_INSTALLER" \
            --i-agree-to-the-contained-eula \
            --no-interactive \
            --force \
            --destination "$FVP_DIR_NAME"
        printf '%s\n' "$FVP_VERSION" > "$FVP_VERSION_FILE"
    fi

    popd >/dev/null
    log "AEM FVP-A prerequisites installed"
}

fvp_preflight() {
    local operation="${1:-run}"
    log "AEM FVP-A preflight checks"

    local ACS_PATH_DEFAULT="${REPO_ROOT}"
    local ACS_PATH_VAL="${ACS_PATH:-$ACS_PATH_DEFAULT}"
    local PCIE_JSON_PATH=""
    local TOOLCHAIN_ELF_BIN=""
    local TOOLCHAIN_LINUX_BIN=""

    PCIE_JSON_PATH="${REPO_ROOT}/tools/configs/pcie/aemfvp-a/"
    PCIE_JSON_PATH+="pcie_hierarchy.json"
    [[ -d "$CONFIGS_ROOT" ]] || { log "Missing ${CONFIGS_ROOT}"; exit 1; }
    [[ -d "$ACS_PATH_VAL" ]] || {
        log "Missing ACS_PATH: $ACS_PATH_VAL"
        exit 1
    }
    [[ -d "${SHRINKWRAP_BUILD:-}" ]] || {
        log "Missing SHRINKWRAP_BUILD: ${SHRINKWRAP_BUILD:-<unset>}"
        exit 1
    }
    [[ -d "${SHRINKWRAP_PACKAGE:-}" ]] || {
        log "Missing SHRINKWRAP_PACKAGE: ${SHRINKWRAP_PACKAGE:-<unset>}"
        exit 1
    }
    [[ -f "${PCIE_JSON_PATH}" ]] || {
        log "Missing ${PCIE_JSON_PATH}"
        exit 1
    }

    # Verify shrinkwrap presence in tools/ and its venv; then activate once
    local TOOLS_DIR="${REPO_ROOT}/tools"
    local SW_DIR="${TOOLS_DIR}/shrinkwrap"
    local TOOLS_VENV="${TOOLS_DIR}/.venv"
    local LOCAL_SW_BIN="${TOOLS_VENV}/bin/shrinkwrap"

    [[ -x "$LOCAL_SW_BIN" ]] || {
        log "shrinkwrap not found at ${LOCAL_SW_BIN}." \
            "Run --install-prerequisites"
        exit 1
    }
    [[ -x "${TOOLS_VENV}/bin/python" ]] || {
        log "venv missing: ${TOOLS_VENV}/bin/python." \
            "Run --install-prerequisites"
        exit 1
    }

    # Always activate and prefer the repository-local checkout installed above.
    if [[ "${VIRTUAL_ENV:-}" != "${TOOLS_VENV}" ]]; then
        . "${TOOLS_VENV}/bin/activate"
        __SW_VENV_ACTIVE=1
        trap '[[ -n "${__SW_VENV_ACTIVE:-}" ]] && deactivate || true' EXIT
    fi
    log "Using shrinkwrap from ${LOCAL_SW_BIN} at commit "\
        "$(git -C "$SW_DIR" rev-parse HEAD)"

    # Docker supplies build toolchains. Native builds and all model runs use
    # the tools installed on the host.
    if [[ "$operation" == "run" || "$BUILD_RUNTIME" == "native" ]]; then
        TOOLCHAIN_ELF_BIN="${TOOLS_DIR}/"
        TOOLCHAIN_ELF_BIN+="arm-gnu-toolchain-13.2.Rel1-"
        TOOLCHAIN_ELF_BIN+="x86_64-aarch64-none-elf/bin"
        TOOLCHAIN_LINUX_BIN="${TOOLS_DIR}/"
        TOOLCHAIN_LINUX_BIN+="arm-gnu-toolchain-13.2.Rel1-"
        TOOLCHAIN_LINUX_BIN+="x86_64-aarch64-none-linux-gnu/bin"
        export PATH="${TOOLCHAIN_ELF_BIN}:${PATH}"
        export PATH="${TOOLCHAIN_LINUX_BIN}:${PATH}"

        local FVP_MODEL="${FVP_BASE_MODEL:-}"
        if [[ -z "$FVP_MODEL" ]]; then
            local candidate=""
            for candidate in \
                "$TOOLS_DIR/Base_RevC_AEMvA_pkg/bin/FVP_Base_RevC-2xAEMvA" \
                "$TOOLS_DIR/Base_RevC_AEMvA_pkg/models/Linux64_GCC-9.3/FVP_Base_RevC-2xAEMvA"; do
                if [[ -x "$candidate" ]]; then
                    FVP_MODEL="$candidate"
                    break
                fi
            done
        fi
        [[ -x "$FVP_MODEL" ]] || {
            log "Base FVP model not found/executable: ${FVP_MODEL:-<unset>}"
            log "Run --install-prerequisites or set FVP_BASE_MODEL"
            exit 1
        }
        export PATH="$(dirname "$FVP_MODEL"):$PATH"
        log "Using Base FVP model: $FVP_MODEL"
    fi
}

fvp_shrinkwrap_build() {
    local config="$1"
    shift
    local runtime_args=(--runtime=null)

    if [[ "$BUILD_RUNTIME" == "docker" ]]; then
        runtime_args=(--runtime=docker)
        if [[ -n "${SHRINKWRAP_IMAGE:-}" ]]; then
            runtime_args+=(--image="$SHRINKWRAP_IMAGE")
        fi
    fi

    shrinkwrap "${runtime_args[@]}" build "$config" "$@"
}

fvp_build() {
    local env="$1"  # bm|uefi

    local ACS_PATH_DEFAULT="${REPO_ROOT}"
    local ACS_PATH_VAL="${ACS_PATH:-$ACS_PATH_DEFAULT}"
    local EL3_CONFIG="${ACS_PATH_VAL}/pal_el3/FVP/include/pal_el3_config.h"
    if [[ ! -f "$EL3_CONFIG" ]]; then
        log "pal_el3_config.h not found: $EL3_CONFIG";popd >/dev/null; exit 1
    fi

    log "Using FVP PAL EL3 config: $EL3_CONFIG"

    fvp_preflight build

    log "Building AEM FVP-A stack for env: $env"
    case "$env" in
        bm)
            fvp_shrinkwrap_build \
                "${CONFIGS_ROOT}/rme-acs-stack-bm.yaml" \
                --btvar ACS_PATH="$ACS_PATH_VAL" \
                --btvar TFA_PATCHES="${PATCHES_ROOT}/aemfvp-a/tfa"
            ;;
        uefi)
            fvp_shrinkwrap_build \
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
    fvp_preflight run

    # FVP resolves paths embedded in the PCIe hierarchy relative to its cwd.
    cd "$REPO_ROOT"

    log "Running AEM FVP-A env: $env"
    case "$env" in
        bm)
            local pcie_json_path="${REPO_ROOT}/tools/configs/pcie/aemfvp-a/"
            pcie_json_path+="pcie_hierarchy.json"
            shrinkwrap --runtime=null run \
                --rtvar=JSON_FILE="${pcie_json_path}" \
                "rme-acs-stack-bm.yaml"
            ;;
        uefi)
            if [[ -z "${ACS_UEFI_IMAGE:-}" ]]; then
                log "ACS_UEFI_IMAGE not set for uefi run"; exit 1
            fi
            local pcie_json_path="${REPO_ROOT}/tools/configs/pcie/aemfvp-a/"
            pcie_json_path+="pcie_hierarchy.json"
            shrinkwrap --runtime=null run \
                --rtvar=JSON_FILE="${pcie_json_path}" \
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
        log \
            "RDV3_WORKDIR is not set." \
            "Please export RDV3_WORKDIR to the desired install path."
        exit 1
    fi
    log "Using RD-V3 install directory: ${RDV3_WORKDIR}"
}

# ------------------------------ RD-V3 ------------------------------

rdv3_install_prereqs() {
    rdv3_select_workdir
    # Install the RD-V3 model into the repo tools directory
    # using the same convention as FVP
    local TOOLS_DIR="${REPO_ROOT}/tools"
    log "Installing prerequisites for RD-V3 model (in ${TOOLS_DIR})"
    mkdir -p "${TOOLS_DIR}"
    pushd "$TOOLS_DIR" >/dev/null

    local MODEL_URL="https://developer.arm.com/-/cdn-downloads/permalink/"
    MODEL_URL+="FVPs-Neoverse-Infrastructure/RD-V3/"
    MODEL_URL+="FVP_RD_V3_11.29_35_Linux64.tgz"
    local MODEL_TGZ="FVP_RD_V3_11.29_35_Linux64.tgz"
    local MODEL_DIR="FVP_RD_V3"
    local MODEL_VERSION="11.29.35"
    local MODEL_VERSION_FILE="${MODEL_DIR}/.acs-model-version"
    local INSTALLER_SCRIPT="FVP_RD_V3.sh"
    local INSTALLED_MODEL_VERSION=""

    if [ ! -f "$MODEL_TGZ" ]; then
        log "Downloading RD-V3 model..."
        curl -L -o "$MODEL_TGZ" "$MODEL_URL"
    fi

    if [[ -f "$MODEL_VERSION_FILE" ]]; then
        INSTALLED_MODEL_VERSION="$(<"$MODEL_VERSION_FILE")"
    fi
    if [[ "$INSTALLED_MODEL_VERSION" != "$MODEL_VERSION" ]]; then
        log "Installing RD-V3 model ${MODEL_VERSION}..."
        tar -xzf "$MODEL_TGZ" "$INSTALLER_SCRIPT"
        chmod +x "$INSTALLER_SCRIPT"
        "./$INSTALLER_SCRIPT" \
            --i-agree-to-the-contained-eula \
            --no-interactive \
            --force \
            --destination "$MODEL_DIR"
        printf '%s\n' "$MODEL_VERSION" > "$MODEL_VERSION_FILE"
    else
        log "RD-V3 model ${MODEL_VERSION} already installed"
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
        local repo_path="$1"
        local patch_path="$2"
        local strip_level="$3"
        [[ -f "$patch_path" ]] || {
            log "Patch not found: $patch_path"
            popd >/dev/null
            exit 1
        }
        [[ -d "$repo_path" ]] || {
            log "Repo dir not found: $repo_path"
            popd >/dev/null
            exit 1
        }
        log "Applying $(basename "$patch_path") to $repo_path"
        if patch -d "$repo_path" -p"$strip_level" < "$patch_path"; then
            log "Applied to $repo_path"
        else
            log "Failed patch in $repo_path"; popd >/dev/null; exit 1
        fi
    }

    apply_patch "tf-a" "${PATCH_DIR}/tfa/tfa_rdv3.patch" 1
    apply_patch \
        "build-scripts" \
        "${PATCH_DIR}/build-scripts/build-script-rdv3.patch" \
        1
    apply_patch "uefi/edk2" "${PATCH_DIR}/edk2/edk2_rdv3.patch" 1
    apply_patch "scp" "${PATCH_DIR}/scp/scp_rdv3.patch" 1

    popd >/dev/null
}

rdv3_build_payload() {
    local stack_dir="${RDV3_WORKDIR}"
    local acs_path="${ACS_PATH}"
    local toolchain_base="${RDV3_TOOLCHAIN_BASE:-${stack_dir}/tools}"
    local host_arch
    local tfa_output="${stack_dir}/tf-a/build/rdv3/0/debug"
    local tfa_toolchain=""

    pushd "$stack_dir" >/dev/null
    log "Building RDV3 UEFI stack"
    ./build-scripts/build-test-uefi.sh -p rdv3 clean
    ./build-scripts/build-test-uefi.sh -p rdv3 build

    log "Relinking TF-A BL31 with the ACS EL3 implementation"
    host_arch="$(uname -m)"
    tfa_toolchain="${toolchain_base}/gcc/"
    tfa_toolchain+="arm-gnu-toolchain-13.2.rel1-${host_arch}-"
    tfa_toolchain+="aarch64-none-elf/bin"
    [[ -x "${tfa_toolchain}/aarch64-none-elf-gcc" ]] || {
        log "RDV3 AArch64 toolchain not found: ${tfa_toolchain}"
        popd >/dev/null
        exit 1
    }
    (
        export PATH="${tfa_toolchain}:${PATH}"
        export CROSS_COMPILE="aarch64-none-elf-"
        make -C "${acs_path}/val_el3" \
            TFA_PATH="${stack_dir}/tf-a" \
            TFA_BUILD_DIR="${tfa_output}" \
            PLAT=rdv3 \
            PAL_EL3_PLAT=rdv3 \
            clean all
        cp "${tfa_output}/bl31/bl31_new.bin" \
            "${tfa_output}/bl31.bin"
        cp "${tfa_output}/bl31/bl31_new.elf" \
            "${tfa_output}/bl31/bl31.elf"
    )

    ./build-scripts/build-test-uefi.sh -p rdv3 package
    popd >/dev/null
}

rdv3_build_docker() {
    local stack_dir="$1"
    local acs_path="$2"
    local container_helper="${stack_dir}/container-scripts/container.sh"
    local image="${RDV3_DOCKER_IMAGE:-rdinfra-builder}"
    local rebuild="${RDV3_DOCKER_REBUILD:-0}"
    local -a image_args=(-i "$image")
    local -a mount_args=(
        --volume "${stack_dir}:${stack_dir}"
        --volume "${REPO_ROOT}:${REPO_ROOT}"
    )

    [[ -x "$container_helper" ]] || {
        log "RDInfra container helper not found: $container_helper"
        exit 1
    }
    if [[ -n "${RDV3_DOCKER_FILE:-}" ]]; then
        image_args+=(-f "$RDV3_DOCKER_FILE")
    fi

    if [[ "$rebuild" == "1" ]]; then
        log "Rebuilding RDInfra Docker image: $image"
        "$container_helper" "${image_args[@]}" -o build
    elif ! docker image inspect "$image" >/dev/null 2>&1; then
        log "Building RDInfra Docker image: $image"
        "$container_helper" "${image_args[@]}" build
    else
        log "Using existing RDInfra Docker image: $image"
    fi

    if [[ "$acs_path" != "$REPO_ROOT" ]]; then
        mount_args+=(--volume "${acs_path}:${acs_path}")
    fi

    log "Running RD-V3 build, ACS BL31 relink, and packaging in Docker"
    docker run --rm \
        --network host \
        "${mount_args[@]}" \
        --mount "type=volume,dst=${HOME}" \
        --workdir "$stack_dir" \
        --env "ARCADE_USER=$(id -un)" \
        --env "ARCADE_UID=$(id -u)" \
        --env "ARCADE_GID=$(id -g)" \
        --env ACS_RDV3_CONTAINER_STAGE=1 \
        --env "RDV3_WORKDIR=${stack_dir}" \
        --env "ACS_PATH=${acs_path}" \
        --env RDV3_TOOLCHAIN_BASE=/opt \
        "$image" \
        "${REPO_ROOT}/tools/scripts/acsstack.sh"
}

rdv3_build() {
    rdv3_select_workdir
    log "Building RD-V3 stack (in ${RDV3_WORKDIR}) with tag ${RDV3_STACK_TAG}"
    mkdir -p "${RDV3_WORKDIR}"
    pushd "$RDV3_WORKDIR" >/dev/null

    # Derive ACS path like FVP and export ACS_HOME
    local ACS_PATH_DEFAULT="${REPO_ROOT}"
    local ACS_PATH_VAL="${ACS_PATH:-$ACS_PATH_DEFAULT}"
    local MANIFEST_URL=""
    export ACS_HOME="$ACS_PATH_VAL"
    export ACS_PATH="$ACS_PATH_VAL"
    MANIFEST_URL="https://git.gitlab.arm.com/infra-solutions/reference-design"
    MANIFEST_URL+="/infra-refdesign-manifests.git"

    local EL3_CONFIG="${ACS_HOME}/pal_el3/rdv3/include/pal_el3_config.h"
    if [[ ! -f "$EL3_CONFIG" ]]; then
        log "pal_el3_config.h not found: $EL3_CONFIG";popd >/dev/null; exit 1
    fi

    log "Using RD-V3 PAL EL3 config: $EL3_CONFIG"


    mkdir -p "${HOME}/.bin"
    export PATH="${HOME}/.bin:${PATH}"
    if [ ! -f "${HOME}/.bin/repo" ]; then
        log "Installing repo tool to ~/.bin"
        curl -s \
            https://storage.googleapis.com/git-repo-downloads/repo \
            -o "${HOME}/.bin/repo"
        chmod a+rx "${HOME}/.bin/repo"
    fi

    local STACK_DIR="${RDV3_WORKDIR}"
    local STACK_INITIALIZED=false
    [[ -d "$STACK_DIR/.repo" ]] && STACK_INITIALIZED=true

    log "Initializing RDInfra manifest ${RDV3_STACK_TAG} in $STACK_DIR"
    pushd "$STACK_DIR" >/dev/null
    repo init -u "$MANIFEST_URL" \
        -m pinned-rdv3.xml \
        -b "refs/tags/${RDV3_STACK_TAG}"

    if [[ "$STACK_INITIALIZED" == true ]]; then
        log "Cleaning existing RD-V3 checkouts before sync"
        repo forall --ignore-missing \
            -c 'git reset --hard; git clean -fdx'
    fi

    repo sync -c -j "$(nproc)" \
        --recurse-submodules \
        --force-sync \
        --no-clone-bundle \
        -d
    popd >/dev/null

    rdv3_apply_patches "$STACK_DIR"

    if [[ "$BUILD_RUNTIME" == "docker" ]]; then
        rdv3_build_docker "$STACK_DIR" "$ACS_PATH_VAL"
    else
        log "Installing RDInfra stack prerequisites"
        pushd "$STACK_DIR" >/dev/null
        ./build-scripts/rdinfra/install_prerequisites.sh || {
            log "RDInfra prerequisites installation failed"
            popd >/dev/null
            exit 1
        }
        popd >/dev/null
        rdv3_build_payload
    fi

    log "Copying example PCIe hierarchy JSON"
    cp \
        "${REPO_ROOT}/tools/configs/pcie/rdv3/example_pcie_hierarchy_1.json" \
        model-scripts/rdinfra/platforms/rdv3/
    popd >/dev/null
    log "RD-V3 build complete"
}

rdv3_run() {
    local required_tool
    for required_tool in telnet grep tee sleep; do
        command -v "$required_tool" >/dev/null 2>&1 || {
            printf 'Error: required tool not found: %s\n' \
                "$required_tool" >&2
            exit 1
        }
    done

    rdv3_select_workdir
    log "Running RD-V3 model (stack in ${RDV3_WORKDIR})"
    # Use an explicit model override when supplied; otherwise use the public
    # model installed by rdv3_install_prereqs.
    local TOOLS_DIR="${REPO_ROOT}/tools"
    local MODEL_BIN_PATH="${RDV3_MODEL:-}"
    if [[ -z "$MODEL_BIN_PATH" ]]; then
        MODEL_BIN_PATH="${TOOLS_DIR}/FVP_RD_V3/models/Linux64_GCC-9.3/"
        MODEL_BIN_PATH+="FVP_RD_V3"
    fi
    export MODEL="$MODEL_BIN_PATH"
    [[ -x "$MODEL" ]] || {
        log "Model binary not found/executable: $MODEL"
        exit 1
    }

    local STACK_DIR="${RDV3_WORKDIR}"
    local PLATFORM_MODEL_DIR="${STACK_DIR}/model-scripts/rdinfra/platforms/"
    PLATFORM_MODEL_DIR+="rdv3"

    [[ -f "${ACS_UEFI_IMAGE:-}" ]] || {
        log "ACS_UEFI_IMAGE not found: ${ACS_UEFI_IMAGE:-<unset>}"
        exit 1
    }
    [[ -x "${PLATFORM_MODEL_DIR}/run_model.sh" ]] || {
        log "run_model.sh missing: ${PLATFORM_MODEL_DIR}/run_model.sh"
        exit 1
    }

    log "Using RD-V3 FVP model: $MODEL"
    (
        cd "$PLATFORM_MODEL_DIR"

        local MODEL_LOG="${PLATFORM_MODEL_DIR}/model.log"
        local UART_LOG="${PLATFORM_MODEL_DIR}/uart0.log"
        local MODEL_PID=""
        local UART0_PORT=""
        local STARTUP_TIMEOUT_SECONDS=120

        cleanup() {
            local status=$?
            trap - EXIT

            if [[ -n "$MODEL_PID" ]] && kill -0 "$MODEL_PID" 2>/dev/null; then
                log "Stopping RD-V3 model (PID ${MODEL_PID})"
                kill "$MODEL_PID" 2>/dev/null || true
                wait "$MODEL_PID" 2>/dev/null || true
            fi

            log "RD-V3 model log: ${MODEL_LOG}"
            log "RD-V3 UART0 log: ${UART_LOG}"
            return "$status"
        }
        trap cleanup EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM

        : >"$UART_LOG"
        if ! ./run_model.sh -f busybox -v "$ACS_UEFI_IMAGE" -j \
            >"$MODEL_LOG" 2>&1; then
            log "RD-V3 model launcher failed; see ${MODEL_LOG}"
            exit 1
        fi
        log "Waiting for the RD-V3 model and UART0"

        local elapsed
        local line
        for ((elapsed = 0; elapsed < STARTUP_TIMEOUT_SECONDS; elapsed++)); do
            if [[ -z "$MODEL_PID" ]]; then
                line=$(grep -m1 -E \
                    'Model launched with pid: [0-9]+' "$MODEL_LOG" || true)
                if [[ "$line" =~ Model\ launched\ with\ pid:\ ([0-9]+) ]]; then
                    MODEL_PID="${BASH_REMATCH[1]}"
                    log "RD-V3 model PID: ${MODEL_PID}"
                fi
            fi

            if [[ -z "$UART0_PORT" ]]; then
                line=$(grep -m1 -E \
                    'terminal_ns_uart0: Listening for serial connection on port [0-9]+' \
                    "$MODEL_LOG" || true)
                if [[ "$line" =~ port\ ([0-9]+) ]]; then
                    UART0_PORT="${BASH_REMATCH[1]}"
                fi
            fi

            if [[ -n "$MODEL_PID" && -n "$UART0_PORT" ]]; then
                break
            fi
            if [[ -n "$MODEL_PID" ]] \
                && ! kill -0 "$MODEL_PID" 2>/dev/null; then
                log "RD-V3 model exited before UART0 became available"
                exit 1
            fi
            sleep 1
        done

        if [[ -z "$MODEL_PID" || -z "$UART0_PORT" ]]; then
            log "Timed out waiting for RD-V3 UART0; see ${MODEL_LOG}"
            exit 1
        fi

        log "Connecting to RD-V3 UART0 on localhost:${UART0_PORT}"
        log "UART output is also saved to ${UART_LOG}"
        log "Use Ctrl-] then 'quit', or Ctrl-C, to stop the run"

        local telnet_status=0
        telnet localhost "$UART0_PORT" | tee -a "$UART_LOG" \
            || telnet_status=$?
        if ((telnet_status != 0)); then
            log "UART0 telnet connection failed with status ${telnet_status}"
            exit "$telnet_status"
        fi
    )

    log "RD-V3 run complete"
}

# ---------------------------- Arg Parsing ---------------------------

if [[ "${ACS_RDV3_CONTAINER_STAGE:-0}" == "1" ]]; then
    [[ -d "${RDV3_WORKDIR:-}" ]] || {
        log "RDV3_WORKDIR is missing inside the build container"
        exit 1
    }
    [[ -d "${ACS_PATH:-}" ]] || {
        log "ACS_PATH is missing inside the build container"
        exit 1
    }
    rdv3_build_payload
    exit 0
fi

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--platform)
            PLATFORM="$2"; shift 2 ;;
        -env|--environment)
            ENVIRONMENT="$2"; shift 2 ;;
        --runtime)
            if [[ $# -lt 2 ]]; then
                log "Missing value for --runtime"
                usage
                exit 1
            fi
            BUILD_RUNTIME="$2"; shift 2 ;;
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

if [[ -z "$PLATFORM" || -z "$ACTION" ]]; then
    usage
    exit 1
fi
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

if [[ "$ACTION" == "build" \
    || ( "$ACTION" == "install" && "$PLATFORM" == "aemfvp-a" ) \
]]; then
    prepare_build_runtime
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

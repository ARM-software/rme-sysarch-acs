# Tools / Scripts

This directory contains helper scripts to build and run the RME ACS on different platforms, plus a few maintenance utilities.

## Overview

- `acsstack.sh`: Unified entrypoint to build software stack and run ACS on:
  - `aemfvp-a` (Base RevC AEM FVP-A) for `bm` and `uefi` environments
  - `rdv3` (Reference Design V3) for `uefi`

A global log is written to `rme_sysarch_acs.log` at the repository root by `acsstack.sh`.

## acsstack.sh

Unified driver for both Base FVP and RD‑V3 flows. Run `tools/scripts/acsstack.sh` for usage.

### Required environment

`aemfvp-a` (AEM FVP-A):
- `SHRINKWRAP_BUILD` and `SHRINKWRAP_PACKAGE`: existing directories for shrinkwrap outputs.
- `ACS_UEFI_IMAGE`: required only for `uefi` run; used as both `ROOTFS` and `KERNEL`.
- `FVP_BASE_MODEL`: optional path to a Base FVP binary. If unset, the public model installed under `tools/` is used.
- `SHRINKWRAP_REVISION`: optional Shrinkwrap Git revision override. It defaults to the pinned commit `f91e589ba8a61dab6ff6ca7b0904ac0e1755d71c`, validated with both UEFI and bare-metal stacks. This commit includes the pip installation support absent from release `2026.6.0`.
- `SHRINKWRAP_IMAGE`: optional override for the Shrinkwrap build container image.

RD‑V3:
- `RDV3_WORKDIR` (required): install/work directory for the RD‑V3 stack and scripts.
- `ACS_UEFI_IMAGE` (required for run): UEFI image passed to the platform model.
- `RDV3_MODEL`: optional path to an RD‑V3 FVP binary. If unset, the public model installed under `tools/` is used.
- `RDV3_DOCKER_IMAGE`: optional RDInfra build image override. The default is `rdinfra-builder`.
- `RDV3_DOCKER_REBUILD=1`: force the RDInfra build image to be rebuilt.

### Usage

```
# Install prerequisites for a platform
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> --install-prerequisites

# Build a stack
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> build

# Explicitly use host tools instead of Docker
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> --runtime native build

# Run a stack
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> run
```

Notes:
- If `-p rdv3`, `-env` is forced to `uefi`.
- Builds use Docker by default. `ACS_BUILD_RUNTIME=native` is equivalent to `--runtime native`.
- If Docker is unavailable, an interactive invocation offers the native path. Non-interactive invocations fail and print the explicit override.
- Model runs remain native so that UART, telnet, and optional GUI behavior is unchanged.

### What install does

- FVP: updates the repository-local Shrinkwrap checkout and installs Base RevC model 11.32.19 into `tools/` if needed. Docker is the default and supplies the build toolchains; host toolchains are downloaded only when `--runtime native` or `ACS_BUILD_RUNTIME=native` is selected. The local Shrinkwrap checkout is always preferred over an executable already in `PATH`.
- RD‑V3: downloads RD‑V3 model 11.29.35 into `tools/` if not already present.

### What build does

- AEM FVP-A: invokes Shrinkwrap's Docker runtime with configs under `tools/configs/shrinkwrap/` and platform-specific patches under `tools/patches/aemfvp-a/`.
- RD‑V3: initializes RDInfra tag `RD-INFRA-2025.07.03` directly in `"$RDV3_WORKDIR"` (if not already initialized), applies patches from `tools/patches/rdv3/`, and uses RDInfra's existing container definition to build the UEFI stack, relink BL31 with the ACS EL3 implementation, and package the result. The host prerequisite installer is used only by the native build path.

### What run does

- FVP: runs via shrinkwrap. For `uefi`, passes `ACS_UEFI_IMAGE` as both `ROOTFS` and `KERNEL`.
- RD‑V3: executes `model-scripts/rdinfra/platforms/rdv3/run_model.sh` in headless mode, discovers the non-secure UART0 telnet port, and streams its output to the terminal and `model-scripts/rdinfra/platforms/rdv3/uart0.log`. The model launcher output is written to `model-scripts/rdinfra/platforms/rdv3/model.log`. The run fails before starting the model if `telnet` or another required host tool is unavailable.

## Models and patches

- FVP model is installed under `tools/Base_RevC_AEMvA_pkg`.
- RD‑V3 model is installed under `tools/FVP_RD_V3`.
- Patches applied by `acsstack.sh`:
  - AEM FVP‑A TF‑A patches: `tools/patches/aemfvp-a/`
  - RD‑V3 patches: `tools/patches/rdv3/`

## Logs

- Main log: `rme_sysarch_acs.log` (repository root), appended by `acsstack.sh`.

## Troubleshooting

- Missing env vars: the script will exit with a helpful message if required variables (e.g., `RDV3_WORKDIR`, `ACS_HOME`, `SHRINKWRAP_*`) are not set.
- Missing local Shrinkwrap: re-run the AEM FVP-A `--install-prerequisites` command.
- Model binaries not found: re‑run `--install-prerequisites` for the relevant platform.

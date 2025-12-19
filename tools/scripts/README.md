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

RD‑V3:
- `RDV3_WORKDIR` (required): install/work directory for the RD‑V3 stack and scripts.
- `ACS_UEFI_IMAGE` (required for run): UEFI image passed to the platform model.

### Usage

```
# Install prerequisites for a platform
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> --install-prerequisites

# Build a stack
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> build

# Run a stack
./tools/scripts/acsstack.sh -p <aemfvp-a|rdv3> -env <bm|uefi> run
```

Notes:
- If `-p rdv3`, `-env` is forced to `uefi`.

### What install does

- FVP: downloads toolchains and the Base RevC model into `tools/` if not already present.
- RD‑V3: downloads the RD‑V3 model into `tools/` if not already present.

### What build does

- AEM FVP-A: invokes shrinkwrap with configs under `tools/configs/shrinkwarp/` and platform-specific patches under `tools/patches/aemfvp-a/`.
- RD‑V3: initializes the RDInfra manifest directly in `"$RDV3_WORKDIR"` (if not already initialized), applies patches from `tools/patches/rdv3/`, installs stack prerequisites, and builds the UEFI stack.

### What run does

- FVP: runs via shrinkwrap. For `uefi`, passes `ACS_UEFI_IMAGE` as both `ROOTFS` and `KERNEL`.
- RD‑V3: runs the RD‑V3 model from `tools/FVP_RD_V3/...` and executes `model-scripts/rdinfra/platforms/rdv3/run_model.sh` from within the stack directory, passing `-v "$ACS_UEFI_IMAGE"`.

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
- `shrinkwrap` not in `PATH`: ensure shrinkwrap is installed and available.
- Model binaries not found: re‑run `--install-prerequisites` for the relevant platform.

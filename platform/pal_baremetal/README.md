# Baremetal README
**Please Note**: The code in the "pal_baremetal" directory is only a reference code for implementation of PAL APIs and it has not been verified on any model or SoCs.
The directory pal_baremetal consists of the reference code of the PAL API's specific to a platform.
Description of each directory are as follows:

## Directory Structure

&emsp; - **include**: Consists of the include files required for Baremetal RME ACS. \
&emsp; - **src**: Source files consisting platform specific implementations some of which require user modification. \
&emsp; - **FVP**: Contains platform configuration information. The details in this folder need to be modified w.r.t the platform \

## Build Steps

1. To compile Baremetal RME ACS, perform the following steps \
&emsp; 1.1 cd rme-acs \
&emsp; 1.2 git submodule update --init \
&emsp; 1.3 export CROSS_COMPILE=<path_to_the_toolchain>/bin/aarch64-none-elf- \
&emsp; 1.4 mkdir build \
&emsp; 1.5 cd build \
&emsp; 1.6 cmake ../ -G"Unix Makefiles" -DCROSS_COMPILE=$CROSS_COMPILE -DTARGET="Target platform" \
&emsp; 1.7 make

Note: Reference Cmake file for RME ACS is present at [CMakeLists.txt](../../CMakeLists.txt).

*Recommended*: CMake v3.17, GCC v12.2
```
CMake Command Line Options:
 -DARM_ARCH_MAJOR = Arch major version. Default value is 9.
 -DARM_ARCH_MINOR = Arch minor version. Default value is 0.
 -DCROSS_COMPILE  = Cross compiler path
 -DTARGET         = Target platform. Should be same as folder under pal_baremetal. Defaults to "FVP".
 -DTARGET_SIMULATION=ON to enable simulation/emulation helpers (defines TARGET_SIMULATION). Speeds up GIC init and other tight loops for fast models; leave OFF for real hardware.
 -DSKIP_SMMU_GIC_ITS_INIT = Set to 1 to skip SMMU and GIC ITS initialization, or 0 to initialize them. Only 0 and 1 are accepted. Default 0.
 -DENABLE_SPDM    = Build with libspdm and DOE/CXL requester helpers (ON/OFF). Default OFF.
 -DACS_PRINT_LEVEL= ACS print verbosity (1..5). Default 3. 3 prints TEST/ALWAYS/WARN/ERR; 2 also enables DEBUG; 1 also enables INFO.
 -DACS_ENABLED_MODULE_LIST=<comma-separated module IDs> sets which modules are enabled to run by default (all modules are still built). Runtime overrides still take priority. Example: -DACS_ENABLED_MODULE_LIST="RME_MODULE,GIC_MODULE,SMMU_MODULE". Valid IDs: RME_MODULE, LEGACY_MODULE, GIC_MODULE, SMMU_MODULE, DA_MODULE, DPT_MODULE, MEC_MODULE, CXL_MODULE, CDA_MODULE, TDISP_MODULE.
```

On a successful build, *.bin, *.elf, *.img and debug binaries are generated at *build/output* directory. The output library files will be generated at *build/tools/cmake/* of the rme-acs directory.

Logging control (bare‑metal)
- ACS verbosity is set via `-DACS_PRINT_LEVEL` at configure time. The default is 3 (prints TEST/ALWAYS/WARN/ERR). Use 2 to include DEBUG, or 1 to include INFO.
- libspdm logs follow the same knob: when `ACS_PRINT_LEVEL <= 2`, libspdm prints INFO + ERROR; otherwise it prints ERROR only.
- For libspdm prerequisites and patching notes, see
  [Libspdm integration](../../README.md#libspdm-integration).

## Running RME ACS with Bootwrapper on Base RevC

Follow the automated stack build and run instructions in `tools/scripts/README.md`.
That guide covers installing prerequisites, building the software stack for Base RevC, and launching the model with the correct configuration.

For more details on how to port the reference code to a specific platform and for further customisation please refer to the [Porting Guide](../../Docs/Arm_RME_System_ACS_Platform_porting_guide.rst)

-----------------

*Copyright (c) 2020-2022, 2025-2026, Arm Limited and Contributors. All rights reserved.*

#Realm Management Extension System Architecture - Architecture Compliance Suite

## Realm Management Extension System Architecture
**Realm Management Extension System Architecture** (RME) is an extension to the Armv9 A-profile architecture. RME adds the following features:
  - Two additional Security states, Root and Realm.
  - Two additional physical address spaces, Root and Realm.
  - The ability to dynamically transition memory granules between physical address spaces.
  - Granule Protection Check mechanism.
Together with the other components of the Arm CCA, RME enables support for dynamic, attestable, and trusted execution environments (Realms) to be run on an Arm PE.

For more information, download the [RME System Architecture specification](https://developer.arm.com/documentation/den0129/latest/)


## RME System - Architecture Compliance Suite

RME System **Architecture Compliance Suite** (ACS) is a collection of self-checking, portable C-based tests.
This suite includes a set of examples of the invariant behaviors that are provided by the [RME System Architecture specification](https://developer.arm.com/documentation/den0129/latest/), so that implementers can verify if these behaviours have been interpreted correctly.
Most of the tests are executed from UEFI Shell by executing the RME UEFI shell application.

## Release details
  - Code Quality: EAC
  - The tests are written for version B.a of the Arm Realm Management Extension (RME) System Architecture.
  - The compliance suite is not a substitute for design verification.

## GitHub branch
  - To pick up the release version of the code, checkout the latest tag.
  - To get the latest version of the code with bug fixes and new features, use the master branch.

## Additional reading
  - For information about the implementable RME rules test algorithm and for unimplemented RME rules, see [arm RME System ACS Scenario document](Docs/Arm_RME_System_Architecture_Compliance_Suite_Scenario_Document.rst)
  - For details on the RME System ACS UEFI Shell Application, see [arm RME System ACS Porting guide document](Docs/Arm_RME_System_ACS_Platform_porting_guide.rst).
  - For details on the Design of the RME System ACS, see. the [arm RME System ACS Validation Methodology document](Docs/Arm_RME_System_Architecture_Compliance_Suite_Validation_Methodology.pdf)
  - For details on the RME ACS Bare-metal support, see the
          - [arm RME System ACS Porting guide document](Docs/Arm_RME_System_ACS_Platform_porting_guide.rst)
          - [Baremetal code](platform/pal_baremetal/)

## Target platforms
  Any RME enabled ARM system platform.


## ACS build steps - UEFI Shell application

### Prerequisites
    ACK test requires to execute the code at EL3 for GPT/MMU modification, so ensure that the following requirements are met.
- When Non-secure EL2 executes 'smc' with SMC FID, 0xC2000060, EL3 Firmware is expected to branch to plat_arm_acs_smc_handler function which is predefined in ACK.
- To generate binary file for EL3 code, follow the build steps in README of val_el3.
- 2MB memory must be flat mapped in EL3-MMU with Root access PAS and GPI as ROOT/ALL_ACCESS, which is used for MMU tables in EL3.
- 2MB Free memory which is used as PA in tests.
- 2MB memory that is flat-mapped as Realm Access PAS which is used for Realm SMMU tables.
- 4KB/16KB/64KB shared memory that is used, a) as a structure, shared_data_el32 to share data between EL3 and EL2 domains, b) to save/restore registers and sp_el3, and tf-handler entry address.
- 512MB Unused VA space (within 48bits) that is used in the tests as VA.
- 4KB of Non-Volatile memory that is used only in reset tests.

For more information, see [arm RME System ACS Validation Methodology document](Docs/Arm_RME_System_Architecture_Compliance_Suite_Validation_Methodology.pdf).

    Before starting the ACS build, ensure that the following requirements are met.

- Partner needs to provide their inputs to these following files...
   - platform/pal_baremetal/FVP/include/platform_override_fvp.h -> For Bare-metal platform,
   - platform/pal_uefi/include/platform_overrride.h -> For UEFI platform.
- Any mainstream Linux based OS distribution running on a x86 or aarch64 machine.
- git clone --branch edk2-stable202208 --depth 1 https://github.com/tianocore/edk2
- git clone https://github.com/tianocore/edk2-libc [ Checkout SHA: 61687168fe02ac4d933a36c9145fdd242ac424d1]
- Install GCC 13.2 or later toolchain for Linux from [here](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads).
- Install the build prerequisite packages to build EDK2.
Note: The details of the packages are beyond the scope of this document.

To start the ACS build, perform the following steps:

1.  cd local_edk2_path
2.  git clone https://github.com/tianocore/edk2-libc
3.  git submodule update --init --recursive
4.  git clone https://github.com/ARM-software/rme-sysarch-acs ShellPkg/Application/rme-acs
5.  Add the following to the [LibraryClasses.common] section in ShellPkg/ShellPkg.dsc
   - Add  RmeValLib|ShellPkg/Application/rme-acs/val/RmeValLib.inf
   - Add  RmePalLib|ShellPkg/Application/rme-acs/platform/pal_uefi/RmePalLib.inf
   - Add ShellPkg/Application/rme-acs/uefi_app/RmeAcs.inf in the [components] section of ShellPkg/ShellPkg.dsc <br>

### Linux build environment
If the build environment is Linux, perform the following steps:
1.  export GCC49_AARCH64_PREFIX= GCC 13.2 toolchain path pointing to /bin/aarch64-none-linux-gnu-
2.  export PACKAGES_PATH= path pointing to edk2-libc
3.  source edksetup.sh
4.  make -C BaseTools/Source/C
5.  Change each "SBSA" string to "RME" string in MdePkg/Include/IndustryStandard/Acpi61.h using the command, ":%s/SBSA/RME/g"
5.  source ShellPkg/Application/rme-acs/tools/scripts/acsbuild.sh

### Build output

The EFI executable file is generated at <edk2_path>/Build/Shell/DEBUG_GCC49/AARCH64/Rme.efi


## Test suite execution

The execution of the compliance suite varies depending on the test environment. These steps assume that the test suite is invoked through the ACS UEFI shell application.

##For details about the RME System ACS UEFI Shell application, see [Arm RME System ACS Porting Guide](Docs/Arm_RME_System_ACS_Platform_porting_guide.rst)

### UEFI Shell (Parser.efi flow)

Package an image with the three files at the FAT root (flat layout):

```
Rme.efi
Parser.efi
base-revc_config.ini    # or rdv3_config.ini
```

Example (loop-mount):

```bash
mkfs.vfat -C -n HD0 image.img 2097152

sudo mkdir -p /mnt/rme
sudo mount image.img /mnt/rme

sudo cp <path-to>/Rme.efi                       /mnt/rme/
sudo cp <path-to>/Parser.efi                    /mnt/rme/
sudo cp <path-to>/base-revc_config.ini          /mnt/rme/
# or for RDV3:
#sudo cp < path - to> / rdv3_config.ini / mnt / rme /

sudo umount /mnt/rme
```

Equivalent using mtools:

```bash
mcopy -i image.img <path-to>/Rme.efi                         ::/
mcopy -i image.img <path-to>/Parser.efi                      ::/
mcopy -i image.img <path-to>/base-revc_config.ini            ::/
# or:
#mcopy - i image.img < path - to> / rdv3_config.ini :: /
```

Run on the UEFI Shell:

```
Shell> fsX:\Parser.efi
# Optional: point to a specific INI
Shell> fsX:\Parser.efi -cfg \base-revc_config.ini
# Note: Parser no longer auto-launches RME; it prints the exact command
# you should run. Example output:
#   Run the ACS manually using:
#     Rme.efi -cfg \rdv3_config.ini
```

The parser loads `\base-revc_config.ini` (or the platform INI), lets you edit values, saves the file, and then prints the command to run:

  Rme.efi -cfg <ini>

Notes:
- `Rme.efi -cfg <ini>` reads both [RME_COMMAND_CONFIG] (verbosity, logs, test selection) and [PLATFORM_CONFIG] (addresses, counts, flags) from the INI.
- Partners can still run Rme.efi with full legacy command line (without `-cfg`). When `-cfg` is present, INI values take precedence and other flags are ignored. Arrays for modules/tests/skips are replaced (no stale state across re‑runs).

At startup, `Rme.efi` prints a concise [CFG] summary of applied platform values and an explicit selection summary:
- Modules(n): …
- Tests(n): …
- Skips(n): …

Runtime platform configuration (UEFI)
- PAL reads platform values from the Parser‑installed runtime table/INI at runtime. Compile‑time defaults remain as fallback.
- The VAL accessors `val_get_*()` are used throughout to avoid direct use of `PLAT_*` macros in UEFI flows. These resolve to runtime getters on UEFI, and to compile-time macros on baremetal.
- EL3 is authoritative for certain values during UEFI runs:
  - The shared structure base (PLAT_SHARED_ADDRESS) is chosen by EL3 and is not overridden by INI.
  - The SMMUv3 root register page offset (SMMUV3_ROOT_REG_OFFSET) used by EL2 to map the root page is taken from EL3 via the shared structure when available.
  - UEFI calls an SMC (RME_MAP_SHARED_MEM) early to let EL3 map and populate the shared structure.

### Post-Silicon

On a system where a USB port is available and functional, perform the following steps:

1. Copy 'Rme.efi' to a USB Flash drive.
2. Plug in the USB Flash drive to one of the functional USB ports on the system.
3. Boot the system to UEFI shell.
4. To determine the file system number of the plugged in USB drive, execute 'map -r' command.
5. Type 'fsx' where 'x' is replaced by the number determined in step 4.
6. To start the compliance tests, run the executable Rme.efi with the appropriate parameters.
   For details on the parameters, refer to [Arm RME System ACS Porting Guide](Docs/Arm_RME_System_ACS_Platform_porting_guide.rst).
7. Copy the UART console output to a log file for analysis and certification.


### Emulation environment with secondary storage
On an emulation environment with secondary storage, perform the following steps:

1. Create an image file which contains the 'Rme.efi' file. For Example:
  - mkfs.vfat -C -n HD0 hda.img 2097152
  - sudo mount hda.img /mnt/rme
  - cp  "<path to application>/Rme.efi" /mnt/rme/
  - sudo umount /mnt/rme
2. Load the image file to the secondary storage using a backdoor. The steps followed to load the image file are Emulation environment specific and beyond the scope of this document.
3. Boot the system to UEFI shell.
4. To determine the file system number of the secondary storage, execute 'map -r' command.
5. Type 'fsx' where 'x' is replaced by the number determined in step 4.
6. To start the compliance tests, run the executable Rme.efi with the appropriate parameters.
   For details on the parameters, see the [Arm RME System ACS Porting Guide](Docs/Arm_RME_System_ACS_Platform_porting_guide.rst)
7. Copy the UART console output to a log file for analysis and certification.


### Emulation environment without secondary storage

On an emulation platform where secondary storage is not available, perform the following steps:

1. Add the path to 'Rme.efi' file in the UEFI FD file.
2. Build UEFI image including the UEFI Shell.
3. Boot the system to UEFI shell.
4. Run the executable 'Rme.efi' to start the compliance tests. For details about the parameters,
   see the [Arm RME System ACS Porting Guide](Docs/Arm_RME_System_ACS_Platform_porting_guide.rst)
5. Copy the UART console output to a log file for analysis and certification.


## Security implication
Arm RME ACS test suite may run at higher privilege level. An attacker may utilize these tests as a means to elevate privilege which can potentially reveal the platform security assets. To prevent the leakage of secure information, it is strongly recommended that the ACS test suite is run only on development platforms. If it is run on production systems, the system should be scrubbed after running the test suite.

## Limitations

Below tests are not qualified in model. These are expected to pass in any valid RME system.
  - test_pool/legacy_system/*.c - Require Legacy TZ support.
  - test_pool/rme/pas_filter_check_in_inactive_mode.c - Model Issue.
  - test_pool/rme/rme_ns_encryption_is_immutable.c - Require NS encryption to be programmable.
  - test_pool/rme/rme_data_encryption_with_different_tweak.c - Model limitation.
  - test_pool/da/da_rootport_write_protect_full_protect_property.c - ImpDef RP write-protect and full-protect registers not present in Model.
  - test_pool/da/da_interconnect_regs_rmsd_protected.c - ImpDef interconnect registers not present in Model.

## License
RME System ACS is distributed under Apache v2.0 License.

## [Feedback, contributions, and support]
-   For support, send an email to "[support-rme-sysarch-acs@arm.com](mailto:support-rme-sysarch-acs@arm.com)" with details.
-   Arm licensees may contact Arm directly through their partner managers.
-   Arm welcomes code contributions through GitHub pull requests. See GitHub documentation on how to raise pull requests.

--------------

*Copyright (c) 2022-2025, Arm Limited and Contributors. All rights reserved.*

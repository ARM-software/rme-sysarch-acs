# Baremetal README
**Please Note**: The code in the "pal_baremetal" directory is only a reference code for implementation of PAL APIs and it has not been verified on any model or SoCs.
The directory pal_baremetal consists of the reference code of the PAL API's specific to a platform.
Description of each directory are as follows:

## Directory Structure

&emsp; - **include**: Consists of the include files required for Baremetal RME ACS. \
&emsp; - **src**: Source files consisting platform specific implementations some of which require user modification. \
&emsp; - **FVP**: Contains platform configuration information. The details in this folder need to be modified w.r.t the platform

## Build Steps

1. To compile Baremetal RME ACS, perform the following steps \
&emsp; 1.1 cd rme-acs \
&emsp; 1.2 export CROSS_COMPILE=<path_to_the_toolchain>/bin/aarch64-none-elf- \
&emsp; 1.3 mkdir build \
&emsp; 1.4 cd build \
&emsp; 1.5 cmake ../ -G"Unix Makefiles" -DCROSS_COMPILE=$CROSS_COMPILE -DTARGET="Target platform" \
&emsp; 1.6 make

Note: Reference Cmake file for RME ACS is present at [CMakeLists.txt](../../CMakeLists.txt).

*Recommended*: CMake v3.17, GCC v12.2
```
CMake Command Line Options:
 -DARM_ARCH_MAJOR = Arch major version. Default value is 9.
 -DARM_ARCH_MINOR = Arch minor version. Default value is 0.
 -DCROSS_COMPILE  = Cross compiler path
 -DTARGET         = Target platform. Should be same as folder under pal_baremetal. Defaults to "FVP".
```

On a successful build, *.bin, *.elf, *.img and debug binaries are generated at *build/output* directory. The output library files will be generated at *build/tools/cmake/* of the rme-acs directory.

## Running RME ACS with Bootwrapper on Base RevC

**1. Before initially building the Base RevC software stack, apply the following change:**

  In <shrinkwrap_path>/config/ns-edk2-base.yaml - Mention PRELOADED_BL33_BASE parameter with NS EL2 entry address.

```
--- a/config/ns-edk2-base.yaml
+++ b/config/ns-edk2-base.yaml
@@ -13,7 +13,8 @@ layers:
build:
  tfa:
    params:
-      BL33: ${artifact:EDK2}
+      PRELOADED_BL33_BASE: 0x88000000
```

  Proceed with building the stack following the standard setup guide.

**2. Load rme.bin to PRELOADED_BL33_BASE**
- While running the FVP, load the output binary at PRELOADED_BL33_BASE with the following parameter -
```
In <shrinkwrap>/work/package/cca-da-edk2.yaml

--data cluster0.cpu0: <absoulte path to RME ACS>/build/output/rme.bin@0x88000000
```

**Note:** The steps outlined above assume the user is running the Base FVP with the Shrinkwrap tool. If this is not the case, modify TF-A to ensure the PRELOADED_BL33_BASE option is set with the appropriate NS EL2 entry address.


For more details on how to port the reference code to a specific platform and for further customisation please refer to the [User Guide](../../Docs/Arm_RME_System_Architecture_Compliance_Suite_Bare-metal_User_Guide.pdf)

-----------------

*Copyright (c) 2020-2022, 2025, Arm Limited and Contributors. All rights reserved.*

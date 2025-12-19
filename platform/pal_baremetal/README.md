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

Follow the automated stack build and run instructions in `tools/scripts/README.md`.
That guide covers installing prerequisites, building the software stack for Base RevC, and launching the model with the correct configuration.

For more details on how to port the reference code to a specific platform and for further customisation please refer to the [Porting Guide](../../Docs/Arm_RME_System_ACS_Platform_porting_guide.rst)

-----------------

*Copyright (c) 2020-2022, 2025, Arm Limited and Contributors. All rights reserved.*

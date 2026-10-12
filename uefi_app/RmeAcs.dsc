## @file
#  Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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

[Defines]
  PLATFORM_NAME                  = RmeAcs
  PLATFORM_GUID                  = 2B2323C6-21C0-4D4C-A8A6-9E541F4562F3
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010006
  OUTPUT_DIRECTORY               = Build/RmeAcs
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

!include MdePkg/MdeLibs.dsc.inc

[Packages]
  ArmPkg/ArmPkg.dec
  EmbeddedPkg/EmbeddedPkg.dec
  MdePkg/MdePkg.dec
  MdeModulePkg/MdeModulePkg.dec
  ShellPkg/ShellPkg.dec
  ShellPkg/Application/rme-acs/uefi_app/RmeAcs.dec
  CryptoPkg/CryptoPkg.dec

[LibraryClasses.common]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
!if $(TARGET) == RELEASE
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
  DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
!endif
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  CompilerIntrinsicsLib|MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf
  ShellCEntryLib|ShellPkg/Library/UefiShellCEntryLib/UefiShellCEntryLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  RmeValLib|ShellPkg/Application/rme-acs/val/RmeValLib.inf
  RmePalLib|ShellPkg/Application/rme-acs/platform/pal_uefi/RmePalLib.inf
!if $(ENABLE_SPDM) == 1
  SpdmRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmRequesterLib.inf
  SpdmCommonLib|ShellPkg/Application/rme-acs/ext/RmeSpdmCommonLib.inf
  SpdmSecuredMessageLib|ShellPkg/Application/rme-acs/ext/RmeSpdmSecuredMessageLib.inf
  SpdmTransportPciDoeLib|ShellPkg/Application/rme-acs/ext/RmeSpdmTransportPciDoeLib.inf
  SpdmCryptLib|ShellPkg/Application/rme-acs/ext/RmeSpdmCryptLib.inf
  PciDoeRequesterLib|ShellPkg/Application/rme-acs/ext/RmePciDoeRequesterLib.inf
  CxlIdeKmRequesterLib|ShellPkg/Application/rme-acs/ext/RmeCxlIdeKmRequesterLib.inf
  PciIdeKmRequesterLib|ShellPkg/Application/rme-acs/ext/RmePciIdeKmRequesterLib.inf
  CxlTspRequesterLib|ShellPkg/Application/rme-acs/ext/RmeCxlTspRequesterLib.inf
  PciTdispRequesterLib|ShellPkg/Application/rme-acs/ext/RmePciTdispRequesterLib.inf
  SpdmDeviceSecretLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmDeviceSecretLibNull.inf
  PlatformLibWrapper|SecurityPkg/DeviceSecurity/OsStub/PlatformLibWrapper/PlatformLibWrapper.inf
  MemLibWrapper|SecurityPkg/DeviceSecurity/OsStub/MemLibWrapper/MemLibWrapper.inf
  CryptlibWrapper|SecurityPkg/DeviceSecurity/OsStub/CryptlibWrapper/CryptlibWrapper.inf
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibFull.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf
!else
  SpdmRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  SpdmCommonLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  SpdmSecuredMessageLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  SpdmTransportPciDoeLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  SpdmCryptLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  PciDoeRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  CxlIdeKmRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  PciIdeKmRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  CxlTspRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  PciTdispRequesterLib|ShellPkg/Application/rme-acs/ext/RmeSpdmNullLib.inf
  RngLib|MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf
!endif

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0xFF
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000000
  gEfiMdePkgTokenSpaceGuid.PcdUefiLibMaxPrintBufferSize|16000

[BuildOptions]
!if $(ENABLE_SPDM) == 1
  *_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/tools/configs -DLIBSPDM_CONFIG=\"acs_libspdm_config.h\" -DENABLE_SPDM=$(ENABLE_SPDM)
!endif

[Components]
!if $(ENABLE_SPDM) == 1
  ShellPkg/Application/rme-acs/val/RmeValLib.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/libspdm/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/spdm-emu/include
      CLANGPDB:*_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/libspdm/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/spdm-emu/include
      CLANGDWARF:*_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/libspdm/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/spdm-emu/include
  }
  ShellPkg/Application/rme-acs/uefi_app/RmeAcs.inf {
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/libspdm/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/spdm-emu/include
      CLANGPDB:*_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/libspdm/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/spdm-emu/include
      CLANGDWARF:*_*_*_CC_FLAGS = -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/libspdm/include -I$(WORKSPACE)/ShellPkg/Application/rme-acs/ext/spdm-emu/include
  }
!else
  ShellPkg/Application/rme-acs/uefi_app/RmeAcs.inf
!endif

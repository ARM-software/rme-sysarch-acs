## @file
 # Copyright (c) 2022, Arm Limited or its affiliates. All rights reserved.
 # SPDX-License-Identifier : Apache-2.0
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #  http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 ##

RME_ROOT:= $(RME_PATH)
RME_DIR := $(RME_ROOT)/test_pool
RME_TEST_DIR += $(RME_ROOT)/test_pool/rme

CFLAGS    += -I$(RME_ROOT)/val/include
CFLAGS    += -I$(RME_ROOT)/

CC = $(GCC49_AARCH64_PREFIX)gcc -march=armv8.2-a -DTARGET_EMULATION
AR = $(GCC49_AARCH64_PREFIX)ar
CC_FLAGS = -g -O0 -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wextra -Wmissing-declarations -Wstrict-prototypes -Wno-error=conversion -Wno-error=sign-conversion -Wno-error=strict-overflow -Wno-type-limits

DEPS = $(RME_ROOT)/platform/pal_baremetal/FVP/include/platform_override_fvp.h

OBJ_DIR := $(RME_ROOT)/build/obj
LIB_DIR := $(RME_ROOT)/build/lib
OUT_DIR = $(RME_ROOT)/build

FILES   := $(foreach files,$(RME_TEST_DIR),$(wildcard $(files)/*.c))
FILE    = `find $(FILES) -type f -exec sh -c 'echo {} $$(basename {})' \; | sort -u --stable -k2,2 | awk '{print $$1}'`
FILE_1  := $(shell echo $(FILE))
XYZ     := $(foreach a,$(FILE_1),$(info $(a)))
PAL_OBJS :=$(addprefix $(OBJ_DIR)/,$(addsuffix .o, $(basename $(notdir $(foreach dirz,$(FILE_1),$(dirz))))))

all: PAL_LIB

create_dirs:
	rm -rf ${OBJ_DIR}
	rm -rf ${LIB_DIR}
	rm -rf ${OUT_DIR}
	@mkdir ${OUT_DIR}
	@mkdir ${OBJ_DIR}
	@mkdir ${LIB_DIR}


$(OBJ_DIR)/%.o: $(RME_DIR)/rme/%.c
	$(CC) $(CC_FLAGS) $(CFLAGS) -c -o $@ $< >> $(OUT_DIR)/compile.log 2>&1

$(OBJ_DIR)/%.o: %.S$(RME_DIR)
	$(CC) -c -o $@ $< >> $(OUT_DIR)/compile.log 2>&1

$(LIB_DIR)/lib_testpool.a: $(PAL_OBJS)
	$(AR) $(ARFLAGS) $@ $^ >> $(OUT_DIR)/link.log 2>&1

PAL_LIB: $(LIB_DIR)/lib_testpool.a

clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(LIB_DIR)
	rm -rf ${OUT_DIR}

.PHONY: all PAL_LIB


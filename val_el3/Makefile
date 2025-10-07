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

include configs.mk

ASM_SOURCES = $(filter %.S,$(EXTRA_SOURCES))
C_SOURCES = $(filter %.c,$(EXTRA_SOURCES))

ASM_OBJS = $(ASM_SOURCES:%.S=%.o)
C_OBJS = $(C_SOURCES:%.c=%.o)
BL31_OBJS = $(wildcard $(BL31_OBJ_DIR)/*.o)

all: $(BL31_ELF) $(BL31_DUMP) $(BL31_BIN)

$(BL31_DUMP): $(BL31_ELF)
	$(OBJ_DUMP) -dx $< > $@

$(BL31_BIN): $(BL31_ELF)
	$(OBJ_COPY) -O binary $< $@

$(BL31_ELF): $(C_OBJS) $(ASM_OBJS) $(LINKERFILE)
	$(LD) -o $@ $(LD_FLAGS) $(BL_LDFLAGS) -Map=$(BL31_MAP) --script $(LINKERFILE) $(C_OBJS) $(ASM_OBJS) $(BL31_OBJS) $(LD_PATHS)  $(LD_LIBS)

$(LINKERFILE): $(BL31_LINKERFILE)
	$(CPP_COMPILER) $(CPP_FLAGS) $(INCDIRS) $(BL_CPPFLAGS) $(LINKER_FLAGS) -Wp,-MD,$(LINKERFILE).d -MT $(LINKERFILE) -MP -o $@ $<

$(ASM_OBJS): %.o : %.S
	$(ASM_COMPILER) $(INCDIRS) $(ASM_FLAGS) -Wp,-MD,$*.d -MT $@ -MP -c $< -o $@

$(C_OBJS): %.o : %.c
	$(C_COMPILER) $(INCDIRS) $(C_FLAGS) -Wp,-MD,$*.d -MT $@ -MP -c $< -o $@

.PHONY: clean
clean:
	rm -f $(BL31_ELF) $(BL31_DUMP) $(BL31_BIN) $(ASM_OBJS) $(C_OBJS)

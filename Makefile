#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

####### SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

SGXSSL_INCLUDE_PATH := /home/gremaupa/intel-sgx-ssl/package/include
SGXSSL_TRUSTED_LIB_PATH := /home/gremaupa/intel-sgx-ssl/package/lib64/debug/
SGXSSL_UNTRUSTED_LIB_PATH := /home/gremaupa/intel-sgx-ssl/package/lib64/debug/

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := $(wildcard App/*.cpp)
App_Include_Paths := -I$(SGX_SDK)/include -I./Common -IApp/restbed

App_Compile_CFlags := -fPIC -Wno-attributes $(App_Include_Paths)
# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_Compile_CFlags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_Compile_CFlags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_Compile_CFlags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Compile_CXXFlags := -std=c++11 $(App_Compile_CFlags)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L$(SGXSSL_UNTRUSTED_LIB_PATH) -pthread App/librestbed.a -lssl -lcrypto -lsgx_usgxssl

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

Gen_Untrusted_Source := App/Enclave_u.c
Gen_Untrusted_Object := App/Enclave_u.o

App_Objects := $(Gen_Untrusted_Object) App/ocalls.o $(App_Cpp_Files:.cpp=.o)

App_Name := app


######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp) $(wildcard Enclave/models/*.cpp) $(wildcard Enclave/auth/*.cpp) $(wildcard Enclave/controllers/*.cpp) $(wildcard Enclave/database/*.cpp) $(wildcard Enclave/crypto/*.cpp) $(wildcard Enclave/error/*.cpp) $(wildcard Enclave/request/*.cpp)  
#-I$(SGX_SDK)/include/stlport
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I./Common -I$(SGX_SDK)/include/libcxx -I$(SGXSSL_INCLUDE_PATH) -IEnclave/Include/jansson -IEnclave/Include -Imfl

Enclave_Compile_CFlags := -nostdinc -ffreestanding -fvisibility=hidden -fpie \
			 $(Enclave_Include_Paths)
Enclave_Compile_CXXFlags := -nostdinc++ -std=c++14 -include "tsgxsslio.h"  $(Enclave_Compile_CFlags)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
#-L$(SGX_LIBRARY_PATH) -L$(SGXSSL_TRUSTED_LIB_PATH)
Enclave_Link_Flags := -m64 -Wall -O2 -D_FORTIFY_SOURCE=2 \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,-z,noexecstack \
	-Wl,-z,now -pie -L/home/gremaupa/intel-sgx-ssl/package/lib64/release/ \
	-Wl,--whole-archive -lsgx_tsgxssl \
	-Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tservice \
	-Wl,--end-group \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L/opt/intel/sgxsdk/lib64 \
	-Wl,--whole-archive -lsgx_trts \
	-Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) libjansson.a \
	-Wl,--end-group \
	-Wl,-Bstatic \
	-Wl,-Bsymbolic \
	-Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry \
	-Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave/Enclave.lds



Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Gen_Trusted_Source := Enclave/Enclave_t.c
Gen_Trusted_Object := Enclave/Enclave_t.o

Enclave_Objects := $(Gen_Trusted_Object) $(Enclave_Cpp_Files:.cpp=.o) Enclave/duktape.o Enclave/database/sqlite3.o Enclave/database/ocall_interface.o Enclave/crypto/b64url_encode.o Enclave/crypto/b64url_decode.o

Enclave_Name := libenclave.so
Signed_Enclave_Name := libenclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name) directories 
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

######## App Objects ########

$(Gen_Untrusted_Source): $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path /home/gremaupa/intel-sgx-ssl/package/include --search-path ../Enclave/
	@echo "GEN  =>  $@"

$(Gen_Untrusted_Object): $(Gen_Untrusted_Source)
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(SGX_COMMON_CFLAGS) $(App_Compile_CXXFlags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_Objects)
	@$(CXX) $(SGX_COMMON_CFLAGS) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

# Compile ocalls
App/ocalls.o: App/ocalls.c
	@$(CC) $(App_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"


######## Enclave Objects ########

$(Gen_Trusted_Source): $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include --search-path /home/gremaupa/intel-sgx-ssl/package/include
	@echo "GEN  =>  $@"
$(Gen_Trusted_Object): $(Gen_Trusted_Source)
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(SGX_COMMON_CFLAGS) $(Enclave_Compile_CXXFlags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): $(Enclave_Objects)
	@$(CXX) $(SGX_COMMON_CFLAGS) $(Enclave_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

# Preprocess sqlite3
Enclave/database/sqlite3.i: Enclave/database/sqlite3.c
	@$(CC) -I$(SGX_SDK)/include -DSQLITE_THREADSAFE=0 -E $< -o $@
	@echo "CC-Preprocess  <=  $<"

# Compile sqlite3
Enclave/database/sqlite3.o: Enclave/database/sqlite3.i Enclave/database/sqlite3.c
	@$(CC) $(Enclave_Compile_CFlags) -DSQLITE_THREADSAFE=0 -c $< -o $@
	@echo "CC  <=  $<"

# Compile duktape
Enclave/duktape.o: Enclave/duktape.c
	@$(CC) $(App_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

# Preprocess ocall_interface
Enclave/database/ocall_interface.i: Enclave/database/ocall_interface.c
	@$(CC) -I$(SGX_SDK)/include -ICommon -E $< -o $@
	@echo "CC-Preprocess  <=  $<"

# Compile ocall_interface
Enclave/database/ocall_interface.o: Enclave/database/ocall_interface.i Enclave/Enclave_t.c
	@$(CC) $(Enclave_Compile_CFlags) -c $< -o $@
	@echo "CC  <=  $<"

# Compile b64url
Enclave/crypto/b64url_encode.o: Enclave/crypto/b64url_encode.c
	@$(CC) $(App_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

# Compile b64url
Enclave/crypto/b64url_decode.o: Enclave/crypto/b64url_decode.c
	@$(CC) $(App_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

directories: 
	@rm -rf data/
	@mkdir -p data/events
######### clean up ########
.PHONY: clean

myclean: 
	@rm -f $(Enclave_Name) App/Enclave_u.* Enclave/Enclave_t.* $(Signed_Enclave_Name)

clean:
	@rm -rf $(App_Name) $(App_Objects) $(Enclave_Name) $(Enclave_Objects) App/Enclave_u.* Enclave/Enclave_t.* App/ocalls.o Enclave/database/sqlite3.i Enclave/database/ocall_interface.i Enclave/Utils.o $(Signed_Enclave_Name) data

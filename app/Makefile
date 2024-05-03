#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2024 Zondax AG
#  (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

DEBUG:=0

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

include $(BOLOS_SDK)/Makefile.defines

$(info ************ TARGET_NAME  = [$(TARGET_NAME)])

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN=AVAX
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN),AVAX)
# Main app configuration
DEFINES += APP_STANDARD
APPNAME = "Avalanche"
APPPATH = "44'/9000'" --path "44'/60'"
else
define error_message

COIN value not supported: [$(COIN)]

endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = $(COMMON_LOAD_PARAMS) --curve secp256k1

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform

# Add SDK BLAKE2b
DEFINES += HAVE_HASH HAVE_BLAKE2
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# TODO: maybe not that useful so far?
ifeq ($(APP_TESTING),1)
DEFINES += APP_TESTING
DEFINES += ZEMU_LOGGING
$(info ************ LOGGING ENABLED ************)
endif

# Enable app features depending on the target device
ifeq ($(TARGET_NAME),TARGET_NANOS)
RUST_TARGET:=thumbv6m-none-eabi
APP_FULL:=1
endif

ifeq ($(TARGET_NAME),TARGET_NANOX)
RUST_TARGET:=thumbv6m-none-eabi
APP_FULL:=1
endif

ifeq ($(TARGET_NAME),TARGET_NANOS2)
RUST_TARGET:=thumbv6m-none-eabi
APP_FULL:=1
endif

ifeq ($(TARGET_NAME),TARGET_STAX)
RUST_TARGET:=thumbv6m-none-eabi
APP_FULL:=1
endif

ifeq ($(APP_TESTING),1)
RUST_FEATURES+=--features "dev"
endif
ifeq ($(APP_FULL),1)
RUST_FEATURES+=--features "full"
else
# Lite version to run on nanos
RUST_FEATURES+=--features "lite"
endif

# Compiler, assembler, and linker

# Building Rust
CC := $(CLANGPATH)clang

ifeq ($(DEBUG),1)
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter -g
else
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter
endif

AS := $(GCCPATH)arm-none-eabi-gcc
AFLAGS +=

LD       := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -z muldefs
LDLIBS   += -lm -lgcc -lc
LDLIBS += -L$(MY_DIR)rust/target/$(RUST_TARGET)/release -lrslib

APP_SOURCE_PATH += $(CURDIR)/rust/include
APP_CUSTOM_LINK_DEPENDENCIES := rust

.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" TARGET_NAME=$(TARGET_NAME) ZEMU_LOGGING=$(ZEMU_LOGGING) \
	cargo build --release --target $(RUST_TARGET) \
	--no-default-features $(RUST_FEATURES)

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

.PHONY: rust_test_full
rust_test_full:
	RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" TARGET_NAME=$(TARGET_NAME) ZEMU_LOGGING=$(ZEMU_LOGGING) \
	cargo test --release --target $(RUST_TARGET) \
	--no-default-features $(RUST_FEATURES)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN IRON

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version

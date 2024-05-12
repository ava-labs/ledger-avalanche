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

# This enables automatically the ethereum application 
# for all targets except for the nanos
ifneq ($(TARGET_NAME), TARGET_NANOS)
FEATURE_ETH = 1
endif

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
# Why just here and not common setting for similar targets 
# like nanosplus and stax?
ifeq ($(FEATURE_ETH), 1))
# taken from ethereum app config
APP_LOAD_PARAMS += --appFlags 0xa50
APP_LOAD_FLAGS += --appFlags 0xa40
else
APP_LOAD_PARAMS += --appFlags 0x200
endif
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

ifeq ($(FEATURE_ETH), 1)
	# Do not compile eth app if target is nanos
	ifeq (,$(filter $(TARGET_NAME),TARGET_NANOS))
		DEFINES += HAVE_ETH_INTEGRATION
		DEFINES += HAVE_ETH2 
		DEFINES_LIB = USE_LIB_ETHEREUM

		# EIP-712
		DEFINES	+= HAVE_EIP712_FULL_SUPPORT
		# Feature used by EIP-712
		DEFINES += HAVE_DOMAIN_NAME

		DEFINES += TICKER="ETH"
		DEFINES += CHAIN_ID=1
		DEFINES += HAVE_BOLOS_APP_STACK_CANARY
		DEFINES += HAVE_HASH3
		# TODO: This should not be necessary 
		# but compilation fails after enabling it with HAVE_HASH3
		DEFINES += CX_KECCAK_256_SIZE=32
		# Dynamic memory allocator
		DEFINES += HAVE_DYN_MEM_ALLOC

		ETH_GLYPHS = $(MY_DIR)/../deps/ethereum/glyphs
		GLYPH_FILES += $(addprefix $(ETH_GLYPHS)/,$(sort $(notdir $(shell find $(ETH_GLYPHS)/))))
		HAVE_EIP712_FULL_SUPPORT = 1

		# The coin type bellow is not part of the eth app,
		# but this is necesary here as avax wants support for
		# coin_type = 60'
		DEFINES   += BIP44_COIN_TYPE_3=60
		DEFINES   += COIN_COINID_SHORT=\"ETH\"

		DEFINES += HAVE_SNPRINTF_FORMAT_U
		DEFINES += IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64

        DEFINES += HAVE_U2F HAVE_IO_U2F
        DEFINES += U2F_PROXY_MAGIC=\"w0w\"
        DEFINES += BLE_SEGMENT_SIZE=32 #max MTU, min 20

		DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""


		# Needed to be able to include the definition of G_cx
		INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src
		INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/include

		INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src
		INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src_features/
		INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src_common/
		# include bellow is necessary if HAVE_ETH2 is defined
		INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src_plugins/

		APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src
		APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_features
		APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_common
		# include bellow is necessary if HAVE_ETH2 is defined
		APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_plugins/

		SDK_SOURCE_PATH += lib_stusb lib_stusb_impl lib_u2f

		APP_SOURCE_PATH += ${BOLOS_SDK}/lib_standard_app

		# import rules to compile glyphs(/pone)
		ifeq  ($(TARGET_NAME),TARGET_STAX)
			APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_nbgl
		else
			SDK_SOURCE_PATH += lib_ux
			APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_bagl
			DEFINES += HAVE_BAGL
			DEFINES += HAVE_UX_FLOW
			DEFINES += HAVE_GLO096
			DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
			DEFINES += HAVE_BAGL_ELLIPSIS # long label truncation feature
			DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
			DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
			DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
		endif

		# require linker flags
		LDFLAGS += -L$(BOLOS_SDK)/lib_cxng
		LDFLAGS += -L$(BOLOS_SDK)/lib_standard_app
		# bellow does not work neither
		# LDLIBS += -lcxng -lstandard_app

	endif #NO TARGET_NANOS OR TARGET_STAX
endif #NO FEATURE_ETH


# Compiler, assembler, and linker

# Building Rust
CC := $(CLANGPATH)clang

ifeq ($(DEBUG),1)
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter -g
else
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter
endif

CFLAGS += -DAPPVERSION_M=$(APPVERSION_M) -DAPPVERSION_N=$(APPVERSION_N) -DAPPVERSION_P=$(APPVERSION_P)

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

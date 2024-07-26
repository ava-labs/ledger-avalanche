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

DEBUG := 0

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/Makefile.conf

# Enable Ethereum features for all targets except TARGET_NANOS
ifneq ($(TARGET_NAME), TARGET_NANOS)
FEATURE_ETH = 1
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script
include $(BOLOS_SDK)/Makefile.defines

## Display whether this is a production build or for internal use
ifeq ($(PRODUCTION_BUILD), 1)
    $(info ************ PRODUCTION_BUILD  = [PRODUCTION BUILD])
else
    $(info ************ PRODUCTION_BUILD  = [INTERNAL USE])
endif

DEFINES += PRODUCTION_BUILD=$(PRODUCTION_BUILD)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN = AVAX
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN), AVAX)
# Main app configuration
DEFINES += APP_STANDARD
APPNAME = "Avalanche"
APPPATH = "44'/9000'" --path "44'/60'"
PATH_APP_LOAD_PARAMS = "44'/9000'" "44'/60'"
else
define error_message

COIN value not supported: [$(COIN)]

endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = $(COMMON_LOAD_PARAMS) --curve secp256k1

# Configure minimun stack size
ifeq ($(TARGET_NAME),TARGET_NANOS)
	APP_STACK_MIN_SIZE := 1752
else
	APP_STACK_MIN_SIZE := 2000
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

# Add SDK BLAKE2b
DEFINES += HAVE_HASH HAVE_BLAKE2
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

ifeq ($(APP_TESTING), 1)
DEFINES += APP_TESTING ZEMU_LOGGING
$(info ************ LOGGING ENABLED ************)
endif

# Enable app features depending on the target device
ifeq ($(TARGET_NAME), TARGET_NANOS)
RUST_TARGET := thumbv6m-none-eabi
APP_FULL := 1
APP_SOURCE_PATH += $(MY_DIR)/../deps/zxlib/view_s.c
RUST_TARGET_NAME := TARGET_NANOS
endif

ifeq ($(TARGET_NAME), TARGET_NANOX)
RUST_TARGET := thumbv6m-none-eabi
APP_FULL := 1
RUST_TARGET_NAME := TARGET_NANOX
endif

ifeq ($(TARGET_NAME), TARGET_NANOS2)
RUST_TARGET := thumbv6m-none-eabi
APP_FULL := 1
RUST_TARGET_NAME := TARGET_NANOS2
endif

NBGL_TARGETS := TARGET_STAX TARGET_FLEX
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME), $(NBGL_TARGETS)))
RUST_TARGET := thumbv6m-none-eabi
APP_FULL := 1
DEFINES += ICONGLYPH=C_icon_stax_64
DEFINES += ICONBITMAP=C_icon_stax_64
DEFINES += ICONGLYPH_SMALL=C_icon_stax_32
RUST_TARGET_NAME := TARGET_STAX
endif

ifeq ($(APP_TESTING), 1)
RUST_FEATURES += --features "dev"
endif

ifeq ($(APP_FULL), 1)
RUST_FEATURES += --features "full"
else
RUST_FEATURES += --features "lite"
endif

ifeq ($(FEATURE_ETH), 1)

# Avax CHAIN_ID
CHAIN_ID = 43114
TICKER = "AVAX"

CFLAGS += -DMAJOR_VERSION=$(APPVERSION_M) -DMINOR_VERSION=$(APPVERSION_N) -DPATCH_VERSION=$(APPVERSION_P)

ifeq (,$(filter $(TARGET_NAME),TARGET_NANOS))
DEFINES += HAVE_ETH_INTEGRATION HAVE_ETH2 USE_LIB_ETHEREUM
DEFINES += HAVE_BYPASS_SIGNATURES
# commented out as we no longer use app-ethereum
# for handling erc20 tokens.
# DEFINES += HAVE_CONTRACT_NAME_IN_DESCRIPTOR
HAVE_EIP712_FULL_SUPPORT = 1
DEFINES += HAVE_EIP712_FULL_SUPPORT=$(HAVE_EIP712_FULL_SUPPORT)
DEFINES += HAVE_DOMAIN_NAME
DEFINES += CHAIN_ID=$(CHAIN_ID)
DEFINES += TICKER=\"$(TICKER)\"
DEFINES += HAVE_BOLOS_APP_STACK_CANARY HAVE_HASH3
DEFINES += HAVE_DYN_MEM_ALLOC

DEFINES += BIP44_COIN_TYPE_3=60 COIN_COINID_SHORT=\"AVAX\"
DEFINES += HAVE_SNPRINTF_FORMAT_U IO_HID_EP_LENGTH=64
DEFINES += HAVE_U2F HAVE_IO_U2F U2F_PROXY_MAGIC=\"w0w\"
DEFINES += BLE_SEGMENT_SIZE=32
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""
DEFINES += CHAINID_COINNAME=\"$(TICKER)\" BUILD_YEAR=\"$(shell date +%Y)\"

INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/include
INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/ethereum-plugin-sdk/src
INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src
INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src_features/
INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src_plugins/

ETHEREUM_SRC_DIR := $(MY_DIR)/../deps/ethereum/src
# With the line bellow we remove app-ethereum/src/main.c file from our sources
ETHEREUM_SRC_FILES := $(filter-out $(ETHEREUM_SRC_DIR)/main.c, $(shell find $(ETHEREUM_SRC_DIR) -name '*.c'))
APP_SOURCE_PATH += $(ETHEREUM_SRC_FILES)
APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_features
APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_plugins/
APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/ethereum-plugin-sdk

SDK_SOURCE_PATH += lib_u2f lib_standard_app

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME), $(NBGL_TARGETS)))
	NBGL_SRC_DIR := $(MY_DIR)/../deps/ethereum/src_nbgl
	NBGL_SRC_FILES := $(filter-out $(NBGL_SRC_DIR)/network_icons.c, $(shell find $(NBGL_SRC_DIR) -name '*.c'))
	NBGL_SRC_FILES := $(filter-out $(NBGL_SRC_DIR)/ui_idle.c, $(NBGL_SRC_FILES))

	INCLUDES_PATH += $(MY_DIR)/../deps/ethereum/src_nbgl
	APP_SOURCE_PATH += $(NBGL_SRC_FILES)
else
	SDK_SOURCE_PATH += lib_ux
	APP_SOURCE_PATH += $(MY_DIR)/../deps/ethereum/src_bagl
	DEFINES += HAVE_BAGL HAVE_UX_FLOW HAVE_GLO096
	DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64 HAVE_BAGL_ELLIPSIS
	DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
	DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
	DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

LDFLAGS += -L$(BOLOS_SDK)/lib_cxng

DEFINES += FEATURE_ETH=$(FEATURE_ETH)

# not present in app-ethereum/master but in develop branch
# so it could be needed once develop gets revased onto master
# include $(CURDIR)/../deps/ethereum/makefile_conf/features.mk

endif # NO TARGET_NANOS OR TARGET_STAX
endif # NO FEATURE_ETH

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform
INCLUDES_PATH += $(CURDIR)/src/common/

CC := $(CLANGPATH)clang

ifeq ($(DEBUG), 1)
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter -g
else
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter
endif

CFLAGS += -DAPPVERSION_M=$(APPVERSION_M) -DAPPVERSION_N=$(APPVERSION_N) -DAPPVERSION_P=$(APPVERSION_P)

AS := $(GCCPATH)arm-none-eabi-gcc
AFLAGS +=

LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -z muldefs
LDLIBS += -lm -lgcc -lc
LDLIBS += -L$(MY_DIR)rust/target/$(RUST_TARGET)/release -lrslib

APP_SOURCE_PATH += $(CURDIR)/rust/include
APP_CUSTOM_LINK_DEPENDENCIES := rust


.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" TARGET_NAME=$(RUST_TARGET_NAME) ZEMU_LOGGING=$(ZEMU_LOGGING) \
	cargo build --release --target $(RUST_TARGET) \
	--no-default-features $(RUST_FEATURES)

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN AVAX

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version

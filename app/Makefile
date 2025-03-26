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

include $(CURDIR)/Makefile.conf

# Enable Ethereum features for all targets except TARGET_NANOS
ifneq ($(TARGET_NAME), TARGET_NANOS)
FEATURE_ETH = 1
endif

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

VARIANT_PARAM=COIN
VARIANT_VALUES=$(COIN)

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

APP_LOAD_PARAMS = $(COMMON_LOAD_PARAMS) --curve secp256k1 --curve ed25519

# Configure minimun stack size
ifeq ($(TARGET_NAME),TARGET_NANOS)
	APP_STACK_MIN_SIZE := 1752
else
	APP_STACK_MIN_SIZE := 2000
endif

# Enable QR code display for all devices
ENABLE_NBGL_QRCODE ?= 1
ENABLE_BLUETOOTH = 1

include $(BOLOS_SDK)/Makefile.target

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])

# Add SDK BLAKE2b
DEFINES += HAVE_HASH HAVE_BLAKE2
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

ifeq ($(APP_TESTING), 1)
DEFINES += APP_TESTING ZEMU_LOGGING
$(info ************ LOGGING ENABLED ************)
endif

INCLUDES_PATH += $(CURDIR)/src/common/

CC := $(CLANGPATH)clang

ifeq ($(DEBUG), 1)
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter -g
else
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter
endif

CFLAGS += -DAPPVERSION_M=$(APPVERSION_M) -DAPPVERSION_N=$(APPVERSION_N) -DAPPVERSION_P=$(APPVERSION_P)

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/Makefile.rust
include $(CURDIR)/Makefile.erc20
include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform
include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

# make rust a prerequisite for all object files
$(OBJECT_FILES): | rust

dep/%.d: %.c Makefile

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version

#*******************************************************************************
#*   (c) 2018 - 2023 Zondax AG
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************

.PHONY: all deps build clean load delete check_python show_info_recovery_mode

TESTS_ZEMU_DIR?=$(CURDIR)/zemu
TESTS_JS_PACKAGE?=
TESTS_JS_DIR?=

LEDGER_SRC=$(CURDIR)/app
DOCKER_APP_SRC=/app
DOCKER_APP_BIN=$(DOCKER_APP_SRC)/app/bin/app.elf

DOCKER_BOLOS_SDKS = NANOS_SDK
DOCKER_BOLOS_SDKX = NANOX_SDK
DOCKER_BOLOS_SDKSP = NANOSP_SDK
DOCKER_BOLOS_SDKFS = STAX_SDK

TARGET_S = nanos
TARGET_X = nanox
TARGET_SP = nanos2
TARGET_STAX = stax

# Note: This is not an SSH key, and being public represents no risk
SCP_PUBKEY=049bc79d139c70c83a4b19e8922e5ee3e0080bb14a2e8b0752aa42cda90a1463f689b0fa68c1c0246845c2074787b649d0d8a6c0b97d4607065eee3057bdf16b83
SCP_PRIVKEY=ff701d781f43ce106f72dc26a46b6a83e053b5d07bb3d4ceab79c91ca822a66b

INTERACTIVE:=$(shell [ -t 0 ] && echo 1)
USERID:=$(shell id -u)
GROUPID:=$(shell id -g)
$(info USERID                : $(USERID))
$(info GROUPID               : $(GROUPID))
$(info TESTS_ZEMU_DIR        : $(TESTS_ZEMU_DIR))
$(info TESTS_JS_DIR          : $(TESTS_JS_DIR))
$(info TESTS_JS_PACKAGE      : $(TESTS_JS_PACKAGE))

DOCKER_IMAGE_ZONDAX=zondax/ledger-app-builder:ledger-d5bfe2e793f15a826971ae9de2adcad524df3e8e
DOCKER_IMAGE_LEDGER=ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest

ifdef INTERACTIVE
INTERACTIVE_SETTING:="-i"
TTY_SETTING:="-t"
else
INTERACTIVE_SETTING:=
TTY_SETTING:=
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	NPROC=$(shell nproc)
endif
ifeq ($(UNAME_S),Darwin)
	NPROC=$(shell sysctl -n hw.physicalcpu)
endif

define run_docker
	docker run $(TTY_SETTING) $(INTERACTIVE_SETTING) --rm \
	-e SCP_PRIVKEY=$(SCP_PRIVKEY) \
	-e SDK_VARNAME=$(1) \
	-e TARGET=$(2) \
	-u $(USERID):$(GROUPID) \
	-v $(shell realpath .):/app \
	-e COIN=$(COIN) \
	-e APP_TESTING=$(APP_TESTING) \
	$(DOCKER_IMAGE_ZONDAX) "$(3)"
endef

define run_docker_ledger
	docker run $(TTY_SETTING) $(INTERACTIVE_SETTING) --rm \
	-v $(shell pwd):/app \
	$(DOCKER_IMAGE_LEDGER) "$(1)"
endef

all:
	@$(MAKE) clean
	@$(MAKE) buildS
	@$(MAKE) clean_build
	@$(MAKE) buildX
	@$(MAKE) clean_build
	@$(MAKE) buildSP
	@$(MAKE) clean_build
	@$(MAKE) buildFS

.PHONY: check_python
check_python:
	@python -c 'import sys; sys.exit(3-sys.version_info.major)' || (echo "The python command does not point to Python 3"; exit 1)

.PHONY: deps
deps: check_python
	@echo "Install dependencies"
	$(CURDIR)/install_deps.sh

.PHONY: pull
pull:
	docker pull $(DOCKER_IMAGE_ZONDAX)
	docker pull $(DOCKER_IMAGE_LEDGER)

.PHONY: ledger_lint
ledger_lint:
	$(call run_docker_ledger,"scan-build --use-cc=clang -analyze-headers -enable-checker security -enable-checker unix -enable-checker valist -o scan-build --status-bugs make default")

.PHONY: build_rustS
build_rustS:
	$(call run_docker,$(DOCKER_BOLOS_SDKS),$(TARGET_S),make -j $(NPROC) rust)

.PHONY: build_rustX
build_rustX:
	$(call run_docker,$(DOCKER_BOLOS_SDKX),$(TARGET_X),make -j $(NPROC) rust)

.PHONY: build_rustSP
build_rustSP:
	$(call run_docker,$(DOCKER_BOLOS_SDKSP),$(TARGET_SP),make -j $(NPROC) rust)

.PHONY: build_rustFS
build_rustFS:
	$(call run_docker,$(DOCKER_BOLOS_SDKFS),$(TARGET_FS),make -j $(NPROC) rust)

generate_rustFS:
	$(MAKE) -C $(CURDIR) TARGET_NAME=TARGET_STAX BOLOS_SDK=$(CURDIR)/deps/ledger-secure-sdk generate

.PHONY: convert_icon
convert_icon:
	@convert $(LEDGER_SRC)/tmp.gif -monochrome -size 16x16 -depth 1 $(LEDGER_SRC)/nanos_icon.gif
	@convert $(LEDGER_SRC)/nanos_icon.gif -crop 14x14+1+1 +repage -negate $(LEDGER_SRC)/nanox_icon.gif

.PHONY: buildS
buildS:
	$(call run_docker,$(DOCKER_BOLOS_SDKS),$(TARGET_S),make -j $(NPROC))

.PHONY: buildX
buildX:
	$(call run_docker,$(DOCKER_BOLOS_SDKX),$(TARGET_X),make -j $(NPROC))

.PHONY: buildSP
buildSP:
	$(call run_docker,$(DOCKER_BOLOS_SDKSP),$(TARGET_SP),make -j $(NPROC))

.PHONY: clean_glyphs
clean_glyphs:
	@echo "Removing glyphs files"
	@rm -f app/glyphs/glyphs.c app/glyphs/glyphs.h || true

.PHONY: buildFS
buildFS: build_rustFS
	$(call run_docker,$(DOCKER_BOLOS_SDKFS),$(TARGET_FS),make -j $(NPROC))

.PHONY: clean_output
clean_output:
	@echo "Removing output files"
	@rm -f app/output/app* || true

.PHONY: clean_build
clean_build: clean_glyphs
	$(call run_docker,$(DOCKER_BOLOS_SDKSP),$(TARGET_SP),make clean)

.PHONY: clean
clean: clean_output clean_build

.PHONY: listvariants
listvariants:
	$(call run_docker,$(DOCKER_BOLOS_SDKSP),$(TARGET_SP),make listvariants)

.PHONY: shellS
shellS:
	$(call run_docker,$(DOCKER_BOLOS_SDKS) -t,$(TARGET_S),bash)

.PHONY: shellX
shellX:
	$(call run_docker,$(DOCKER_BOLOS_SDKX) -t,$(TARGET_X),bash)

.PHONY: shellSP
shellSP:
	$(call run_docker,$(DOCKER_BOLOS_SDKSP) -t,$(TARGET_SP),bash)

.PHONY: shellFS
shellFS:
	$(call run_docker,$(DOCKER_BOLOS_SDKFS) -t,$(TARGET_FS),bash)

.PHONY: loadS
loadS:
	${LEDGER_SRC}/pkg/installer_s.sh load

.PHONY: deleteS
deleteS:
	${LEDGER_SRC}/pkg/installer_s.sh delete

.PHONY: loadSP
loadSP:
	${LEDGER_SRC}/pkg/installer_sp.sh load

.PHONY: deleteSP
deleteSP:
	${LEDGER_SRC}/pkg/installer_sp.sh delete

.PHONY: loadFS
loadFS:
	${LEDGER_SRC}/pkg/installer_fs.sh load

.PHONY: deleteFS
deleteFS:
	${LEDGER_SRC}/pkg/installer_fs.sh delete

.PHONY: show_info_recovery_mode
show_info_recovery_mode:
	@echo "This command requires a Ledger Nano S in recovery mode. To go into recovery mode, follow:"
	@echo " 1. Settings -> Device -> Reset all and confirm"
	@echo " 2. Unplug device, press and hold the right button, plug-in again"
	@echo " 3. Navigate to the main menu"
	@echo "If everything was correct, no PIN needs to be entered."

# This target will initialize the device with the integration testing mnemonic
.PHONY: dev_init
dev_init: show_info_recovery_mode
	@echo "Initializing device with test mnemonic! WARNING TAKES 2 MINUTES AND REQUIRES RECOVERY MODE"
	@python -m ledgerblue.hostOnboard --apdu --id 0 --prefix "" --passphrase "" --pin 5555 --words "equip will roof matter pink blind book anxiety banner elbow sun young"

# This target will initialize the device with the secondary integration testing mnemonic (Bob)
.PHONY: dev_init_secondary
dev_init_secondary: check_python show_info_recovery_mode
	@echo "Initializing device with secondary test mnemonic! WARNING TAKES 2 MINUTES AND REQUIRES RECOVERY MODE"
	@python -m ledgerblue.hostOnboard --apdu --id 0 --prefix "" --passphrase "" --pin 5555 --words "elite vote proof agree february step sibling sand grocery axis false cup"

# This target will setup a custom developer certificate
.PHONY: dev_ca
dev_ca: check_python
	@python -m ledgerblue.setupCustomCA --targetId 0x31100004 --public $(SCP_PUBKEY) --name zondax

.PHONY: dev_ca_delete
dev_ca_delete: check_python
	@python -m ledgerblue.resetCustomCA --targetId 0x31100004

# This target will setup a custom developer certificate
.PHONY: dev_caSP
dev_caSP: check_python
	@python -m ledgerblue.setupCustomCA --targetId 0x33100004 --public $(SCP_PUBKEY) --name zondax

.PHONY: dev_ca_deleteSP
dev_ca_deleteSP: check_python
	@python -m ledgerblue.resetCustomCA --targetId 0x33100004

.PHONY: zemu_install
zemu_install:
	cd $(TESTS_JS_DIR) && yarn install && yarn build
	cd $(TESTS_ZEMU_DIR) && yarn install

########################## TEST Section ###############################

.PHONY: zemu_test
zemu_test:
	cd $(TESTS_ZEMU_DIR) && yarn test $(COIN)

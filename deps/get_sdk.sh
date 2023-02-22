#!/usr/bin/env sh
. ./.env

git submodule update --init --remote
git -C ledger-rust checkout $SDK_GIT_REVISION

ln -sf ./ledger-rust/bolos-sys/sdk/ledger-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/nanos-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/nanox-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/nanosplus-secure-sdk ./

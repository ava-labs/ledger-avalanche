#!/usr/bin/env sh
BASE_DIR="$(realpath "$(dirname "$0")")"

. ./.env

git submodule update --init --remote
git -C ledger-rust checkout $SDK_GIT_REVISION

# Fetch Ledger SDKs
cd ./ledger-rust/bolos-sys/sdk && ./fetch_sdk.sh
cd "$BASE_DIR" || exit

# Prepare links to Ledger SDKs
ln -sf ./ledger-rust/bolos-sys/sdk/ledger-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/nanos-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/nanox-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/nanosplus-secure-sdk ./
ln -sf ./ledger-rust/bolos-sys/sdk/stax-secure-sdk ./

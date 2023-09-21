export MIRIFLAGS := "-Zmiri-symbolic-alignment-check -Zmiri-permissive-provenance -Zmiri-backtrace=full"
export RUST_BACKTRACE := "full"

# Show this menu
@help:
    just --list --unsorted

# Initialize project: fetch dependencies (SDK etc...)
init:
    just deps/sdk true
    just make deps
    just make zemu_install

# Run tests with miri
miri *args='':
    cargo +nightly miri test --features "full" {{args}}

# Run rust tests first and zemu_test afterwards
tests: build-elfs
    cargo test
    just miri
    make zemu_test

# Run zemu tests specified by the given filter
ztest filter="":
    cd zemu && yarn test -t {{filter}}

# Start debugging with zemu according to debug.mjs
debug:
    make zemu_debug

alias l := lint

# Format, then run clippy and fix warnings
lint:
    cargo fmt
    cargo clippy --fix --allow-dirty --allow-staged --all

# Build all the elfs of the app
build-elfs:
    make

alias m := make
make *cmd='':
    make {{cmd}}

try:
    cd zemu && yarn try

alias c := cargo
cargo *cmd='':
    cargo {{cmd}}

insta: (cargo "insta test --review")

_ztest-ci:
    #!/bin/env bash
    pushd zemu
    TESTS=`yarn test --listTests --json | head -n 3 | tail -n 1 | jq -r '.[]'`

    has_failed=0
    outputs=()

    for file in ${TESTS[@]}; do
        output=`yarn jest "$file" --maxConcurrency 2 2>&1`
        exit=$?

        outputs+=("$output")
        if [ $exit -ne 0 ]; then
            echo "=== Test $file failed ==="
            has_failed=1
        fi
    done

    if [ $has_failed -eq 1 ]; then
        for i in "${!outputs[@]}"; do
            output=$outputs[i]
            file=$TESTS[i]
            echo "=== Test Output for $file ==="
            echo "$output"
        done
        echo "Some tests failed. See detailed output above."
        exit 1
    else
        echo "All tests passed."
        exit 0
    fi

    popd

# Run the same things as a normal CI workflow
ci:
    just miri
    cargo fmt -- --check
    cargo clippy --all-targets --features "full"
    just make clean all
    just _ztest-ci

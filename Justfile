export MIRIFLAGS := "-Zmiri-symbolic-alignment-check -Zmiri-check-number-validity"

# Show this menu
@help:
    just --list --unsorted

# Run tests with miri
miri:
    cargo +nightly miri test

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

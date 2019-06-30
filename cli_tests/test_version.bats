#!/usr/bin/env bats

load helpers/assert
load helpers/teardown

setup_once() {
  pass
}

teardown_once() {
  teardown_common
}

setup() {
  if [ "$BATS_TEST_NUMBER" -eq 1 ]; then
    setup_once
  fi
}

teardown() {
  if [ "$BATS_TEST_NUMBER" -eq ${#BATS_TEST_NAMES[@]} ]; then
    teardown_once
  fi
}

@test "threatspec version" {
  run threatspec --version
  assert_success
  assert_output_contains "threatspec, version"
}
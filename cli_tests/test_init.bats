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

@test "initialise threatspec" {
    run threatspec init
    assert_success
    assert_file_exists "threatspec.yaml"
    assert_file_contains "threatspec.yaml" 'name: "threatspec project"'

    assert_dir_exists "threatmodel"
}
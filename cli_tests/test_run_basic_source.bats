#!/usr/bin/env bats

load helpers/assert
load helpers/teardown

setup_once() {
  cat <<'EOF' > source.js
// @mitigates Path:To:Component against A Threat with A Control
function a_line_of_code(with, parameters) {
    this.is_fake()
}
EOF

  cat <<'EOF' > threatspec.yaml
project:
    name: clitest
    description: CLI test
paths:
    - source.js
EOF

  mkdir -p threatmodel
}

teardown_once() {
  if [ -f "source.js" ]; then
    rm source.js
  fi
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

@test "threat model json files created" {
  run threatspec run
  assert_success
  
  assert_dir_exists "threatmodel"
  
  assert_file_exists "threatmodel/threatmodel.json"
  assert_file_contains "threatmodel/threatmodel.json" '"annotation": "@mitigates Path:To:Component against A Threat with A Control"'

  assert_file_exists "threatmodel/threats.json"
  assert_file_contains "threatmodel/threats.json" '"id": "#a_threat"'
  
  assert_file_exists "threatmodel/controls.json"
  assert_file_contains "threatmodel/controls.json" '"id": "#a_control"'

  assert_file_exists "threatmodel/components.json"
  assert_file_contains "threatmodel/components.json" '"id": "#path_to_component"'
}



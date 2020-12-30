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
    - path: "source.js"
      mime: "text/x-javascript"
EOF

  if [ -d "threatmodel" ]; then
    rmdir threatmodel
  fi
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

@test "creates threatmodel directory if missing" {
  refute_file_exists "threatmodel"
  run threatspec run
  assert_success
  
  assert_dir_exists "threatmodel"
}



#!/usr/bin/env bats

load helpers/assert
load helpers/teardown

setup_once() {
  mkdir path1
  mkdir path2

  cat <<'EOF' > path1/threats.threatspec.txt
@threat A Threat (#threat):
  description: Something had happens
EOF
  
  cat <<'EOF' > path2/source.js
// @mitigates Path:To:Component against #threat with A Control
function a_line_of_code(with, parameters) {
    this.is_fake()
}
EOF

  cat <<'EOF' > path1/threatspec.yaml
project:
    name: repo1
    description: repo1 test
paths:
    - threats.threatspec.txt
EOF

  cat <<'EOF' > path2/threatspec.yaml
project:
    name: repo1
    description: repo1 test
imports:
    - ../path1/
paths:
    - path: "source.js"
      mime: "text/x-javascript"
EOF

  mkdir -p path1/threatmodel
  mkdir -p path2/threatmodel
}

teardown_once() {
  if [ -d "path1" ]; then
    pushd path1
    if [ -f "threats.threatspec.txt" ]; then
      rm threats.threatspec.txt
    fi
    teardown_common
    popd
    rmdir path1
  fi
  
  if [ -d "path2" ]; then
    pushd path2
    if [ -f "source.js" ]; then
      rm source.js
    fi
    teardown_common
    popd
    rmdir path2
  fi
    
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

@test "multi repos" {
  pushd path1
  run threatspec run
  assert_success
  
  assert_dir_exists "threatmodel"
  assert_file_exists "threatmodel/threats.json"
  assert_file_contains "threatmodel/threats.json" '"id": "#threat"'
  popd
  
  pushd path2
  run threatspec run
  assert_success
  
  run threatspec report
  assert_success
  
  assert_file_exists "ThreatModel.md"
  assert_file_contains "ThreatModel.md" "A threat"
  popd
}



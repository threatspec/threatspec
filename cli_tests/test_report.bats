#!/usr/bin/env bats

load helpers/assert
load helpers/teardown

setup_once() {
  cat <<'EOF' > threatspec.yaml
project:
    name: reporttest
    description: CLI report test
paths:
    - source.js
EOF

  mkdir -p threatmodel

  cat <<'EOF' > threatmodel/threatmodel.json
{
  "mitigations": [
    {
      "control": "#strict_file_permissions",
      "threat": "#unauthorised_access",
      "component": "#webapp_filesystem",
      "source": {
        "annotation": "@mitigates WebApp:FileSystem against unauthorised access with strict file permissions",
        "code": "func (p *Page) save() error {",
        "filename": "/home/zeroxten/Downloads/src/threatspec/threatspec_examples/simple_web.go",
        "line": 28
      }
    }
  ],
  "exposures": [],
  "transfers": [],
  "acceptances": [],
  "connections": [],
  "reviews": [],
  "tests": [],
  "run_id": "abc123"
}
EOF

  cat <<'EOF' > threatmodel/threats.json
{
  "threats": {
    "#arbitrary_file_writes": {
      "id": "#arbitrary_file_writes",
      "run_id": "abc123",
      "name": "arbitrary file writes",
      "description": ""
    },
    "#unauthorised_access": {
      "id": "#unauthorised_access",
      "run_id": "abc123",
      "name": "unauthorised access",
      "description": ""
    }
  }
}
EOF

  cat <<'EOF' > threatmodel/controls.json
{
  "controls": {
    "#strict_file_permissions": {
      "id": "#strict_file_permissions",
      "run_id": "c37d4f5be64e457d910b7abea66708cf",
      "name": "strict file permissions",
      "description": ""
    },
    "#basic_input_validation": {
      "id": "#basic_input_validation",
      "run_id": "c37d4f5be64e457d910b7abea66708cf",
      "name": "basic input validation",
      "description": ""
    }
  }
}
EOF

  cat <<'EOF' > threatmodel/components.json
{
  "components": {
    "#webapp_filesystem": {
      "id": "#webapp_filesystem",
      "run_id": "c37d4f5be64e457d910b7abea66708cf",
      "name": "WebApp:FileSystem",
      "description": "",
      "paths": [
        [
          "WebApp"
        ],
        [
          "User"
        ]
      ]
    },
    "#webapp_app": {
      "id": "#webapp_app",
      "run_id": "c37d4f5be64e457d910b7abea66708cf",
      "name": "WebApp:App",
      "description": "",
      "paths": [
        [
          "WebApp"
        ],
        [
          "User"
        ]
      ]
    }
  }
}
EOF

  run threatspec report
  assert_success
}

teardown_once() {
  #teardown_common
  pass
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

@test "report only contains one mitigation" {
  assert_file_exists "ThreatModel.md"
  assert_file_contains_count "ThreatModel.md" "unauthorised access" "==1"
  refute_file_contains "ThreatModel.md" "arbitrary file writes"
}

@test "report doesn't include unused library objects" {
  assert_file_exists "ThreatModel.md"
  assert_file_contains "ThreatModel.md" "unauthorised access"
  refute_file_contains "ThreatModel.md" "arbitrary file writes"
}
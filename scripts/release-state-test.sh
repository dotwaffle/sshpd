#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export GH_REPO=example/project RELEASE_TAG=v1.0.0

# Export a stub so the checked script cannot contact GitHub.
gh() {
  if [[ "$*" != 'api --paginate repos/example/project/releases?per_page=100' ]]; then
    return 99
  fi
  printf '%s' "$RESPONSE"
  return "$STATUS"
}
export -f gh

check() {
  local name=$1 expected=$2 result status=0
  export RESPONSE=$3 STATUS=$4
  result=$(bash "$script_dir/release-state.sh" 2>/dev/null) || status=$?
  if [[ $expected == reject ]]; then
    if [[ $status == 0 ]]; then
      printf 'FAIL: %s: expected rejection, got %s\n' "$name" "$result" >&2
      return 1
    fi
  elif [[ $status != 0 || $result != "$expected" ]]; then
    printf 'FAIL: %s: expected %s, got status=%s output=%s\n' "$name" "$expected" "$status" "$result" >&2
    return 1
  fi
  printf 'PASS: %s\n' "$name"
}

check missing missing '[]' 0
check draft draft '[{"tag_name":"v1.0.0","draft":true}]' 0
check published reject '[{"tag_name":"v1.0.0","draft":false}]' 0
check other_tag missing '[{"tag_name":"v0.9.0","draft":false}]' 0
check later_page draft $'[]\n[{"tag_name":"v1.0.0","draft":true}]' 0
check later_published reject $'[]\n[{"tag_name":"v1.0.0","draft":false}]' 0
check api_failure reject '' 1
check partial_page_failure reject '[]' 1
check auth_failure reject '{"message":"Bad credentials"}' 1
check invalid_json reject 'not json' 0
check empty_response reject '' 0
check invalid_response reject '{"message":"Not Found"}' 0
check invalid_state reject '[{"tag_name":"v1.0.0"}]' 0
check duplicate_tag reject '[{"tag_name":"v1.0.0","draft":true},{"tag_name":"v1.0.0","draft":true}]' 0

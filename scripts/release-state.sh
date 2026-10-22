#!/usr/bin/env bash
set -euo pipefail

: "${GH_REPO:?GH_REPO must identify the repository}"
: "${RELEASE_TAG:?RELEASE_TAG must identify the release}"

# A failed lookup must stop publication, even after a successful page.
releases=$(gh api --paginate "repos/$GH_REPO/releases?per_page=100")
printf '%s\n' "$releases" | jq --slurp --exit-status --raw-output --arg tag "$RELEASE_TAG" '
  if length == 0 or any(.[]; type != "array") then
    error("Invalid release list response")
  else
    [.[][] | select(.tag_name == $tag)]
  end
  | if length == 0 then
      "missing"
    elif length == 1 and .[0].draft == true then
      "draft"
    else
      error("Release is published or its state is invalid; stop publication")
    end
'

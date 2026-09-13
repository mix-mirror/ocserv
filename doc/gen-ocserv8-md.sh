#!/bin/sh
# Embeds sample.config, indented as a markdown code block, into ocserv.8.md
# in place of the @CONFIGFILE@ placeholder.
set -e

md="$1"
config="$2"
out="$3"

tmp_config=$(mktemp)
trap 'rm -f "$tmp_config"' EXIT

sed 's/^/    /' "$config" >"$tmp_config"
sed -e "/@CONFIGFILE@/{r $tmp_config" -e 'd}' "$md" >"$out"

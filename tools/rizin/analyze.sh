#!/usr/bin/env bash
# Safe, read-only, general-purpose Rizin report generator.
set -euo pipefail
usage() {
  printf 'Usage: %s [--deep] FILE [OUTPUT_DIR]\n' "$0" >&2
  exit 2
}
level=aa
if [[ "${1:-}" == --deep ]]; then
  level=aaa
  shift
fi
(( $# >= 1 && $# <= 2 )) || usage
input="$1"
[[ -f "$input" && -r "$input" ]] || { printf 'Not a readable file: %s\n' "$input" >&2; exit 1; }
input="$(realpath -- "$input")"
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
output="${2:-$PWD/rizin-reports/$(basename -- "$input")}"
mkdir -p -- "$output"
output="$(realpath -- "$output")"
sha256sum -- "$input" > "$output/sha256.txt"
"$script_dir/launch.sh" rz-bin -I "$input" > "$output/info.txt" 2> "$output/info.stderr" || {
  printf 'rz-bin metadata unsupported or incomplete; see info.stderr\n' >&2
}
"$script_dir/launch.sh" rz-bin -S "$input" > "$output/sections.txt" 2> "$output/sections.stderr" || {
  printf 'rz-bin sections unsupported or incomplete; see sections.stderr\n' >&2
}
"$script_dir/launch.sh" rz-bin -zz "$input" > "$output/strings.txt" 2> "$output/strings.stderr" || {
  printf 'rz-bin strings unsupported or incomplete; see strings.stderr\n' >&2
}
"$script_dir/launch.sh" rizin -2 -q -c "$level; afl; q" "$input" > "$output/functions.txt"
printf 'Analysis: %s\nReports: %s\n' "$level" "$output"

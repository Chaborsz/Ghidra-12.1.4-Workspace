#!/usr/bin/env bash
# Offline-first, verified Rizin launcher for Linux x86_64.
set -euo pipefail

die() { printf 'Rizin workspace: %s\n' "$*" >&2; exit 1; }
if (( $# < 1 )); then
  die 'usage: launch.sh <rizin|rz-bin|rz-asm|rz-hash|rz-find|rz-diff|rz-ax> [arguments ...]'
fi
tool="$1"
shift
case "$tool" in
  rizin|rz-bin|rz-asm|rz-hash|rz-find|rz-diff|rz-ax) ;;
  *) die "unsupported tool: $tool" ;;
esac

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
  die 'the bundled Rizin v0.9.1 static release requires Linux x86_64'

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(cd -- "$script_dir/../.." && pwd)"
bundle_dir="$repo_dir/rizin_offline/v0.9.1-linux-x86_64"
upstream='https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz'
sha256='9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf'

cache_base="${RIZIN_WORKSPACE_CACHE:-${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/ghidra-rizin-workspace}"
install_dir="$cache_base/rizin-v0.9.1-linux-x86_64"
ready() {
  [[ -r "$install_dir/.bin-dir" ]] || return 1
  local subdir
  subdir="$(cat "$install_dir/.bin-dir")"
  [[ -x "$install_dir/$subdir/rizin" && -x "$install_dir/$subdir/rz-bin" ]]
}

if ! ready; then
  command -v flock >/dev/null || die 'flock is required for safe concurrent installation'
  command -v sha256sum >/dev/null || die 'sha256sum is required'
  mkdir -p -- "$cache_base"
  exec 9>"$cache_base/.install.lock"
  flock -x 9
  if ! ready; then
    temp_dir="$(mktemp -d "$cache_base/.install.XXXXXXXX")"
    trap 'rm -rf -- "$temp_dir"' EXIT
    archive="$temp_dir/rizin-v0.9.1-static-x86_64.tar.xz"

    shopt -s nullglob
    parts=( "$bundle_dir"/archive.part* )
    shopt -u nullglob
    if (( ${#parts[@]} > 0 )); then
      cat -- "${parts[@]}" > "$archive"
    else
      command -v curl >/dev/null || die 'archive missing: curl is required for verified upstream download'
      printf 'Rizin workspace: offline bundle absent; fetching pinned upstream release\n' >&2
      curl -fL --retry 5 --retry-delay 2 "$upstream" -o "$archive"
    fi

    printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status ||
      die 'archive SHA-256 mismatch (installation refused)'
    mkdir -p -- "$temp_dir/unpacked"
    tar -xJf "$archive" -C "$temp_dir/unpacked"

    rizin_binary="$(find "$temp_dir/unpacked" \( -type f -o -type l \) -name rizin -print -quit)"
    [[ -n "$rizin_binary" && -x "$rizin_binary" ]] || die 'rizin executable missing from official archive'
    bin_dir="$(dirname -- "$rizin_binary")"
    [[ -x "$bin_dir/rz-bin" ]] || die 'rz-bin executable missing from official archive'
    "$rizin_binary" -v >/dev/null || die 'rizin version smoke test failed'
    "$bin_dir/rz-bin" -I /bin/true >/dev/null || die 'rz-bin ELF smoke test failed'

    relative_bin_dir="${bin_dir#"$temp_dir/unpacked"/}"
    printf '%s\n' "$relative_bin_dir" > "$temp_dir/unpacked/.bin-dir"
    # The lock prevents concurrent installers; the rename makes the cache publish atomic.
    rm -rf -- "$install_dir"
    mv -- "$temp_dir/unpacked" "$install_dir"
  fi
  flock -u 9
fi

bin_subdir="$(cat "$install_dir/.bin-dir")"
executable="$install_dir/$bin_subdir/$tool"
[[ -x "$executable" ]] || die "$tool is not included in the pinned release"
exec "$executable" "$@"

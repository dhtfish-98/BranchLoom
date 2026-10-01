#!/usr/bin/env bash
# Build the renamed synthetic AArch64 target using the caller's Android NDK.
set -euo pipefail
probe_root="$(cd "$(dirname "$0")" && pwd)"
target_api="${API:-29}"
binary_output="$probe_root/librouteprobe.so"
toolkit_root="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
if [ -z "$toolkit_root" ]; then
  echo "Set ANDROID_NDK_HOME (or NDK_HOME) to your Android NDK root." >&2
  exit 1
fi
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) platform_tag=windows-x86_64 ;;
  Darwin) platform_tag=darwin-x86_64 ;;
  *) platform_tag=linux-x86_64 ;;
esac
llvm_root="$toolkit_root/toolchains/llvm/prebuilt/$platform_tag"
compiler_path="$llvm_root/bin/clang"
if [ ! -x "$compiler_path" ]; then compiler_path="$llvm_root/bin/clang.exe"; fi
sysroot_path="$llvm_root/sysroot"
"$compiler_path" --target="aarch64-linux-android${target_api}" --sysroot="$sysroot_path" \
  -O2 -fPIC -shared -Wl,-soname,librouteprobe.so -o "$binary_output" "$probe_root/routeprobe.c"
echo "built $binary_output"
echo "disassemble the dispatcher with:"
echo "  \"$llvm_root/bin/llvm-objdump\" -d \"$binary_output\" | grep -A3 -iE 'ldrsw .*lsl #2'"

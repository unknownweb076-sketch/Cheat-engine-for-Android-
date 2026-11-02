#!/usr/bin/env bash
set -euo pipefail

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
[ -n "$NDK" ] || { echo "ANDROID_NDK_HOME not set"; exit 1; }

HOST="linux-x86_64"
case "$(uname -s)" in
  Darwin) HOST="darwin-x86_64" ;;
esac

CC="$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android26-clang"
[ -x "$CC" ] || { echo "clang not found: $CC"; exit 1; }

mkdir -p app/src/main/jniLibs/arm64-v8a
"$CC" -O2 -fPIE -pie -D_FILE_OFFSET_BITS=64 \
  -o app/src/main/jniLibs/arm64-v8a/libscanhelper.so \
  app/src/main/jni/scanhelper.c

echo "helper built: $(stat -c%s app/src/main/jniLibs/arm64-v8a/libscanhelper.so) bytes"

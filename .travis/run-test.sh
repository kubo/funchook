#!/bin/sh
set -e

cd "$(dirname "$0")"
cd ..
rm -rf build
cd test

dir="target-$1"
shift
rm -rf "$dir"
mkdir "$dir"
cd "$dir"
cmake "$@" ..
make VERBOSE=1

failed() {
  cat debug.log
  exit 1
}

case "$dir" in
*mingw32*)
  cp ../../build/libfunchook.dll .
  wine ./funchook_test_ex || failed
  ;;
*)
  ./funchook_test_ex || failed
  ;;
esac

exit 0

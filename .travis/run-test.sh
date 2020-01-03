#!/bin/sh

cd "$(dirname "$0")"
cd ..
rm -rf build
cd test

dir="target-$1"
shift
rm -rf "$dir"
mkdir "$dir"
cd "$dir"
cmake -DCMAKE_BUILD_TYPE=Release "$@" ..
type make > /dev/null && make || cmake --build .

case "$(basename "$dir")" in
*mingw32*)
    cp ../../build/funchook.dll .
    wine ./funchook_test_ex.exe
    ;;
*windows*)
    cp ../../build/Debug/funchook.dll Debug
    cd Debug
    ./funchook_test_ex.exe
    ;;
*)
    ./funchook_test_ex
    ;;
esac

ret=$?
test ${ret} -eq 0 || cat debug.log
exit ${ret}

#!/bin/sh
set -e

cd `dirname $0`
cd ..

dir=$1
shift

if expr "$dir" : ".*windows$" > /dev/null; then
  GENERATOR_TYPE=multi_config
else
  GENERATOR_TYPE=single_config
fi

if test "`uname -m`" = aarch64; then
  DISASM_BACKENDS="capstone"
else
  DISASM_BACKENDS="distorm zydis capstone"
fi

message() {
  echo "################# $* #################"
}

echodo() {
  echo '$' "$@"
  "$@"
}

build_and_test() {
  NAME=$1
  if test "$2"; then
    CONFIG_OPT="--config $2"
    BUILD_CONFIG_OPT="--build-config $2"
  else
    CONFIG_OPT=""
    BUILD_CONFIG_OPT=""
  fi
  message "build $NAME"
  echodo cmake --build . $CONFIG_OPT
  message "test $NAME"
  if ! echodo ctest --output-on-failure $BUILD_CONFIG_OPT; then
    cat test/debug.log
    exit 1
  fi
}

for disasm in $DISASM_BACKENDS; do
  case "$GENERATOR_TYPE" in
    multi_config)
      mkdir test-$dir-$disasm
      cd test-$dir-$disasm
      message "cmake (using $disasm as disassembler)"
      echodo cmake "$@" -DFUNCHOOK_DISASM=$disasm ..
      build_and_test Release Release
      build_and_test Debug Debug
      cd ..
      ;;
    single_config)
      mkdir test-$dir-$disasm-release
      cd test-$dir-$disasm-release
      message "cmake Release (using $disasm as disassembler)"
      echodo cmake -DCMAKE_BUILD_TYPE=Release "$@" -DFUNCHOOK_DISASM=$disasm ..
      build_and_test Release
      cd ..
      mkdir test-$dir-$disasm-debug
      cd test-$dir-$disasm-debug
      message "cmake Debug (using $disasm as disassembler)"
      echodo cmake -DCMAKE_BUILD_TYPE=Debug "$@" -DFUNCHOOK_DISASM=$disasm ..
      build_and_test Debug
      cd ..
      ;;
  esac
done

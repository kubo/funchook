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

case "$GENERATOR_TYPE" in
  multi_config)
    mkdir test-$dir
    cd test-$dir
    message "cmake"
    echodo cmake "$@" ..
    build_and_test Release Release
    build_and_test Debug Debug
    cd ..
    ;;
  single_config)
    mkdir test-$dir-release
    cd test-$dir-release
    message "cmake Release"
    echodo cmake -DCMAKE_BUILD_TYPE=Release "$@" ..
    build_and_test Release
    cd ..
    mkdir test-$dir-debug
    cd test-$dir-debug
    message "cmake Debug"
    echodo cmake -DCMAKE_BUILD_TYPE=Debug "$@" ..
    build_and_test Debug
    cd ..
    ;;
esac

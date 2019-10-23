#!/bin/sh
set -e

cd `dirname $0`
cd ..

if ! test -f configure; then
  ./autogen.sh
fi

dir=$1
shift
mkdir $dir
cd $dir
../configure "$@"
if ! make test; then
  cat test/debug.log
  exit 1
fi
exit 0


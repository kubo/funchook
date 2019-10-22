#!/bin/sh
set -e

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


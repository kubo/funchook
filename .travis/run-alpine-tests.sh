#!/bin/sh
set -e

script_dir=`dirname $0`

$script_dir/run-test.sh alpine
$script_dir/run-cmake-test.sh alpine

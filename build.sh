#!/bin/bash
PREFIX=$(uname -m)
OS=$(uname | tr '[:upper:]' '[:lower:]')

while getopts "p:o:l" OPTION 2> /dev/null; do
	case ${OPTION} in
		p)
			PREFIX="$OPTARG"
			;;
		o)
			OS="$OPTARG"
			;;
		l)
			X86="yes"
			;;
		?)
			break
			;;
	esac
done

cd test
mkdir -p "${PREFIX}-${OS}" && cd "${PREFIX}-${OS}"
if [[ ${X86} == "yes" ]]; then
	cmake -DCMAKE_C_FLAGS="-m32" .. || exit 1
else
	cmake .. || exit 1
fi
make || exit 1
./funchook_test_ex || (cat test/debug.log; exit 1)
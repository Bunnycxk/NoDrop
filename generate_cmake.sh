#!/usr/bin/bash

DIR=$(dirname $0)
TARGET=${DIR}/build
# BUILD_TYPE="RelWithDebInfo"
BUILD_TYPE="Release"

[[ ! -d "${TARGET}" ]] || mkdir -p ${TARGET}
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DPKEY_SUPPORT=OFF \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -B ${TARGET} \
  -S ${DIR}

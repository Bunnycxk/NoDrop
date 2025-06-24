#!/usr/bin/bash

DIR=$(dirname $0)
TARGET=${DIR}/build

[[ ! -d "${TARGET}" ]] || mkdir -p ${TARGET}
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DPKEY_SUPPORT=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -B ${TARGET} \
  -S ${DIR}

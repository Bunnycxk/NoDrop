#!/usr/bin/bash

DIR=$(dirname $0)
TARGET=${DIR}/build

[[ ! -d "${TARGET}" ]] || mkdir -p ${TARGET}
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DPKEY_SUPPORT=OFF \
  -B ${TARGET} \
  -S ${DIR}

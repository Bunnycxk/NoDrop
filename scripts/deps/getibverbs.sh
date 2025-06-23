#!/bin/sh
set -e

ROOT=$1
DIRNAME=$(dirname "$0")
if [[ "${ROOT}" != "/*" ]]; then 
    echo "Usage: $0 <absolute-path-to-NoTamper>"
    exit 1
fi

VERSION="58.0"
OUTPUT_FILE="${ROOT}/rdma-core-${VERSION}.tar.gz"
OUTPUT_DIR="${ROOT}/rdma-core"
# DOWNLOAD_URL="https://github.com/linux-rdma/rdma-core/archive/refs/tags/v${VERSION}.zip"
DOWNLOAD_URL="https://github.com/linux-rdma/rdma-core/releases/download/v${VERSION}/rdma-core-${VERSION}.tar.gz"

echo "Downloading rdma-core version ${VERSION} from \"${DOWNLOAD_URL}\""
wget ${DOWNLOAD_URL} -O ${OUTPUT_FILE}
tar xzvf ${OUTPUT_FILE}
mv rdma-core-${VERSION} ${OUTPUT_DIR}
rm ${OUTPUT_FILE}

# get musl-wrapped C Compiler from ${DIRNAME}/musl-gcc-path
export CC="$(cat ${DIRNAME}/musl-gcc-path)"

mkdir -p ${OUTPUT_DIR}/build-musl
cd ${OUTPUT_DIR}/build-musl
cmake -DENABLE_STATIC=1 -DNO_MAN_PAGES=1 -DIN_PLACE=1 -DENABLE_RESOLVE_NEIGH=0 -DNO_PYVERBS=1 ..
make -j4

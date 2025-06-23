#!/bin/sh

set -e

ROOT=$1
DIRNAME=$(dirname "$0")
if [[ "${ROOT}" != "/*" ]]; then 
    echo "Usage: $0 <absolute-path-to-NoTamper>"
    exit 1
fi

${DIRNAME}/getmusl.sh "${ROOT}"
${DIRNAME}/getibverbs.sh "${ROOT}"

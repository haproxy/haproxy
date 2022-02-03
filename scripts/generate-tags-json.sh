#!/bin/bash
# Copyright (c) 2022 Daniele Rondina <geaaru@funtoo.org>
# Description: Generate the JSON and YAML files with the details
#              of all releases available in the download directory.
#
# NOTE: This script require https://github.com/stedolan/jq and
#       https://github.com/mikefarah/yq tools.
#
# The JSON output for every branch will be in this format:
#
#
# {
#    "branch": "2.5",
#    "last_release: "2.5.1",
#    "releases: {
#       "2.5.1": {
#          "file": "haproxy-2.5.1.tar.gz",
#          "md5": "7e08480a6c52f2c3be8a9b778c54105f",
#          "sha256": "0666cea8d90f9f5635b5fd8e4f49a555ed132def650d463125b2106d53d11187",
#       }
#
#    }
# }

SOURCE_DIR=${SOURCE_DIR:-}
DOWNLOAD_TOOLS=${DOWNLOAD_TOOLS:-0}

JQ_VERSION=${JQ_VERSION:-1.6}
YQ_VERSION=${YQ_VERSION:-4.18.1}
yq=/usr/bin/yq4
jq=/usr/bin/jq

die() {
  [ "$#" -eq 0 ] || echo "$*" >&2
  exit 1
}

download_tools() {
  wget -O /usr/local/bin/jq \
    https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64 || {
    die "Error on download jq!"
  }

  wget -O /usr/local/bin/yq4 \
    https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64 || {
    die "Error on download yq!"
  }

  chmod a+x /usr/bin/yq4 /usr/bin/jq

  export PATH=${PATH}:/usr/local/bin
}

main() {
  local prevbranch=""
  local tarball=""
  local branch=""
  local branchdir=""
  local branch_counter=0

  if [ "${DOWNLOAD_TOOLS}" = "1" ] ; then
    # Download tools
    download_tools
    yq=/usr/local/bin/yq
    jq=/usr/local/bin/jq
  fi

  export yq jq

  for f in $(find ${SOURCE_DIR}  -name 'haproxy-*.tar.gz' | sort -r) ; do
    tarball=$(basename $f)
    branch=$(basename $(realpath $(dirname $f)/..))
    branchdir=$(dirname $f)
    release=$(echo ${tarball} | sed -e 's|haproxy-||g' -e 's|.tar.gz||g')
    md5=$(cat ${f}.md5 | cut -d' ' -f1)
    sha256=$(cat ${f}.sha256 | cut -d' ' -f1)

    echo "Parsing ${tarball} for branch ${branch}..."

    if [ "${branch}" != "${prevbranch}" ] ; then
      branch_counter=0
      # POST: The first tarball is the last release of the branch.

      # Remove existing yaml and json
      rm -f ${branchdir}/releases.yaml ${branchdir}/releases.json || true

      touch ${branchdir}/releases.yaml

      ${yq} e ".branch = \"${branch}\"" -i ${branchdir}/releases.yaml
      ${yq} e ".last_release = \"${release}\"" -i ${branchdir}/releases.yaml
      ${yq} e ".releases.\"${release}\".file = \"${tarball}\"" -i ${branchdir}/releases.yaml
      ${yq} e ".releases.\"${release}\".md5 = \"${md5}\"" -i ${branchdir}/releases.yaml
      ${yq} e ".releases.\"${release}\".sha256 = \"${sha256}\"" -i ${branchdir}/releases.yaml
    else

      ${yq} e ".releases.\"${release}\".file = \"${tarball}\"" -i ${branchdir}/releases.yaml
      ${yq} e ".releases.\"${release}\".md5 = \"${md5}\"" -i ${branchdir}/releases.yaml
      ${yq} e ".releases.\"${release}\".sha256 = \"${sha256}\"" -i ${branchdir}/releases.yaml
    fi

    yq4 e -o j ${branchdir}/releases.yaml > ${branchdir}/releases.json

    prevbranch=${branch}
    let branch_counter++
  done

  return 0
}

if [ $# -ne 1 ] ; then
  die "$0 <download-dir>"
else
  SOURCE_DIR=$1
fi

echo "Using source dir: ${SOURCE_DIR}"

main $@
exit $?

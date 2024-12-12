#!/usr/bin/python3

# Copyright 2019 Ilya Shipitsin <chipitsine@gmail.com>
# Copyright 2020 Tim Duesterhus <tim@bastelstu.be>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.

import functools
import json
import re
import sys
import urllib.request
from os import environ
from packaging import version

#
# this CI is used for both development and stable branches of HAProxy
#
# naming convention used, if branch name matches:
#
#   "haproxy-" - stable branches
#   otherwise  - development branch (i.e. "latest" ssl variants, "latest" github images)
#

def clean_ssl(ssl):
    return ssl.replace("_VERSION", "").lower()

def get_all_github_tags(url):
    headers = {}
    if environ.get("GITHUB_TOKEN") is not None:
        headers["Authorization"] = "token {}".format(environ.get("GITHUB_TOKEN"))
    request = urllib.request.Request(url, headers=headers)
    try:
        tags = urllib.request.urlopen(request)
    except:
        return None
    tags = json.loads(tags.read().decode("utf-8"))
    return [tag['name'] for tag in tags]

@functools.lru_cache(5)
def determine_latest_openssl(ssl):
    tags = get_all_github_tags("https://api.github.com/repos/openssl/openssl/tags")
    if not tags:
        return "OPENSSL_VERSION=failed_to_detect"
    latest_tag = ""
    for tag in tags:
        if "openssl-" in tag:
            if (not latest_tag) or (version.parse(tag[8:]) > version.parse(latest_tag[8:])):
                latest_tag = tag
    return "OPENSSL_VERSION={}".format(latest_tag[8:])

def aws_lc_version_string_to_num(version_string):
    return tuple(map(int, version_string[1:].split('.')))

def aws_lc_version_valid(version_string):
    return re.match('^v[0-9]+(\.[0-9]+)*$', version_string)

@functools.lru_cache(5)
def determine_latest_aws_lc(ssl):
    tags = get_all_github_tags("https://api.github.com/repos/aws/aws-lc/tags")
    if not tags:
        return "AWS_LC_VERSION=failed_to_detect"
    valid_tags = list(filter(aws_lc_version_valid, tags))
    latest_tag = max(valid_tags, key=aws_lc_version_string_to_num)
    return "AWS_LC_VERSION={}".format(latest_tag[1:])

def aws_lc_fips_version_string_to_num(version_string):
    return tuple(map(int, version_string[12:].split('.')))

def aws_lc_fips_version_valid(version_string):
    return re.match('^AWS-LC-FIPS-[0-9]+(\.[0-9]+)*$', version_string)

@functools.lru_cache(5)
def determine_latest_aws_lc_fips(ssl):
    # the AWS-LC-FIPS tags are at the end of the list, so let's get a lot
    tags = get_all_github_tags("https://api.github.com/repos/aws/aws-lc/tags?per_page=200")
    if not tags:
        return "AWS_LC_FIPS_VERSION=failed_to_detect"
    valid_tags = list(filter(aws_lc_fips_version_valid, tags))
    latest_tag = max(valid_tags, key=aws_lc_fips_version_string_to_num)
    return "AWS_LC_FIPS_VERSION={}".format(latest_tag[12:])

def wolfssl_version_string_to_num(version_string):
    return tuple(map(int, version_string[1:].removesuffix('-stable').split('.')))

def wolfssl_version_valid(version_string):
    return re.match('^v[0-9]+(\.[0-9]+)*-stable$', version_string)

@functools.lru_cache(5)
def determine_latest_wolfssl(ssl):
    tags = get_all_github_tags("https://api.github.com/repos/wolfssl/wolfssl/tags")
    if not tags:
        return "WOLFSSL_VERSION=failed_to_detect"
    valid_tags = list(filter(wolfssl_version_valid, tags))
    latest_tag = max(valid_tags, key=wolfssl_version_string_to_num)
    return "WOLFSSL_VERSION={}".format(latest_tag[1:].removesuffix('-stable'))

@functools.lru_cache(5)
def determine_latest_libressl(ssl):
    try:
      libressl_download_list = urllib.request.urlopen(
          "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/"
      )
    except:
      return "LIBRESSL_VERSION=failed_to_detect"
    for line in libressl_download_list.readlines():
        decoded_line = line.decode("utf-8")
        if "libressl-" in decoded_line and ".tar.gz.asc" in decoded_line:
            l = re.split("libressl-|.tar.gz.asc", decoded_line)[1]
    return "LIBRESSL_VERSION={}".format(l)


def clean_compression(compression):
    return compression.replace("USE_", "").lower()


def main(ref_name):
    print("Generating matrix for branch '{}'.".format(ref_name))

    matrix = []

    # Ubuntu

    if "haproxy-" in ref_name:
        os = "ubuntu-22.04" # stable branch
    else:
        os = "ubuntu-24.04" # development branch

    TARGET = "linux-glibc"
    for CC in ["gcc", "clang"]:
        matrix.append(
            {
                "name": "{}, {}, no features".format(os, CC),
                "os": os,
                "TARGET": TARGET,
                "CC": CC,
                "FLAGS": [],
            }
        )

        matrix.append(
            {
                "name": "{}, {}, all features".format(os, CC),
                "os": os,
                "TARGET": TARGET,
                "CC": CC,
                "FLAGS": [
                    'DEBUG="-DDEBUG_LIST"',
                    "USE_ZLIB=1",
                    "USE_OT=1",
                    "OT_INC=${HOME}/opt-ot/include",
                    "OT_LIB=${HOME}/opt-ot/lib",
                    "OT_RUNPATH=1",
                    "USE_PCRE2=1",
                    "USE_PCRE2_JIT=1",
                    "USE_LUA=1",
                    "USE_OPENSSL=1",
                    "USE_WURFL=1",
                    "WURFL_INC=addons/wurfl/dummy",
                    "WURFL_LIB=addons/wurfl/dummy",
                    "USE_DEVICEATLAS=1",
                    "DEVICEATLAS_SRC=addons/deviceatlas/dummy",
                    "USE_PROMEX=1",
                    "USE_51DEGREES=1",
                    "51DEGREES_SRC=addons/51degrees/dummy/pattern",
                ],
            }
        )

        # ASAN

        matrix.append(
            {
                "name": "{}, {}, ASAN, all features".format(os, CC),
                "os": os,
                "TARGET": TARGET,
                "CC": CC,
                "FLAGS": [
                    "USE_OBSOLETE_LINKER=1",
                    'ARCH_FLAGS="-g -fsanitize=address"',
                    'OPT_CFLAGS="-O1"',
                    "USE_ZLIB=1",
                    "USE_OT=1",
                    "OT_INC=${HOME}/opt-ot/include",
                    "OT_LIB=${HOME}/opt-ot/lib",
                    "OT_RUNPATH=1",
                    "USE_PCRE2=1",
                    "USE_PCRE2_JIT=1",
                    "USE_LUA=1",
                    "USE_OPENSSL=1",
                    "USE_WURFL=1",
                    "WURFL_INC=addons/wurfl/dummy",
                    "WURFL_LIB=addons/wurfl/dummy",
                    "USE_DEVICEATLAS=1",
                    "DEVICEATLAS_SRC=addons/deviceatlas/dummy",
                    "USE_PROMEX=1",
                    "USE_51DEGREES=1",
                    "51DEGREES_SRC=addons/51degrees/dummy/pattern",
                ],
            }
        )

        for compression in ["USE_ZLIB=1"]:
            matrix.append(
                {
                    "name": "{}, {}, gz={}".format(os, CC, clean_compression(compression)),
                    "os": os,
                    "TARGET": TARGET,
                    "CC": CC,
                    "FLAGS": [compression],
                }
            )

        ssl_versions = [
            "stock",
            "OPENSSL_VERSION=1.0.2u",
            "OPENSSL_VERSION=1.1.1s",
            "QUICTLS=yes",
            "WOLFSSL_VERSION=5.7.0",
            "AWS_LC_VERSION=1.39.0",
            # "BORINGSSL=yes",
        ]

        if "haproxy-" not in ref_name: # development branch
            ssl_versions = ssl_versions + [
                "OPENSSL_VERSION=latest",
                "LIBRESSL_VERSION=latest",
            ]

        for ssl in ssl_versions:
            flags = ["USE_OPENSSL=1"]
            if ssl == "BORINGSSL=yes" or ssl == "QUICTLS=yes" or "LIBRESSL" in ssl or "WOLFSSL" in ssl or "AWS_LC" in ssl:
                flags.append("USE_QUIC=1")
            if "WOLFSSL" in ssl:
                flags.append("USE_OPENSSL_WOLFSSL=1")
            if "AWS_LC" in ssl:
                flags.append("USE_OPENSSL_AWSLC=1")
            if ssl != "stock":
                flags.append("SSL_LIB=${HOME}/opt/lib")
                flags.append("SSL_INC=${HOME}/opt/include")
            if "LIBRESSL" in ssl and "latest" in ssl:
                ssl = determine_latest_libressl(ssl)
            if "OPENSSL" in ssl and "latest" in ssl:
                ssl = determine_latest_openssl(ssl)

            matrix.append(
                {
                    "name": "{}, {}, ssl={}".format(os, CC, clean_ssl(ssl)),
                    "os": os,
                    "TARGET": TARGET,
                    "CC": CC,
                    "ssl": ssl,
                    "FLAGS": flags,
                }
            )

    # macOS

    if "haproxy-" in ref_name:
        os = "macos-13"     # stable branch
    else:
        os = "macos-15"     # development branch

    TARGET = "osx"
    for CC in ["clang"]:
        matrix.append(
            {
                "name": "{}, {}, no features".format(os, CC),
                "os": os,
                "TARGET": TARGET,
                "CC": CC,
                "FLAGS": [],
            }
        )

    # Print matrix

    print(json.dumps(matrix, indent=4, sort_keys=True))

    if environ.get("GITHUB_OUTPUT") is not None:
        with open(environ.get("GITHUB_OUTPUT"), "a") as f:
            print("matrix={}".format(json.dumps({"include": matrix})), file=f)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        ref_name = sys.argv[1]
        main(ref_name)
    else:
        print("Usage: {} <ref_name>".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

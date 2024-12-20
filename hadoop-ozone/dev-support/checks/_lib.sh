#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

check_name="$(basename "${BASH_SOURCE[1]}")"
check_name="${check_name%.sh}"

: ${TOOLS_DIR:=$(pwd)/.dev-tools} # directory for tools
: ${OZONE_PREFER_LOCAL_TOOL:=true} # skip install if tools are already available (eg. via package manager)

## @description  Install a dependency.  Only first argument is mandatory.
## @param name of the tool
## @param the directory for binaries, relative to the tool directory; added to PATH.
## @param the directory for the tool, relative to TOOLS_DIR
## @param name of the executable, for testing if it is already installed
## @param name of the function that performs actual installation steps
_install_tool() {
  local tool bindir dir bin func

  tool="$1"
  bindir="${2:-}"
  dir="${TOOLS_DIR}"/"${3:-"${tool}"}"
  bin="${4:-"${tool}"}"
  func="${5:-"_install_${tool}"}"

  if [[ "${OZONE_PREFER_LOCAL_TOOL}" == "true" ]] && which "$bin" >& /dev/null; then
    echo "Skip installing $bin, as it's already available on PATH."
    return
  fi

  if [[ ! -d "${dir}" ]]; then
    mkdir -pv "${dir}"
    pushd "${dir}"
    if eval "${func}"; then
      echo "Installed ${tool} in ${dir}"
    else
      echo "Failed to install ${tool}"
      exit 1
    fi
    popd
  fi

  if [[ -n "${bindir}" ]]; then
    bindir="${dir}"/"${bindir}"
    if [[ -d "${bindir}" ]]; then
      if [[ "${OZONE_PREFER_LOCAL_TOOL}" == "true" ]]; then
        export PATH="${PATH}:${bindir}"
      else
        export PATH="${bindir}:${PATH}"
      fi
    fi
  fi
}

install_bats() {
  _install_tool bats bats-core-1.2.1/bin
}

_install_bats() {
  curl -LSs https://github.com/bats-core/bats-core/archive/v1.2.1.tar.gz | tar -xz -f -
}

install_k3s() {
  _install_tool k3s
}

_install_k3s() {
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.21.2+k3s1" sh -
  sudo chmod a+r $KUBECONFIG
}

install_flekszible() {
  _install_tool flekszible bin
}

_install_flekszible() {
  mkdir bin

  local os=$(uname -s)
  local arch=$(uname -m)

  curl -LSs https://github.com/elek/flekszible/releases/download/v2.3.0/flekszible_2.3.0_${os}_${arch}.tar.gz | tar -xz -f - -C bin

  chmod +x bin/flekszible
}

install_hugo() {
  _install_tool hugo bin
}

_install_hugo() {
  : ${HUGO_VERSION:=0.83.1}

  local os=$(uname -s)
  local arch=$(uname -m)

  mkdir bin

  case "${os}" in
    Darwin)
      os=macOS
      ;;
  esac

  case "${arch}" in
    x86_64)
      arch=64bit
      ;;
  esac

  curl -LSs "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_${HUGO_VERSION}_${os}-${arch}.tar.gz" | tar -xz -f - -C bin hugo
  chmod +x bin/hugo
}

install_virtualenv() {
  _install_tool virtualenv
}

_install_virtualenv() {
  sudo pip3 install virtualenv
}

install_robot() {
  _install_tool robot venv/bin
}

_install_robot() {
  virtualenv venv
  source venv/bin/activate
  pip install robotframework
}

install_spotbugs() {
  _install_tool spotbugs spotbugs-3.1.12/bin
}

_install_spotbugs() {
  curl -LSs https://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/3.1.12/spotbugs-3.1.12.tgz | tar -xz -f -
}

download_hadoop_aws() {
  local dir="$1"

  if [[ -z ${dir} ]]; then
    echo "Required argument: target directory for Hadoop AWS sources" >&2
    return 1
  fi

  if [[ ! -e "${dir}" ]] || [[ ! -d "${dir}"/src/test/resources ]]; then
    mkdir -p "${dir}"
    if [[ ! -f "${dir}.tar.gz" ]]; then
      local url="https://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-${HADOOP_VERSION}-src.tar.gz"
      echo "Downloading Hadoop from ${url}"
      curl -LSs --fail -o "${dir}.tar.gz" "$url" || return 1
    fi
    tar -x -z -C "${dir}" --strip-components=3 -f "${dir}.tar.gz" --wildcards 'hadoop-*-src/hadoop-tools/hadoop-aws' || return 1
  fi
}

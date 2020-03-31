# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image=gcr.io/fuzzbench/base-builder
FROM $parent_image

# Install Clang/LLVM 6.0.
RUN apt-get update -y && \
    apt-get -y install llvm-6.0 \
    clang-6.0 llvm-6.0-dev llvm-6.0-tools

# Install KLEE dependencies
RUN apt-get install -y \
    cmake-data build-essential curl libcap-dev \
    git cmake libncurses5-dev python-minimal \
    python-pip unzip libtcmalloc-minimal4 \
    libgoogle-perftools-dev bison flex libboost-all-dev \
    perl zlib1g-dev libsqlite3-dev doxygen

ENV INSTALL_DIR=/out

# Install minisat
RUN git clone https://github.com/stp/minisat.git /minisat && \
    cd /minisat && mkdir build && cd build && \
    CXXFLAGS= cmake -DSTATIC_BINARIES=ON \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DCMAKE_BUILD_TYPE=Release ../ && \
    make -j`nproc` && make install

# Install STP solver
RUN git clone https://github.com/stp/stp.git /stp && \
    cd /stp && git checkout tags/2.1.2 && \
    mkdir build && cd build && \
    CXXFLAGS= cmake -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DENABLE_PYTHON_INTERFACE:BOOL=OFF \
    -DMINISAT_LIBRARY=$INSTALL_DIR/lib/libminisat.so \
    -DMINISAT_INCLUDE_DIR=$INSTALL_DIR/include \
    -DCMAKE_INSTALL_PREFIX=/user/local/ -DCMAKE_BUILD_TYPE=Release .. && \
    make -j`nproc` && make install

# Install klee-uclibc. TODO: do we need libcxx?
RUN git clone https://github.com/lmrs2/klee-uclibc.git /klee-uclibc && \
    cd /klee-uclibc && \
    ./configure --make-llvm-lib --with-llvm-config=`which llvm-config-6.0` && \
    make -j`nproc` && make install

# Install KLEE. Use my personal repo containing additional scripts we need for now.
RUN git clone https://github.com/lmrs2/klee.git /klee && \
    cd /klee && \
    git checkout debug && \
    mkdir build && cd build && \
    CXXFLAGS= cmake -DENABLE_SOLVER_STP=ON -DENABLE_POSIX_RUNTIME=ON \
    -DENABLE_KLEE_UCLIBC=ON -DKLEE_UCLIBC_PATH=/klee-uclibc/ \
    -DENABLE_SYSTEM_TESTS=OFF -DENABLE_UNIT_TESTS=OFF \
    -DLLVM_CONFIG_BINARY=`which llvm-config-6.0` -DLLVMCC=`which clang-6.0` \
    -DLLVMCXX=`which clang++-6.0` -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR ../ \
    -DCMAKE_BUILD_TYPE=Release && \
    make -j`nproc` && make install

# debugging
#RUN apt-get -y install vim less apt-file

# Install golang and wllvm
ENV GOPATH=/
ENV PATH=$PATH:$GOPATH/bin
RUN apt-get -y install \
    software-properties-common && \
    add-apt-repository -y ppa:gophers/archive && \
    apt-get update -y && \
    apt-get -y install golang-1.10-go && \
    go get github.com/SRI-CSL/gllvm/cmd/...

ENV LLVM_CC_NAME=clang-6.0
ENV LLVM_CXX_NAME=clang++-6.0
ENV LLVM_AR_NAME=llvm-ar-6.0
ENV LLVM_LINK_NAME=llvm-link-6.0
ENV LLVM_COMPILER=clang
ENV CC=gclang
ENV CXX=gclang++

# Compile the harness klee_driver.cpp.
COPY klee_driver.cpp /klee_driver.cpp
COPY klee_mock.c /klee_mock.c
RUN $CXX -stdlib=libc++ -std=c++11 -O2 -c /klee_driver.cpp && \ 
    ar r /libAFL.a /klee_driver.o && \
    $LLVM_CC_NAME -O2 -c -fPIC /klee_mock.c && \
    $LLVM_CC_NAME -shared -o /libKleeMock.so /klee_mock.o

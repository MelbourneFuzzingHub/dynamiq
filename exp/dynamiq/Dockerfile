FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --fix-missing -y \
      autoconf \
      autogen \
      automake \
      bison \
      build-essential \
      ca-certificates \
      clang-15 \
      cmake \
      curl \
      flex \
      git \
      libglib2.0-dev \
      libgtk-3-dev \
      libjbig-dev \
      libjpeg-dev \
      libboost-dev \
      libcairo2-dev \
      libc++-dev \
      libc++abi-dev \
      liblcms2-dev \
      liblzma-dev \
      libopenjp2-7-dev \
      libpixman-1-dev \
      libtool \
      lld-15 \
      llvm-15 \
      llvm-15-dev \
      meson \
      nasm \
      ninja-build \
      pkg-config \
      python3 \
      python3-dev \
      python3-pip \
      python3-setuptools \
      python-is-python3 \
      re2c \
      sudo \
      texinfo \
      unzip \
      wget \
      xz-utils \
      zlib1g-dev && \
    python3 -m pip install --no-cache-dir \
      'cmake==3.31.6' \
      'meson==1.3.2' \
      'networkx' \
      'numpy==2.2.6' \
      'psutil' \
      'pydot<2.0' \
      'scipy>=1.14.0' \
      'scikit-learn>=1.5.0' \
      'wllvm' \
      'jsonschema' \
      'jinja2' && \
    rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/root/.cargo
ENV RUSTUP_HOME=/root/.rustup
ENV LLVM_CONFIG=llvm-config-15
ENV LLVM_COMPILER=clang
ENV LLVM_COMPILER_PATH=/usr/lib/llvm-15/bin
ENV PATH=/root/.cargo/bin:/root/.local/bin:/usr/lib/llvm-15/bin:/dynamiq/AFLplusplus4.22a:/opt/dynamiq-fuzzers/target/release:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
      sh -s -- -y --profile minimal

COPY fuzzers /opt/dynamiq-fuzzers

WORKDIR /opt/dynamiq-fuzzers

RUN . /root/.cargo/env && \
    cargo build --release --bin parallel_sync --bin parallel_sync_cmplog --bin advanced_sync --bin advanced_cmplog --bin run --bin compile

WORKDIR /workdir/subjects

# vmp-devirt build env: LLVM 22 + Rust + Python lifting deps.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# LLVM 22 is NOT on stock noble: pull from apt.llvm.org (same as CI llvm-link job).
RUN apt-get update && apt-get install -y wget gnupg \
    && wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
    && echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-22 main" | tee /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y \
    cmake ninja-build git curl python3 python3-pip pkg-config \
    llvm-22-dev libclang-22-dev clang-22 libpolly-22-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip3 install --break-system-packages triton-library capstone pefile
COPY . /root/vmp-devirt
WORKDIR /root/vmp-devirt
# Remill (optional backend): build separately, point REMILL_LIFT at it.
#   git clone https://github.com/lifting-bits/remill /root/remill && ...
RUN cargo build --release
CMD ["./target/release/devirt", "--help"]

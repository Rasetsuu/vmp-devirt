# vmp-devirt build env: LLVM 22 + Rust + Python lifting deps.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    cmake ninja-build git curl python3 python3-pip pkg-config \
    llvm-22-dev libclang-22-dev clang-22 \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip3 install --break-system-packages triton-library capstone pefile
COPY . /root/vmp-devirt
WORKDIR /root/vmp-devirt
# Remill (optional backend): build separately, point REMILL_LIFT at it.
#   git clone https://github.com/lifting-bits/remill /root/remill && ...
RUN cargo build --release
CMD ["./target/release/vmp-devirt", "--help"]

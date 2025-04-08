FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential gdb libssl-dev \
    gcc-11 g++-11 \
    python3 python3-pip python3-setuptools \
    wget curl libboost-all-dev libtool \
    git && rm -rf /var/lib/apt/lists/*

# Set gcc/g++ to version 11
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 100

# Install CMake 4.0.0 from prebuilt binary
RUN wget https://cmake.org/files/v4.0/cmake-4.0.0-linux-x86_64.tar.gz && \
    tar -xzf cmake-4.0.0-linux-x86_64.tar.gz --strip-components=1 -C /usr/local && \
    rm cmake-4.0.0-linux-x86_64.tar.gz

WORKDIR /app
COPY . .

# Build app (generates ./out folder with frontend binary)
RUN python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON

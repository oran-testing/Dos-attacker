FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y gcc g++ make xz-utils dpdk-dev libnuma-dev wget linux-headers-generic

WORKDIR /app

COPY . .

RUN wget https://fast.dpdk.org/rel/dpdk-19.11.14.tar.xz

RUN tar -xvf ./dpdk-19.11.14.tar.xz
RUN rm -f ./dpdk-19.11.14.tar.xz

RUN cd dpdk-stable-19.11.14 && \
    sed -i \
    -e 's|DIRS-$(CONFIG_RTE_EAL_IGB_UIO) += igb_uio||g' \
    -e 's|DIRS-$(CONFIG_RTE_KNI_KMOD) += kni||g' \
    ./kernel/linux/Makefile && \
    make defconfig O=x86_64-native-linuxapp-gcc && \
    make -j$(nproc) O=x86_64-native-linuxapp-gcc/

ENV PCAP_DIR="/app/Traffic"
ENV RTE_SDK="/app/dpdk-stable-19.11.14/"
ENV RTE_TARGET="x86_64-native-linuxapp-gcc"

RUN rm -rf build && make -f DPDK_Makefile

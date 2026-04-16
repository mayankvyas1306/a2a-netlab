FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    iproute2 \
    iputils-ping \
    net-tools \
    bridge-utils \
    tcpdump \
    traceroute \
    curl \
    vim \
    netcat-openbsd \
    iperf3 \
    strace \
    frr \
    frr-pythontools \
    openvswitch-switch \
    openvswitch-common \
    python3 \
    python3-pip \
    libcjson-dev \
    gcc \
    make \
    cmake \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/frr && chown -R frr:frr /var/run/frr
RUN mkdir -p /var/run/openvswitch

RUN sed -i "s/ospfd=no/ospfd=yes/" /etc/frr/daemons
RUN sed -i "s/zebra=no/zebra=yes/" /etc/frr/daemons

COPY a2a /root/a2a

RUN cd /root/a2a && rm -rf build && mkdir build && cd build && \
    cmake .. && make -j && \
    cp a2a_agent /usr/local/bin/a2a_agent && \
    chmod +x /usr/local/bin/a2a_agent
CMD ["/bin/bash"]

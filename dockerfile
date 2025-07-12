FROM ubuntu:22.04 
#minimized image, if man is needed run unminimize :p

ENV DEBIAN_FRONTEND=noninteractive

# install more tools and utilities for testing 
RUN apt-get update && \
    apt-get install -y \
        gcc \
        make \
        build-essential \
        curl \
        iproute2 \
        iputils-ping \
        net-tools \            
        psmisc \             
        procps \               
        lsof \
        strace \
        tcpdump \
        less \
        vim \
        nano \
        dialog \
        python3 \
        python3-pip \
        man-db \
        manpages \
        ncat \
        check \
        nginx \
        locales && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set up UTF-8 locale , safeguard against issues with unicode in man and vim, etc
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

WORKDIR /root

# Expose the SOCKS5 port && admin port
# could be deleted tbh
EXPOSE 1080
EXPOSE 8080

CMD ["/bin/bash"]
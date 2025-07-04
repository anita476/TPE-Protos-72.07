FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && \
    apt-get install -y gcc make check ncat curl iproute2 whiptail && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /root

# Expose the SOCKS5 port && admin port
# could be deleted tbh
EXPOSE 1080
EXPOSE 8080

CMD ["/bin/bash"]
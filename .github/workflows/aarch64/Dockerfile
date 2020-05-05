FROM arm64v8/ubuntu:20.04


ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true

RUN apt-get update -y

# general build dependencies
RUN apt-get install -y gcc git make wget

# for HAProxy
RUN apt-get install -y clang-9 liblua5.3-dev libpcre3-dev libsystemd-dev socat 

# for VTest
RUN apt-get install -y zlib1g-dev 

ADD build-and-test.sh /usr/bin

CMD ["build-and-test.sh"]
FROM arm64v8/ubuntu:20.04


ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true

RUN apt-get update -y
RUN apt-get install -y liblua5.3-dev libsystemd-dev libpcre2-dev clang-9 socat
RUN apt-get install -y make

ADD build-and-test.sh /usr/bin

CMD ["build-and-test.sh"]
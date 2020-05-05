FROM arm64v8/ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true

RUN apt update -y
RUN apt install -y liblua5.3-dev libsystemd-dev libpcre2-dev clang-9 socat


ENV FLAGS="USE_ZLIB=1 USE_PCRE=1 USE_PCRE_JIT=1 USE_LUA=1 USE_OPENSSL=1 USE_SYSTEMD=1 USE_WURFL=1 WURFL_INC=contrib/wurfl WURFL_LIB=contrib/wurfl USE_DEVICEATLAS=1 DEVICEATLAS_SRC=contrib/deviceatlas USE_51DEGREES=1"
ENV SSL_LIB=${HOME}/opt/lib
ENV SSL_INC=${HOME}/opt/include
ENV TMPDIR=/tmp
ENV FIFTYONEDEGREES_SRC="contrib/51d/src/pattern"
ENV DEBUG_OPTIONS="DEBUG_STRICT=1"


CMD ["ls", "-la", "/haproxy"]
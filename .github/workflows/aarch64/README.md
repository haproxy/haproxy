How to build and test HAProxy on aarch64 architecture
=======================================

At the time of writing GitHub Actions CI provides only x86_64 machines [1](https://help.github.com/en/actions/reference/virtual-environments-for-github-hosted-runners#about-github-hosted-runners) [2](https://docs.microsoft.com/en-us/azure/virtual-machines/dv2-dsv2-series#dsv2-series)


One way to execute the build and test commands on foreign CPU architecture
is to use [QEMU](https://www.qemu.org/).
To simplify the installation of QEMU here we make use of [multiarch/qemu-user-static](https://hub.docker.com/r/multiarch/qemu-user-static) Docker container.
By executing

    $ docker run --rm --privileged multiarch/qemu-user-static --reset --credential yes --persistent yes

we make it possible to run any Docker image built for one of the supported by QEMU CPU architectures, e.g.:

    $ docker run -it --rm arm64v8/ubuntu:20.04 uname -m

Instead of executing `uname -m` we will execute the build scripts of HAProxy. 


Build and run locally
=====================

To run (and debug) the Docker images locally follow these steps:

1. Register QEMU in memory

    `$ docker run --rm --privileged multiarch/qemu-user-static --reset --credential yes --persistent yes`

1. Build a new Docker image that sets up the dependencies

    `$ docker build .github/workflows/aarch64 -t haproxy-aarch64:latest`

1. Create a folder where HAProxy will be checked out and
where OpenSSL will be cached (the `opt` folder)

    `$ mkdir -p /path/to/haproxy-root/haproxy/opt`

1. Checkout HAProxy, if you don't have it already

    `$ git clone https://github.com/haproxy/haproxy.git /path/to/haproxy-root/haproxy`    

1. Execute the newly built image:

    `$ docker run -it -v/path/to/haproxy-root/haproxy:/haproxy -v/path/to/haproxy-root/opt:/root/opt haproxy-aarch64:latest`

The main logic for building and testing HAProxy is in [build-and-test.sh](./build-and-test.sh) which is copied to the custom Docker image. This makes it much faster to rebuild the image when modifications are needed.

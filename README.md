# HAProxy

[![alpine/musl](https://github.com/haproxy/haproxy/actions/workflows/musl.yml/badge.svg)](https://github.com/haproxy/haproxy/actions/workflows/musl.yml)
[![AWS-LC](https://github.com/haproxy/haproxy/actions/workflows/aws-lc.yml/badge.svg)](https://github.com/haproxy/haproxy/actions/workflows/aws-lc.yml)
[![openssl no-deprecated](https://github.com/haproxy/haproxy/actions/workflows/openssl-nodeprecated.yml/badge.svg)](https://github.com/haproxy/haproxy/actions/workflows/openssl-nodeprecated.yml)
[![Illumos](https://github.com/haproxy/haproxy/actions/workflows/illumos.yml/badge.svg)](https://github.com/haproxy/haproxy/actions/workflows/illumos.yml)
[![NetBSD](https://github.com/haproxy/haproxy/actions/workflows/netbsd.yml/badge.svg)](https://github.com/haproxy/haproxy/actions/workflows/netbsd.yml)
[![FreeBSD](https://api.cirrus-ci.com/github/haproxy/haproxy.svg?task=FreeBSD)](https://cirrus-ci.com/github/haproxy/haproxy/)
[![VTest](https://github.com/haproxy/haproxy/actions/workflows/vtest.yml/badge.svg)](https://github.com/haproxy/haproxy/actions/workflows/vtest.yml)

![HAProxy logo](doc/HAProxyCommunityEdition_60px.png)

HAProxy is a free, very fast and reliable reverse-proxy offering high availability, load balancing, and proxying for TCP
and HTTP-based applications.

## Installation

The [INSTALL](INSTALL) file describes how to build HAProxy.
A [list of packages](https://github.com/haproxy/wiki/wiki/Packages) is also available on the wiki.

## Getting help

The [discourse](https://discourse.haproxy.org/) and the [mailing-list](https://www.mail-archive.com/haproxy@formilux.org/)
are available for questions or configuration assistance. You can also use the [slack](https://slack.haproxy.org/) or
[IRC](irc://irc.libera.chat/%23haproxy) channel. Please don't use the issue tracker for these.

The [issue tracker](https://github.com/haproxy/haproxy/issues/) is only for bug reports or feature requests.

## Documentation

The HAProxy documentation has been split into a number of different files for
ease of use. It is available in text format as well as HTML. The wiki is also meant to replace the old architecture
guide.

- [HTML documentation](http://docs.haproxy.org/)
- [HTML HAProxy LUA API Documentation](https://www.arpalert.org/haproxy-api.html)
- [Wiki](https://github.com/haproxy/wiki/wiki)

Please refer to the following files depending on what you're looking for:

  - [INSTALL](INSTALL) for instructions on how to build and install HAProxy
  - [BRANCHES](BRANCHES) to understand the project's life cycle and what version to use
  - [LICENSE](LICENSE) for the project's license
  - [CONTRIBUTING](CONTRIBUTING) for the process to follow to submit contributions

The more detailed documentation is located into the doc/ directory:

  - [ doc/intro.txt ](doc/intro.txt) for a quick introduction on HAProxy
  - [ doc/configuration.txt ](doc/configuration.txt) for the configuration's reference manual
  - [ doc/lua.txt ](doc/lua.txt) for the Lua's reference manual
  - [ doc/SPOE.txt ](doc/SPOE.txt) for how to use the SPOE engine
  - [ doc/network-namespaces.txt ](doc/network-namespaces.txt) for how to use network namespaces under Linux
  - [ doc/management.txt ](doc/management.txt) for the management guide
  - [ doc/regression-testing.txt ](doc/regression-testing.txt) for how to use the regression testing suite
  - [ doc/peers.txt ](doc/peers.txt) for the peers protocol reference
  - [ doc/coding-style.txt ](doc/coding-style.txt) for how to adopt HAProxy's coding style
  - [ doc/internals ](doc/internals) for developer-specific documentation (not all up to date)

## License

HAProxy is licensed under [GPL 2](doc/gpl.txt) or any later version, the headers under [LGPL 2.1](doc/lgpl.txt). See the
[LICENSE](LICENSE) file for a more detailed explanation.

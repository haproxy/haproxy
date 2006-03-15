Summary: HA-Proxy is a TCP/HTTP reverse proxy for high availability environments
Name: haproxy
Version: 1.2.9
Release: 1
License: GPL
Group: System Environment/Daemons
URL: http://w.ods.org/tools/haproxy/

Source0: http://w.ods.org/tools/haproxy/haproxy-%{version}.tar.gz
Source1: haproxy.cfg
Source2: haproxy.init
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: pcre-devel
Requires: /sbin/chkconfig, /sbin/service

%description
HA-Proxy is a TCP/HTTP reverse proxy which is particularly suited for high
availability environments. Indeed, it can:
- route HTTP requests depending on statically assigned cookies
- spread the load among several servers while assuring server persistence
  through the use of HTTP cookies
- switch to backup servers in the event a main one fails
- accept connections to special ports dedicated to service monitoring
- stop accepting connections without breaking existing ones
- add/modify/delete HTTP headers both ways
- block requests matching a particular pattern

It needs very little resource. Its event-driven architecture allows it to easily
handle thousands of simultaneous connections on hundreds of instances without
risking the system's stability.

%prep
%setup

%build
%{__make} REGEX="pcre" "COPTS.pcre=-DUSE_PCRE $(pcre-config --cflags)" DEBUG="" TARGET=linux24e

%install
%{__rm} -rf %{buildroot}
 
%{__install} -d -m0755 %{buildroot}%{_datadir}/haproxy/

%{__install} -D -m0755 haproxy %{buildroot}%{_sbindir}/haproxy
%{__install} -D -m0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/haproxy/haproxy.cfg
%{__install} -D -m0755 %{SOURCE2} %{buildroot}%{_initrddir}/haproxy
 
%clean
%{__rm} -rf %{buildroot}
 
%post
/sbin/chkconfig --add haproxy

%preun
if [ $1 -eq 0 ]; then
	/sbin/service haproxy stop &>/dev/null || :
	/sbin/chkconfig --del haproxy
fi

%postun
if [ $1 -ge 1 ]; then
	/sbin/service haproxy condrestart &>/dev/null || :
fi

%files
%defattr(-, root, root, 0755)
%doc CHANGELOG README TODO doc/* examples/
%config(noreplace) %{_sysconfdir}/haproxy/
%config %{_initrddir}/haproxy
%{_sbindir}/haproxy
%dir %{_datadir}/haproxy/

%changelog
* Wed Mar 15 2006 Willy Tarreau <willy@w.ods.org> - 1.2.9-1
- ported to 1.2.9.

* Tue Feb 07 2006 Dag Wieers <dag@wieers.com> - 1.1.34-1
- Initial package. (using DAR)

Summary: HA-Proxy is a TCP/HTTP reverse proxy for high availability environments
Name: haproxy
Version: 1.3.14.9
Release: 1
License: GPL
Group: System Environment/Daemons
URL: http://haproxy.1wt.eu/
Source0: http://haproxy.1wt.eu/download/1.3/src/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
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
%setup -q

%build
%{__make} REGEX="pcre" "COPTS.pcre=-DUSE_PCRE $(pcre-config --cflags)" DEBUG="" TARGET=linux24e SMALL_OPTS="-DBUFSIZE=8030 -DMAXREWRITE=1030 -DSYSTEM_MAXCONN=1024" DEBUG="" LIBS.pcre="-L\$(PCREDIR)/lib -Wl,-Bstatic -lpcreposix -lpcre -Wl,-Bdynamic"

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
 
%{__install} -d %{buildroot}%{_sbindir}
%{__install} -d %{buildroot}%{_sysconfdir}/rc.d/init.d
%{__install} -d %{buildroot}%{_sysconfdir}/%{name}

%{__install} -s %{name} %{buildroot}%{_sbindir}/
%{__install} -c -m 644 examples/%{name}.cfg %{buildroot}%{_sysconfdir}/%{name}/
%{__install} -c -m 755 examples/%{name}.init %{buildroot}%{_sysconfdir}/rc.d/init.d/%{name}
 
%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
 
%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
  /sbin/service %{name} stop >/dev/null 2>&1 || :
  /sbin/chkconfig --del %{name}
fi

%postun
if [ "$1" -ge "1" ]; then
  /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root)
%doc CHANGELOG TODO examples doc/haproxy-en.txt doc/haproxy-fr.txt doc/architecture.txt examples/url-switching.cfg
%attr(0755,root,root) %{_sbindir}/%{name}
%dir %{_sysconfdir}/%{name}
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.cfg
%attr(0755,root,root) %config %{_sysconfdir}/rc.d/init.d/%{name}

%changelog
* Sun Oct 12 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.9

* Sun Sep 14 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.8

* Tue Sep 02 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.7

* Sat Jun 21 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.6

* Sun May 25 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.5

* Thu Mar 20 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.4

* Sat Mar 08 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.3

* Mon Jan 21 2008 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.2

* Mon Dec 24 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14.1

* Wed Dec  5 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.14

* Thu Oct 18 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.13

* Sun Jun 17 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.12

* Sun Jun  3 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.11.4

* Mon May 14 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.11.3

* Mon May 14 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.11.2

* Mon May 14 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.11.1

* Mon May 14 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.11

* Thu May 10 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.10.2

* Tue May 09 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.10.1

* Tue May 08 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.10

* Sun Apr 15 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.9

* Tue Apr 03 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.8.2

* Sun Apr 01 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.8.1

* Sun Mar 25 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.8

* Wed Jan 26 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.7

* Wed Jan 22 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.6

* Wed Jan 07 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.5

* Wed Jan 02 2007 Willy Tarreau <w@1wt.eu>
- updated to 1.3.4

* Wed Oct 15 2006 Willy Tarreau <w@1wt.eu>
- updated to 1.3.3

* Wed Sep 03 2006 Willy Tarreau <w@1wt.eu>
- updated to 1.3.2

* Wed Jul 09 2006 Willy Tarreau <w@1wt.eu>
- updated to 1.3.1

* Wed May 21 2006 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.14

* Wed May 01 2006 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.13

* Wed Apr 15 2006 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.12

* Wed Mar 30 2006 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.11.1

* Wed Mar 19 2006 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.10

* Wed Mar 15 2006 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.9

* Sat Jan 22 2005 Willy Tarreau <willy@w.ods.org>
- updated to 1.2.3 (1.1.30)

* Sun Nov 14 2004 Willy Tarreau <w@w.ods.org>
- updated to 1.1.29
- fixed path to config and init files
- statically linked PCRE to increase portability to non-pcre systems

* Sun Jun  6 2004 Willy Tarreau <willy@w.ods.org>
- updated to 1.1.28
- added config check support to the init script

* Tue Oct 28 2003 Simon Matter <simon.matter@invoca.ch>
- updated to 1.1.27
- added pid support to the init script

* Wed Oct 22 2003 Simon Matter <simon.matter@invoca.ch>
- updated to 1.1.26

* Thu Oct 16 2003 Simon Matter <simon.matter@invoca.ch>
- initial build

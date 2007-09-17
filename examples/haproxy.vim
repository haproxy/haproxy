" Vim syntax file
" Language:    HAproxy
" Maintainer:  Bruno Michel <brmichel@free.fr>
" Last Change: Mar 30, 2007
" Version:     0.3
" URL:         http://haproxy.1wt.eu/
" URL:         http://vim.sourceforge.net/scripts/script.php?script_id=1845

" It is suggested to add the following line to $HOME/.vimrc :
"    au BufRead,BufNewFile haproxy* set ft=haproxy

" For version 5.x: Clear all syntax items
" For version 6.x: Quit when a syntax file was already loaded
if version < 600
	syntax clear
elseif exists("b:current_syntax")
	finish
endif

if version >= 600
	setlocal iskeyword=_,-,a-z,A-Z,48-57
else
	set iskeyword=_,-,a-z,A-Z,48-57
endif


" Escaped chars
syn match   hapEscape    +\\\(\\\| \|n\|r\|t\|#\|x\x\x\)+

" Comments
syn match   hapComment   /#.*$/ contains=hapTodo
syn keyword hapTodo      contained TODO FIXME XXX
syn case ignore

" Sections
syn match   hapSection   /^\s*\(global\|defaults\)/
syn match   hapSection   /^\s*\(listen\|frontend\|backend\|ruleset\)/         skipwhite nextgroup=hapSectLabel
syn match   hapSectLabel /\S\+/                                               skipwhite nextgroup=hapIp1 contained
syn match   hapIp1       /\(\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\?:\d\{1,5}/        nextgroup=hapIp2 contained
syn match   hapIp2       /,\(\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\?:\d\{1,5}/hs=s+1 nextgroup=hapIp2 contained

" Parameters
syn keyword hapParam     chroot cliexp clitimeout contimeout
syn keyword hapParam     daemon debug disabled
syn keyword hapParam     enabled
syn keyword hapParam     fullconn
syn keyword hapParam     gid grace group
syn keyword hapParam     maxconn monitor-uri
syn keyword hapParam     nbproc noepoll nopoll
syn keyword hapParam     pidfile
syn keyword hapParam     quiet
syn keyword hapParam     redispatch retries
syn keyword hapParam     reqallow  reqdel  reqdeny  reqpass  reqtarpit  skipwhite nextgroup=hapRegexp
syn keyword hapParam     reqiallow reqidel reqideny reqipass reqitarpit skipwhite nextgroup=hapRegexp
syn keyword hapParam     rspdel  rspdeny    skipwhite nextgroup=hapRegexp
syn keyword hapParam     rspidel rspideny   skipwhite nextgroup=hapRegexp
syn keyword hapParam     reqsetbe reqisetbe skipwhite nextgroup=hapRegexp2
syn keyword hapParam     reqadd reqiadd rspadd rspiadd
syn keyword hapParam     server source srvexp srvtimeout
syn keyword hapParam     uid ulimit-n user
syn keyword hapParam     reqrep reqirep rsprep rspirep    skipwhite nextgroup=hapRegexp
syn keyword hapParam     errorloc errorloc302 errorloc303 skipwhite nextgroup=hapStatus
syn keyword hapParam     default_backend                  skipwhite nextgroup=hapSectLabel
syn keyword hapParam     appsession  skipwhite nextgroup=hapAppSess
syn keyword hapParam     bind        skipwhite nextgroup=hapIp1
syn keyword hapParam     balance     skipwhite nextgroup=hapBalance
syn keyword hapParam     cookie      skipwhite nextgroup=hapCookieNam
syn keyword hapParam     capture     skipwhite nextgroup=hapCapture
syn keyword hapParam     dispatch    skipwhite nextgroup=hapIpPort
syn keyword hapParam     source      skipwhite nextgroup=hapIpPort
syn keyword hapParam     mode        skipwhite nextgroup=hapMode
syn keyword hapParam     monitor-net skipwhite nextgroup=hapIPv4Mask
syn keyword hapParam     option      skipwhite nextgroup=hapOption
syn keyword hapParam     stats       skipwhite nextgroup=hapStats
syn keyword hapParam     server      skipwhite nextgroup=hapServerN
syn keyword hapParam     source      skipwhite nextgroup=hapServerEOL
syn keyword hapParam     log         skipwhite nextgroup=hapGLog,hapLogIp

" Options and additional parameters
syn keyword hapAppSess   contained len timeout
syn keyword hapBalance   contained roundrobin source
syn keyword hapLen       contained len
syn keyword hapGLog      contained global
syn keyword hapMode      contained http tcp health
syn keyword hapOption    contained abortonclose allbackups checkcache clitcpka dontlognull forceclose forwardfor
syn keyword hapOption    contained httpchk httpclose httplog keepalive logasap persist srvtcpka ssl-hello-chk
syn keyword hapOption    contained tcplog tcpka tcpsplice
syn keyword hapOption    contained except skipwhite nextgroup=hapIPv4Mask
syn keyword hapStats     contained uri realm auth scope enable
syn keyword hapLogFac    contained kern user mail daemon auth syslog lpr news nextgroup=hapLogLvl skipwhite
syn keyword hapLogFac    contained uucp cron auth2 ftp ntp audit alert cron2  nextgroup=hapLogLvl skipwhite
syn keyword hapLogFac    contained local0 local1 local2 local3 local4 local5 local6 local7 nextgroup=hapLogLvl skipwhite
syn keyword hapLogLvl    contained emerg alert crit err warning notice info debug
syn keyword hapCookieKey contained rewrite insert nocache postonly indirect prefix nextgroup=hapCookieKey skipwhite
syn keyword hapCapture   contained cookie nextgroup=hapNameLen skipwhite
syn keyword hapCapture   contained request response nextgroup=hapHeader skipwhite
syn keyword hapHeader    contained header nextgroup=hapNameLen skipwhite
syn keyword hapSrvKey    contained backup cookie check inter rise fall port source minconn maxconn weight usesrc
syn match   hapStatus    contained /\d\{3}/
syn match   hapIPv4Mask  contained /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\(\/\d\{1,2}\)\?/
syn match   hapLogIp     contained /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/   nextgroup=hapLogFac skipwhite
syn match   hapIpPort    contained /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}:\d\{1,5}/
syn match   hapServerAd  contained /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\(:[+-]\?\d\{1,5}\)\?/ nextgroup=hapSrvEOL skipwhite
syn match   hapNameLen   contained /\S\+/ nextgroup=hapLen       skipwhite
syn match   hapCookieNam contained /\S\+/ nextgroup=hapCookieKey skipwhite
syn match   hapServerN   contained /\S\+/ nextgroup=hapServerAd  skipwhite
syn region  hapSrvEOL    contained start=/\S/ end=/$/ contains=hapSrvKey
syn region  hapRegexp    contained start=/\S/ end=/\(\s\|$\)/ skip=/\\ / nextgroup=hapRegRepl skipwhite
syn region  hapRegRepl   contained start=/\S/ end=/$/ contains=hapComment,hapEscape,hapBackRef
syn region  hapRegexp2   contained start=/\S/ end=/\(\s\|$\)/ skip=/\\ / nextgroup=hapSectLabel skipwhite
syn match   hapBackref   contained /\\\d/


" Transparent is a Vim keyword, so we need a regexp to match it
syn match   hapParam     +transparent+
syn match   hapOption    +transparent+ contained


" Define the default highlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version < 508
	command -nargs=+ HiLink hi link <args>
else
	command -nargs=+ HiLink hi def link <args>
endif

HiLink      hapEscape    SpecialChar
HiLink      hapBackRef   Special
HiLink      hapComment   Comment
HiLink      hapTodo      Todo
HiLink      hapSection   Constant
HiLink      hapSectLabel Identifier
HiLink      hapParam     Keyword

HiLink      hapRegexp    String
HiLink      hapRegexp2   hapRegexp
HiLink      hapIp1       Number
HiLink      hapIp2       hapIp1
HiLink      hapLogIp     hapIp1
HiLink      hapIpPort    hapIp1
HiLink      hapIPv4Mask  hapIp1
HiLink      hapServerAd  hapIp1
HiLink      hapStatus    Number

HiLink      hapOption    Operator
HiLink      hapAppSess   hapOption
HiLink      hapBalance   hapOption
HiLink      hapCapture   hapOption
HiLink      hapCookieKey hapOption
HiLink      hapHeader    hapOption
HiLink      hapGLog      hapOption
HiLink      hapLogFac    hapOption
HiLink      hapLogLvl    hapOption
HiLink      hapMode      hapOption
HiLink      hapStats     hapOption
HiLink      hapLen       hapOption
HiLink      hapSrvKey    hapOption


delcommand HiLink

let b:current_syntax = "haproxy"
" vim: ts=8

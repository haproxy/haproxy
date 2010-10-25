#
# Net-SNMP perl plugin for Haproxy
# Version 0.30
#
# Copyright 2007-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
#
# 1. get a variable from "show stat":
#  1.3.6.1.4.1.29385.106.1.$type.$field.$iid.$sid
#   type: 0->frontend, 1->backend, 2->server, 3->socket
#
# 2. get a variable from "show info":
#  1.3.6.1.4.1.29385.106.2.$req.$varnr
#
# TODO:
# - implement read timeout
#

use NetSNMP::agent (':all');
use NetSNMP::ASN qw(:all);
use IO::Socket::UNIX;

use strict;

my $agent = new NetSNMP::agent('Name' => 'Haproxy');
my $sa = "/var/run/haproxy.stat";

use constant OID_HAPROXY => '1.3.6.1.4.1.29385.106';
use constant OID_HAPROXY_STATS => OID_HAPROXY . '.1';
use constant OID_HAPROXY_INFO => OID_HAPROXY . '.2';

my $oid_stat = new NetSNMP::OID(OID_HAPROXY_STATS);
my $oid_info = new NetSNMP::OID(OID_HAPROXY_INFO);

use constant STATS_PXNAME => 0;
use constant STATS_SVNAME => 1;
use constant STATS_IID => 27;
use constant STATS_SID => 28;
use constant STATS_TYPE => 32;

use constant FIELD_INDEX => 10001;
use constant FIELD_NAME => 10002;

my %info_vars = (
	0	=> 'Name',
	1	=> 'Version',
	2	=> 'Release_date',
	3	=> 'Nbproc',
	4	=> 'Process_num',
	5	=> 'Pid',
	6	=> 'Uptime',
	7	=> 'Uptime_sec',
	8	=> 'Memmax_MB',
	9	=> 'Ulimit-n',
	10	=> 'Maxsock',
	11	=> 'Maxconn',
	12	=> 'Maxpipes',
	13	=> 'CurrConns',
	14	=> 'PipesUsed',
	15	=> 'PipesFree',
	16	=> 'Tasks',
	17	=> 'Run_queue',
	18	=> 'node',
	19	=> 'description',
);

sub find_next_stat_id {
	my($type, $field, $proxyid, $sid) = @_;

	my $obj = 1 << $type;

	my $np = -1;
	my $nl = -1;

	my $sock = new IO::Socket::UNIX (Peer => $sa, Type => SOCK_STREAM, Timeout => 1);
	next if !$sock;

	print $sock "show stat -1 $obj -1\n";

	while(<$sock>) {
		chomp;
		my @d = split(',');

		last if !$d[$field] && $field != FIELD_INDEX && $field != FIELD_NAME && /^#/;
		next if /^#/;

		next if $d[STATS_TYPE] != $type;

		next if ($d[STATS_IID] < $proxyid) || ($d[STATS_IID] == $proxyid && $d[STATS_SID] <= $sid);

		if ($np == -1 || $d[STATS_IID] < $np || ($d[STATS_IID] == $np && $d[STATS_SID] < $nl)) {
			$np = $d[STATS_IID];
			$nl = $d[STATS_SID];
			next;
		}
	}

	close($sock);

	return 0 if ($np == -1);

	return "$type.$field.$np.$nl"
}

sub haproxy_stat {
	my($handler, $registration_info, $request_info, $requests) = @_;

	for(my $request = $requests; $request; $request = $request->next()) {
		my $oid = $request->getOID();

		$oid =~ s/$oid_stat//;
		$oid =~ s/^\.//;

		my $mode = $request_info->getMode();

		my($type, $field, $proxyid, $sid, $or) = split('\.', $oid, 5);

		next if $type > 3 || defined($or);

		if ($mode == MODE_GETNEXT) {

			$type = 0 if !$type;
			$field = 0 if !$field;
			$proxyid = 0 if !$proxyid;
			$sid = 0 if !$sid;

			my $nextid = find_next_stat_id($type, $field, $proxyid, $sid);
			$nextid = find_next_stat_id($type, $field+1, 0, 0) if !$nextid;
			$nextid = find_next_stat_id($type+1, 0, 0, 0) if !$nextid;

			if ($nextid) {
				($type, $field, $proxyid, $sid) = split('\.', $nextid);
				$request->setOID(sprintf("%s.%s", OID_HAPROXY_STATS, $nextid));
				$mode = MODE_GET;
			}
		}

		if ($mode == MODE_GET) {
				next if !defined($proxyid) || !defined($type) || !defined($sid) || !defined($field);

				my $obj = 1 << $type;

				my $sock = new IO::Socket::UNIX (Peer => $sa, Type => SOCK_STREAM, Timeout => 1);
				next if !$sock;

				print $sock "show stat $proxyid $obj $sid\n";

				while(<$sock>) {
					chomp;
					my @data = split(',');

					last if !defined($data[$field]) && $field != FIELD_INDEX && $field != FIELD_NAME;

					if ($proxyid) {
						next if $data[STATS_IID] ne $proxyid;
						next if $data[STATS_SID] ne $sid;
						next if $data[STATS_TYPE] ne $type;
					}

					if ($field == FIELD_INDEX) {
						$request->setValue(ASN_OCTET_STR,
							sprintf("%s.%s", $data[STATS_IID],
								$data[STATS_SID]));
					} elsif ($field == FIELD_NAME) {
						$request->setValue(ASN_OCTET_STR,
							sprintf("%s/%s", $data[STATS_PXNAME],
								$data[STATS_SVNAME]));
					} else {
						$request->setValue(ASN_OCTET_STR, $data[$field]);
					}

					close($sock);
					last;
				}

				close($sock);
				next;
		}

  	}
}

sub haproxy_info {
	my($handler, $registration_info, $request_info, $requests) = @_;

	for(my $request = $requests; $request; $request = $request->next()) {
		my $oid = $request->getOID();

		$oid =~ s/$oid_info//;
		$oid =~ s/^\.//;

		my $mode = $request_info->getMode();

		my($req, $nr, $or) = split('\.', $oid, 3);

		next if $req >= 2 || defined($or);

		if ($mode == MODE_GETNEXT) {
			$req = 0 if !defined($req);
			$nr  = -1 if !defined($nr);

			if (!defined($info_vars{$nr+1})) {
				$req++;
				$nr = -1;
			}

			next if $req >= 2;

			$request->setOID(sprintf("%s.%s.%s", OID_HAPROXY_INFO, $req, ++$nr));
			$mode = MODE_GET;
			
		}

		if ($mode == MODE_GET) {

			next if !defined($req) || !defined($nr);

			if ($req == 0) {
				next if !defined($info_vars{$nr});
				$request->setValue(ASN_OCTET_STR, $info_vars{$nr});
				next;
			}

			if ($req == 1) {
				next if !defined($info_vars{$nr});

				my $sock = new IO::Socket::UNIX (Peer => $sa, Type => SOCK_STREAM, Timeout => 1);
				next if !$sock;

				print $sock "show info\n";

				while(<$sock>) {
					chomp;
					my ($key, $val) = /(.*):\s*(.*)/;

					next if $info_vars{$nr} ne $key;

					$request->setValue(ASN_OCTET_STR, $val);
					last;
				}

				close($sock);
			}
		}
	}
}

$agent->register('Haproxy stat', OID_HAPROXY_STATS, \&haproxy_stat);
$agent->register('Haproxy info', OID_HAPROXY_INFO, \&haproxy_info);


#!/usr/bin/env perl
# pasta: a TCP connection that cannot be bound to the outbound interface is
# reset, not connected unbound (vpn-zones, review 2026-09-25).
#
# With --outbound-if4/-if6, tcp_bind_outbound() only logs a failed
# SO_BINDTODEVICE (ENODEV once the interface is gone, or renamed) and the
# caller connects the socket anyway — by the host's routes, from the host's
# address. vpn-zones binds a zone to one interface so that its traffic leaves
# by it or not at all; in the moment between the interface going and the
# holder killing pasta, a SYN went out another way. Now the flow is reset.
#
# A script rather than a diff: the function's signature and its warnings
# differ between passt releases, and a diff that does not apply would break
# the build of whoever has another release. It edits by meaning, and dies —
# failing the build loudly — when any of the three places is not found.
use strict;
use warnings;

local $/;
my $s = <STDIN>;

$s =~ s/static void tcp_bind_outbound\(/static int tcp_bind_outbound(/
    or die "passt patch: tcp_bind_outbound's signature not found\n";

my $n = ($s =~ s/("Can't bind IPv[46] TCP socket to interface %s",\s*c->ip[46]\.ifname_out\);)/$1\n\t\t\t\treturn -1;/g);
$n == 2 or die "passt patch: expected 2 interface binding warnings, found $n\n";

my $start = index($s, "static int tcp_bind_outbound(");
my $end = index($s, "\n}\n", $start);
$end > $start or die "passt patch: tcp_bind_outbound's end not found\n";
substr($s, $end, 3) = "\n\treturn 0;\n}\n";

$s =~ /\n\ttcp_bind_outbound\(c, conn, s([^;]*)\);\n/
    or die "passt patch: the call of tcp_bind_outbound not found\n";
my ($args, $call_start, $call_end) = ($1, $-[0], $+[0]);
my $after = substr($s, $call_end);
$after =~ /(tcp_rst\([^;]*\);)/
    or die "passt patch: no tcp_rst after the call\n";
my $rst = $1;
substr($s, $call_start, $call_end - $call_start) =
    "\n\t/* Bound to the outbound interface or not connected at all. */\n"
  . "\tif (tcp_bind_outbound(c, conn, s$args)) {\n\t\t$rst\n\t\tgoto cancel;\n\t}\n";

print $s;

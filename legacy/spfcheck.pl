#!/usr/bin/perl

use strict;
use warnings;
use Mail::SPF;

# Relay- and Trustclients pass right through
if ( (defined($ENV{'RELAYCLIENT'})) ||
     (defined($ENV{'TRUSTCLIENT'})) ) {
  print "\n";
  exit 0;
}

# Make sure that SMTPHELOHOST is set
if (not(defined($ENV{'SMTPHELOHOST'}))) { print "\n"; exit 0; };

my $spf_server = Mail::SPF::Server->new();
my $request = Mail::SPF::Request->new(ip_address    => $ENV{'TCPREMOTEIP'},
                                      identity      => $ENV{'SMTPMAILFROM'},
                                      helo_identity => $ENV{'SMTPHELOHOST'},
				      scope         => 'mfrom');

my $result = $spf_server->process($request);

# Reject the client if SPF check returns "fail"
if ($result->code eq 'fail') {
  print STDERR getppid()." SPF check failed for $ENV{'SMTPMAILFROM'}\n";
  print STDERR getppid()." Mail recipient would have been $ENV{'SMTPRCPTTO'}\n";
  print "E451 SPF check failed: ".$result->local_explanation."\n";
} else {
  print "\n";
}

exit;

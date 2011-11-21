#!/usr/bin/perl

use strict;
use warnings;
use Mail::SPF::Query;

my $query = new Mail::SPF::Query (ip => $ENV{'TCPREMOTEIP'}, sender=>$ENV{'SMTPMAILFROM'}, helo=>$ENV{'SMTPHELOHOST'}, trusted=>1, guess=>1);

my ($result,           # pass | fail | softfail | neutral | none | error | unknown [mechanism]
    $smtp_comment,     # "please see http://spf.pobox.com/why.html?..."  when rejecting, return this string to the SMTP client
    $header_comment,   # prepend_header("Received-SPF" => "$result ($header_comment)")
    $spf_record,       # "v=spf1 ..." original SPF record for the domain
   ) = $query->result2();

# Relay- and Trustclients pass right through
if ( (defined($ENV{'RELAYCLIENT'})) ||
     (defined($ENV{'TRUSTCLIENT'})) ) {
  print "\n";
  exit 0;
}

# Reject the client if SPF check returns "fail"
if ($result eq 'fail') {
  print STDERR getppid()." SPF check failed for $ENV{'SMTPMAILFROM'} !\n";
  print STDERR getppid()." Mail recipient would have been $ENV{'SMTPRCPTTO'}\n";
  print "E451 SPF check failed: $smtp_comment\n";
} else {
  print "\n";
}

exit;


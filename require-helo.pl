#!/usr/bin/perl

use strict;
use warnings;

# Relay- and Trustclients pass right through
if ( (defined($ENV{'RELAYCLIENT'})) ||
     (defined($ENV{'TRUSTCLIENT'})) ) {
  print "\n";
  exit 0;
}

if ($ENV{'SMTPHELOHOST'} eq '') {
  print STDERR getppid()." Host did not send helo/ehlo\n";
  print "E503 Please say HELO/EHLO first\n";
}

exit;

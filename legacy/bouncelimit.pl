#!/usr/bin/perl

use strict;
use warnings;

if ( ($ENV{'SMTPMAILFROM'} eq '') && ($ENV{'SMTPRCPTCOUNT'} >= 1) ) {
  print STDERR getppid()." Empty envelope sender with multiple recipients from $ENV{'TCPREMOTEIP'} !\n";
  print "E550 Bounces should only have one recipient\n";
} else {
  print "\n";
}

exit;

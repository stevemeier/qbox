#!/usr/bin/perl

use strict;
use warnings;

if (defined($ENV{'RELAYCLIENT'}) || defined($ENV{'TRUSTCLIENT'})) {
  print STDERR getppid()." mail from: $ENV{'SMTPMAILFROM'}\n";
  print STDERR getppid()." rcpt to: $ENV{'SMTPRCPTTO'}\n";
  print "\n";
}

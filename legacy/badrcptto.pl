#!/usr/bin/perl

use strict;
use warnings;

my $recipient = $ENV{'SMTPRCPTTO'};

# Relay- and trustclients pass right trough
# If we have no configfile we give up
if ( (defined($ENV{'RELAYCLIENT'})) || 
     (defined($ENV{'TRUSTCLIENT'})) ||
     (not(-r "/var/qmail/control/badrcptto")) ) {
  print "\n";
  exit(0);
}

# Check the list of bad recepients
open(BADRCPTTO,  "/var/qmail/control/badrcptto");
while(<BADRCPTTO>) {
  chomp($_);
  if ($recipient eq $_) {
    print STDERR getppid()." Found $recipient in badrcptto list !\n";
    print "E550 This address no longer accepts mail [$recipient]\n";
    close(BADRCPTTO);
    exit(0);
  }
}
close(BADRCPTTO);

print "\n";
exit(0);

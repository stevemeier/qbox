#!/usr/bin/perl

use strict;
use warnings;

# Get the provided hostname from $SMTPHELOHOST
my $hostname = $ENV{'SMTPHELOHOST'};

# Check if it is a relay/trustclient
# Check if config file exists
if ( (defined($ENV{'RELAYCLIENT'})) || 
     (defined($ENV{'TRUSTCLIENT'})) ||
     (not(-r "/var/qmail/control/badhelo")) ) {
  print "\n";
  exit(0);
}

# Go through configuration file (if necessary)
open(BADHELO,  "/var/qmail/control/badhelo");
while(<BADHELO>) {
  chomp($_);
  if ($hostname =~ /$_/i) {
    # Reject client
    print STDERR getppid()." Found $hostname in badhelo list !\n";
    sleep 5;
    print "E550 Bad hostname [$hostname]\n";
    close(BADHELO);
    exit(0);
  }
}
close(BADHELO);

# Send OK to client
print "\n";

exit(0);

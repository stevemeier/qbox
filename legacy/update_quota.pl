#!/usr/bin/perl

use strict;
use warnings;

use File::Find;

my $bytes;

find(\&wanted, $ARGV[0]);

if (-w "$ARGV[0]\/.mailquota") {
  open(MAILQUOTA, "> $ARGV[0]\/.mailquota");
    print MAILQUOTA $bytes;
  close(MAILQUOTA);
}

sub wanted {
  $bytes += -s $_;
}

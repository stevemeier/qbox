#!/usr/bin/perl

use strict;
use warnings;
use Net::DNS;

my $resolver = Net::DNS::Resolver->new;
my ($user, $domain) = '';
my (@mx, $a, $dummy);
my $dnsok = 0;

# Split sender into user and domain parts
if ($ENV{'SMTPMAILFROM'} =~ /\w+\@\w+/) {
   ($user, $domain) = split(/\@/, $ENV{'SMTPMAILFROM'});
}

# Relay- and Trustclients pass right through
if ( (defined($ENV{'RELAYCLIENT'})) || 
     (defined($ENV{'TRUSTCLIENT'})) ||
     (not($domain)) ) {
  print "\n";
  exit(0);
}

# Check if the senders domain has an MX record
@mx = mx($resolver, $domain);
if (@mx) {
  foreach $dummy (@mx) {
    if ($dummy->exchange ne '') {
      $dnsok = 1;
    }
  }
}

# If there is no MX, is there at least an A record?
if (not($dnsok)) {
  $a = $resolver->search($domain,'A');
  if ($a) {
    foreach $dummy ($a->answer) {
      if ($dummy->type eq 'A') {
        $dnsok = 1;
      }
    }
  }
}

# If there is an A or MX record it's okay
if ($dnsok) { 
  print STDERR getppid()." Sender $ENV{'SMTPMAILFROM'} passed domain check\n";
  print "\n";
} else {
  print STDERR getppid()." No MX/A record for $domain (claimed sender: $ENV{'SMTPMAILFROM'}) !\n";
  print STDERR getppid()." Mail recipient would have been $ENV{'SMTPRCPTTO'}\n";
  sleep 5;
  print "E451 Sender domain does not exist\n";
}

exit(0);

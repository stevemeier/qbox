#!/usr/bin/perl

use strict;
use warnings;

use Net::DNS;
use Net::Telnet;

my $sender = '';
my $recipient = $ENV{'SMTPMAILFROM'};
my $helohost = &content('/var/qmail/control/helohost');

if ( ($recipient eq '') || (defined($ENV{'RELAYCLIENT'})) ) {
  print "\n";
  exit;
}

$recipient =~ /\@(.*)/;
my $rdomain = $1;
my @mx = mx($rdomain);
my $reply;
my $exit = 0;

if (@mx) {
  foreach my $rr (@mx) {
    my $rserver = $rr->exchange;
    if (&test_server($rserver)) {
      $exit = 0;
    }
  }
} else {
  my $res   = Net::DNS::Resolver->new;
  my $query = $res->search($rdomain);
  if ($query) {
    foreach my $rr ($query->answer) {
      next unless $rr->type eq "A";
      if (&test_server($rr->address)) {
        $exit = 0;
      }
    }
  } else {
    print STDERR getppid()." Could not find MX nor A record for $rdomain\n";
  }
}

if ($exit == 0) {
  print "\n";
} else {
  print STDERR getppid()." Could not verify sender $sender !\n";
  print "E451 Sender verfication failed\n";
}

exit($exit);

sub content() {
  my $input;
  if (-r $_[0]) {
    open(FILE, $_[0]);
      #$input = chomp(*FILE);    <- doesn't work !
      $input = <FILE>;
      if ($input) { chomp($input); }
    close(FILE);
  } else {
    $input = '';
  }
  return $input;
}

sub test_server () {
  my $return = 1;
  my $telnet = Net::Telnet->new(Host => $_[0],
                                Port => 25,
                                Timeout => 10,
                                Errmode => 'return');
  if ($telnet) {
    $reply = '';
    $reply = $telnet->getline;

    $telnet->print("HELO $helohost");
    $reply = $telnet->getline;

    $telnet->print("MAIL FROM: \<$sender\>");
    $reply = $telnet->getline;

    $telnet->print("RCPT TO: \<$recipient\>");
    $reply = $telnet->getline;

    if ($reply =~ /^5/) {
      $return = 0;
    } else {
      $return = 1;
    }

    $telnet->print("QUIT");
    $telnet->close;
  }

  return $return;
}

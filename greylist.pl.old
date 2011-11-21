#!/usr/bin/perl

# This plugin implements greylisting using a SQLite database
# See http://www.sqlite.org for more information on SQLite

use strict;
use warnings;

use DBI;
use DBD::SQLite;
use Time::Local;
use Net::Netmask;

# Seconds until greylisting is deactivated for 'triplet'
my $mindelay = 170;
# Seconds a 'triplet' is valid (no more greylisting)
# Raised from 28800 to 604800 - 20100620 - stevem
my $maxvalid = 604800;
# Default netmask for sender
my $mask = "255.255.255.0";
# Greylisting reply
my $output = "E451 Greylisting active. Your mail will be accepted on the next attempt. This is NOT an error.\n";

# By default, greylisting is active
my $greylist = 1;

# Net::Netmask object
my $block = new Net::Netmask ($ENV{'TCPREMOTEIP'}, $mask);
my $network = $block->base();

# Relayclients will not be greylisted, of course.
if ( (defined($ENV{'RELAYCLIENT'})) || 
     (defined($ENV{'TRUSTCLIENT'})) || 
     (not(-w "/var/qmail/control/greylist/")) ) {
  print "\n";
  exit(0);
}

# hazel hack
if ($ENV{'SMTPRCPTTO'} =~ /hetzl\.com/i) {
  print "\n";
  exit(0);
}

# temp disable
if (-f "/var/qmail/control/greylist/disable") {
  print "\n";
  exit(0);
}

my $i;
my $now = timelocal(localtime);
$ENV{'SMTPMAILFROM'} =~ /\@(.*)$/;
my $sdomain = $1;

my $dbh = DBI->connect("dbi:SQLite:dbname=/var/qmail/control/greylist/sqlite.db","","") 
          || die "Cannot connect: $DBI::errstr";

my $res = $dbh->selectall_arrayref( "SELECT timestamp FROM main WHERE ipaddr = \"$network\" AND mail = \"$sdomain\" AND rcpt = \"$ENV{'SMTPRCPTTO'}\"" );

foreach( @$res ) {
  foreach $i (0..$#$_) {
    # Check if the 'triplet' is older then $mindelay and younger then $maxvalid
    if ( ($_->[$i] >= ($now - $maxvalid)) && ($_->[$i] <= ($now - $mindelay)) ) {
      $greylist = 0;
      $output = "\n";
    }
  }
}

# Record the current 'triplet' to allow next attempt
$dbh->do( "INSERT INTO main VALUES (\"$network\",\"$sdomain\",\"$ENV{'SMTPRCPTTO'}\",\"$now\")" );

# Delete old entries in the DB (older than $maxvalid) and clean out the DB
$dbh->do( "DELETE FROM main WHERE timestamp < $now - $maxvalid" );
$dbh->do( "VACUUM" );

if ($greylist) { 
  print STDERR getppid()." Added to greylist\n"; 
  print $output;
} else {
  print STDERR getppid()." Passed greylist test\n";
  print $output;
}

$dbh->disconnect;
exit;

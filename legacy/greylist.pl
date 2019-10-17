#!/usr/bin/perl

# This plugin implements greylisting using a SQLite database
# See http://www.sqlite.org for more information on SQLite

use strict;
use warnings;

use Carp;
use DBI;
use DBD::SQLite;
use Domain::PublicSuffix;
use Time::Local;
use NetAddr::IP::Lite qw(:lower);

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

# Handle IPv6
my $tcpremoteip;
if ($ENV{'PROTO'} eq 'TCP')  { $tcpremoteip = $ENV{'TCPREMOTEIP'} }
if ($ENV{'PROTO'} eq 'TCP6') { $tcpremoteip = "0.0.0.0" }

# Make sure TCPREMOTEHOST is set
my $tcpremotehost = "";
if (defined($ENV{'TCPREMOTEHOST'})) {
  $tcpremotehost = $ENV{'TCPREMOTEHOST'};
}
if (defined($ENV{'TCP6REMOTEHOST'})) {
  $tcpremotehost = $ENV{'TCP6REMOTEHOST'};
}

# Net::Netmask object
my $ipobj = NetAddr::IP::Lite->new($tcpremoteip, $mask);
my $network = $ipobj->network();
   $network =~ s/\/\d+$//ix;

# Domain::PublicSuffix object
my $suffix = Domain::PublicSuffix->new;
my $rdns;
if (defined($suffix->get_root_domain($tcpremotehost))) {
  $rdns = "".$suffix->get_root_domain($tcpremotehost);
} else {
  $rdns = "";
}

# Relayclients will not be greylisted, of course.
if ( (defined($ENV{'RELAYCLIENT'})) ||
     (defined($ENV{'TRUSTCLIENT'})) ||
     (not(-w "/var/qmail/control/greylist/")) ) {
  print "\n";
  exit(0);
}

# Allow temporary disable
if (-f "/var/qmail/control/greylist/disable") {
  print "\n";
  exit(0);
}

my $i;
my $now = timelocal(localtime);
my $sdomain = "";
if ($ENV{'SMTPMAILFROM'} =~ /\@(.*)$/x) {
  $sdomain = "$1";
}

my $dbh = DBI->connect("dbi:SQLite:dbname=/var/qmail/control/greylist/sqlite.db","","")
          || croak "Cannot connect: $DBI::errstr";

my $res = $dbh->selectall_arrayref( "SELECT timestamp FROM main WHERE ipaddr = \"$network\" AND mail = \"$sdomain\" AND rcpt = \"$ENV{'SMTPRCPTTO'}\"" );

foreach (@$res) {
  foreach my $i (0..$#$_) {
    # Check if the 'triplet' is older then $mindelay and younger then $maxvalid
    if ( ($_->[$i] >= ($now - $maxvalid)) && ($_->[$i] <= ($now - $mindelay)) ) {
      $greylist = 0;
      $output = "\n";
    }
  }
}

# Record the current 'triplet' to allow next attempt
$dbh->do( "INSERT INTO main VALUES (\"$network\",\"$sdomain\",\"$ENV{'SMTPRCPTTO'}\",\"$now\",\"$rdns\")" );

# Delete old entries in the DB (older than $maxvalid) and clean out the DB
if (($$ % 100) == 0) {
  print STDERR getppid()." Vacuuming greylist database\n";
  $dbh->do( "DELETE FROM main WHERE timestamp < $now - $maxvalid" );
  $dbh->do( "VACUUM" );
}

if ($greylist) {
  print STDERR getppid()." Added to greylist\n";
  print $output;
} else {
  print STDERR getppid()." Passed greylist test\n";
  print $output;
}

$dbh->disconnect;
exit;

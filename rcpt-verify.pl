#!/usr/bin/perl

use strict;
use warnings;
use DBI;

my $configdir = "/etc/qbox";

my ($user, $domain);
my ($db, $dbh, $sth, $statement, $success, $sqlrows, @data);

# We don't need to do anything for relaying  and trusted clients
# **************************************************************
if ( (defined($ENV{'RELAYCLIENT'})) ||
     (defined($ENV{'TRUSTCLIENT'})) ) {
  print "\n";
  exit(0);
}

# Connect to database
# *******************
unless (&connect_mysql()) {
  print STDERR "Connection to MySQL failed: $@ !\n";
  print "E451 Recipient verification falied\n";
  &clean_exit(1);
}

($user, $domain) = split(/\@/, $ENV{'SMTPRCPTTO'});
&rewrite_domain();

$statement = "select distinct passwd.homedir,passwd.quota from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\"";
&make_query();

if ($sqlrows >= 1) {
  print STDERR getppid()." Found direct mapping for $ENV{'SMTPRCPTTO'}\n";
  &rcpt_ok();
  &clean_exit(0);
}

$statement = "select distinct passwd.homedir,passwd.quota from passwd inner join mapping on passwd.uid = mapping.uid where user = '*' and domain = \"$domain\"";
&make_query();

if ($sqlrows >= 1) {
  print STDERR getppid()." Found catch-all mapping for $ENV{'SMTPRCPTTO'}\n";
  &rcpt_ok();
  &clean_exit(0);
}

$statement = "select domain from domains where domain = \"$domain\"";
&make_query();
if ($sqlrows >= 1) {
  print STDERR getppid()." User $ENV{'SMTPRCPTTO'} not found in database !\n";
  print "E550 User unknown [$ENV{'SMTPRCPTTO'}]\n";
} else {
  print STDERR "Domain $domain not in table DOMAINS\n";
  print "\n";
}
&clean_exit(0);

sub connect_mysql() {
  $db = "dbi:mysql:qbox; host=".&content("$configdir\/dbserver");
  $dbh = DBI->connect($db, &content("$configdir\/dbuser"), &content("$configdir\/dbpass"));
}

sub disconnect_mysql() {
  $sth->finish;
  $dbh->disconnect;
}

sub make_query() {
  $sqlrows = 0;
  $sth = $dbh->prepare($statement);
  $success = $sth->execute();
  if ($success) {
    $sqlrows = $sth->rows();
  }
}

sub rewrite_domain() {
  $statement = "select rewrite from domains where domain = \"$domain\" and rewrite != ''";
  &make_query();
  if ($sqlrows > 0) {
    @data = $sth->fetchrow_array();
    $domain = $data[0];
  }
}

sub content() {
  if (-r $_[0]) {
    open(FILE, $_[0]);
    my $input = <FILE>;
    chomp($input);
    close(FILE);
    return $input;
  } else {
    return '';
  }
}

sub rcpt_ok() {
  print "\n";
}

sub clean_exit() {
  &disconnect_mysql;
  exit(shift);
}

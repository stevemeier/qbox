#!/usr/bin/perl

use strict;
use warnings;

use DBI;
use Getopt::Long;
use IO::Handle;
use Time::Local;

my $configdir = "/etc/qbox";
my $fetchmail = "/usr/bin/fetchmail";
my $fmflags = "--nokeep --timeout 30 --invisible --silent";
#my $mta = "/var/qmail/bin/sendmail -oem -f %F %T";
my $mta = "/var/qmail/bin/qmail-inject -f%F %T";

my ($db, $dbh, $sth, $statement, $sqlrows);
my (@ids, @data);
my $log;

GetOptions ( 'log=s' => \$log );
if (defined($log)) {
  open(LOGFILE, ">> $log") || die "Could not write to logfile $log: $!\n";
  LOGFILE->autoflush(1);
}

&connect_mysql() || die "Could not connect to MySQL database !\n";

# This is an intentional endless loop
while (1>0) {
  &log("Starting new collection pass...\n");

  # First create a list of accounts that have to be checked
  $statement = "select id from collector where lastcheck + check_every <= ".timelocal(localtime);
  &make_query();
  while ( @data = $sth->fetchrow_array ) {
    push @ids, $data[0];
  }
  &log("Accounts to be checked: ".scalar(@ids)."\n");

  # Fetch login information for accounts
  foreach my $x (@ids) {
    $statement = "select uid,username,password,server,protocol from collector where id = \"$x\"";
    &make_query();
    @data = $sth->fetchrow_array;
      my $uid = $data[0];
      my $username = $data[1];
      my $password = $data[2];
      my $server = $data[3];
      my $protocol = $data[4];

    # Get one local email-address of the user for delivery
    $statement = "select user,domain from mapping where uid = \"$uid\" limit 1";
    &make_query();
    @data = $sth->fetchrow_array;
      my $email = "$data[0]\@$data[1]";
      
      # If we could not find a mapping we report and unset $username so fetchmail doesn't get started
      if (not(defined($email))) {
        &log("ID $x seems to be orphaned (no mapping found) !\n");
	$username = '';
      }
      # We cannot mondify $mda as we need to modify this for every account
      my $mta2 = $mta;
         $mta2 =~ s/\%T/$email/;

    # We put the password into ~/.fetchmailrc as fetchmail doesn't like pipes
    &log("Writing .fetchmailrc in $ENV{'HOME'}\n");
    umask 077;
    open(FMRC, "> $ENV{'HOME'}/.fetchmailrc");
      print FMRC "poll $server\npass \"$password\"\n";
    close(FMRC);

    if ( defined($username) && defined($password) && defined($server) ) {
      # We now start fetchmail if we have all paramters
      &log("Starting: $fetchmail $fmflags -m \"$mta2\" --username $username -p $protocol $server\n");
      system("$fetchmail $fmflags -m \"$mta2\" --username $username -p $protocol $server");
      my $exit = $? >> 8;
      &log("fetchmail exited $exit\n");
      
      # We destroy ~/.fetchmailrc to make sure it doesn't get compromised
      unlink("$ENV{'HOME'}/.fetchmailrc");

      # We set the "last checked" value in MySQL to the current unixtime
      $statement = "update collector set lastcheck = unix_timestamp() where id = $x";
      &make_query();

      if (($exit == 0) || ($exit == 1)) {
        # exit 0 -> all ok, new mail received
	# exit 1 -> all ok, no new mail
        $statement = "update collector set lastsuccess = unix_timestamp() where id = $x";
        &make_query();
      } else {
        # Other exit codes mean failure and are logged to MySQL
        $statement = "update collector set lastfail = unix_timestamp(), lasterror = $exit where id = $x";
        &make_query();
      }
    }
  }
  # To keep the load reasonable we take a little timeout after each round
  &log("Finished collection pass, sleeping.\n");
  # Kill the list of accounts to check
  undef(@ids);
  sleep 60;
}

&disconnect_mysql;
exit;

sub connect_mysql() {
  $db = "dbi:mysql:qbox"; #; host='".&content("$configdir\/dbserver")."'";
  $dbh = DBI->connect($db, &content("$configdir\/dbuser"), &content("$configdir\/dbpass"));
}

sub disconnect_mysql() {
  $sth->finish;
  $dbh->disconnect;
}

sub make_query() {
  $sqlrows = 0;
  $sth = $dbh->prepare($statement);
  my $success = $sth->execute();
  if ($success) {
    $sqlrows = $sth->rows();
  } else {
    die "SQL execution failed: $!\n";
  }  
  
  return $success;
}

sub content() {
  my $input;
  if (-r $_[0]) {
    open(FILE, $_[0]);
      $input = <FILE>;
      if ($input) { chomp($input); }
    close(FILE);
  } else {
    $input = '';
  }
  return $input;
}

sub log() {
  if (defined($log)) {
    print LOGFILE "[".scalar(localtime())."] @_";
  }
}

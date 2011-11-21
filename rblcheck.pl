#!/usr/bin/perl

use strict;
use warnings;
use Mail::RBL;

####
# This is the maximum number of RBLs a client can be listed in
# If this score is reached the client will be denied
# The default value for each RBL is 1

my $maxscore = 2;
####

my $score = 0;
my $rblscore = 0;
my $file;
my ($list, $listed);
my $rbltext = "Sorry, your IP address is blacklisted";
my $configdir = "/var/qmail/control/rbldomains";

# Relay- and Trustclients pass right through
if ( (defined($ENV{'RELAYCLIENT'})) ||
     (defined($ENV{'TRUSTCLIENT'})) ) {
  print "\n";
  exit 0;
}

if ( (-d $configdir) && (-r $configdir) ) {
  opendir(CONFIG, $configdir);
  # Go through the RBL directory
  while ( defined ($file = readdir CONFIG) ) {
    next if $file =~ /^\.\.?$/;     # skip . and ..
    $list = new Mail::RBL($file);
#   if ( ($list->check($ENV{'TCPREMOTEIP'})) && ($score < $maxscore) ) {
    if ($list->check($ENV{'TCPREMOTEIP'})) {
      
      # Get the score of this RBL
      open(RBLFILE, "$configdir/$file");
      $rblscore = <RBLFILE>;
      close(RBLFILE);

      if ($rblscore =~ m/^(\d+)/) {
        $rblscore = $1;
        $score += $rblscore;
      } else {
        $rblscore = 1;
        $score++;
      }
  
      # Client is listed
      print STDERR getppid()." $ENV{'TCPREMOTEIP'} listed in $file (score: $rblscore) !\n";

    }
  }
  closedir(CONFIG);
}

# Send RBL result to client
if ($score >= $maxscore) {
  print STDERR getppid()." Rejecting $ENV{'TCPREMOTEIP'} with score of $score (limit $maxscore)\n";
  # Not so fast, my friend
  sleep 5;
  print "E451 $rbltext\n";
} else {
  print "\n";
}

exit;

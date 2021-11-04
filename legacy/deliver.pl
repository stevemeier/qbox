#!/usr/bin/perl

# This script delivers Mail according to mysql instructions
# It's supposed to be invoked by qmail-local

use strict;
use warnings;

use Carp;
use Digest::SHA qw(sha1_hex);
use File::Find;
use Time::Local;
use Time::gmtime;
use Sys::Hostname;
use DBI;
use DBD::mysql;

# Pathes and external binaries
# Adjust as necessary
# ****************************
my $configdir = "/etc/qbox";
my $spamcbin = "/bin/spamc";
my $vscanbin = "/opt/f-prot/f-prot";
my $tempdir = "/tmp";
my $quarantine = "/var/qmail/quarantine";
# ****************************

my ($db,$dbh);
my $sth;
my $success;
my $sqlrows;
my $statement;
my $error = 111;
my $isduplicate = 0;
my $homedir;
my $quota;
my $diskusage;
my $message;
my ($msgsize, $msghash);
my (@data,@homedirs,%quotas);

# Let's take care of security before writing stuff
# ************************************************
umask(077);

# Check for prerequisites ($RECIPIENT)
# ************************************
if (not($ENV{'RECIPIENT'})) {
  print "\$RECIPIENT not set !\n";
  exit(1);
}

# Connect to MySQL database
# *************************
&connect_mysql() || exit(111);

# Get my own PID
# **************
my $pid = $$;

# Collect information from environment
# ************************************
my $hostname = hostname();
my $sender = $ENV{'SENDER'};
my $email = $ENV{'RECIPIENT'};
$email =~ s/qbox-//x;                   # ausgliedern !
chomp($email);
$ENV{'ORIGINAL_RECIPIENT'} = $email;
my ($user,$domain) = split(/\@/x, $email);
chomp($user);
chomp($domain);

# Check and rewrite recipient domain if necessary
# ***********************************************
&rewrite_domain();

# Get the homedir we will deliver to
# **********************************
&get_homedir();

# Check for generic mappings if no dedicated one found
# ****************************************************
unless (defined($homedirs[0])) {
  $user = '*';
  &get_homedir();
}

# If we still haven't found anything report failure
# **************************************************
if (not(defined($homedirs[0]))) {
  print "ERROR: Couldn't find mapping for $email !\n";
  $error = 100;
  &clean_exit();
}

# Read the message from STDIN
# ***************************
while (<>) {
  $message .= $_;
}
$msgsize = length($message);
$msghash = sha1_hex($message);

# Pipe through SpamAssassin if necessary
# **************************************
$statement = "select distinct passwd.antispam from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\" and antispam > 0";
&make_query();
if ($sqlrows > 0) {
  &debug("Starting SpamAssassin...\n");
  &spam_assassin();
}

# Virus check message if necessary
# ********************************
$statement = "select distinct passwd.antispam from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\" and antivir > 0";
&make_query();
if ($sqlrows > 0) {
  &debug("Starting VirusScanner...\n");
  &virus_scan();
  if ($? != 0) {
    undef @homedirs;
    $homedirs[0] = $quarantine;
  }
}

# Figure out delivery
# *******************
&debug("homedirs: @homedirs\n");

foreach my $homedir (@homedirs) {

  if (defined($quotas{$homedir})) {
    $quota = $quotas{$homedir};
  } else {
    $quota = 0;
  }

  if ($homedir =~ /\@/x) {
    &forward($homedir);
  }
  if ($homedir =~ /^\|/x) {
    &write_pipe($homedir);
  }
  if ($homedir =~ /^\//x) {
    if ($quota > 0) {
      &check_quota($homedir);
        if ($error != 1) {
          &maildir($homedir);
        }
     } else {
      &maildir($homedir);
     }
  }
}

# start autoresponder
# *******************
if ($error == 0) {
  &debug("Starting Autoresponder...\n");
  &autorespond();
}

# Murphys law: something went wrong...
# ************************************
sub clean_exit {
  $sth->finish;
  $dbh->disconnect;
  if ($error != 0) { print "Exiting with code $error\n"; };
  exit($error);
}

# *********************
# MODULES START HERE...
# *********************

sub maildir {
  my ($lhomedir) = @_;
  my $subdir = "INBOX";
  my $timestamp = timelocal(localtime);
  my $filename = "$timestamp\.$pid\.$hostname\.$msghash";
  my $spamdir = '';
  my $spamlimit = 10;

  # Filter duplicates
  $statement = "select distinct passwd.antispam from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\" and dupfilter > 0";
  &make_query();
  if ($sqlrows > 0) {
    &debug("Searching for duplicates with hash $msghash\n");
    find(\&duplicate, $lhomedir);
    if ($isduplicate == 1) {
      # we have found a duplicate
      print "Message discarded due to duplicate filter\n";
      $error = 0;
      return;
    }
  }

  $statement = "select distinct passwd.spamdir, passwd.spamlimit from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\" and spamdir != ''";
  &make_query();
  if ($sqlrows > 0) {
    ($spamdir, $spamlimit) = $sth->fetchrow_array();
  }
  if ( ($message =~ /\nX-Spam-Level:\s+\+{$spamlimit,}/x) && ($spamdir) ) {
    $subdir = $spamdir;
  }

  local $SIG{ALRM} = sub { croak "timeout" };

  eval {
    alarm(86400);
    if (not(-d $lhomedir)) {
      &create_homedir();
    }
    chdir("$lhomedir") || &defer("ERROR: Unable to chdir to $lhomedir\n");
    chdir("$subdir") || &defer("ERROR: Unable to chdir to $lhomedir/$subdir !\n");
    open(my $OUTPUTFH, ">", "tmp/$filename") || &defer("ERROR: Unable to create file in $lhomedir/tmp !\n");
  
    print $OUTPUTFH $message;

    close($OUTPUTFH) || &defer("ERROR: Unable to close tmp file !\n");
    link("tmp/$filename","new/$filename") || &defer("ERROR: Unable to link() !\n");
    unlink("tmp/$filename") || &defer("ERROR: Unable to unlink() !\n");
    print "Message delivered to $lhomedir\/$subdir for $email\n";
    $error = 0;
    alarm(0);
    if ($quota > 0) {
      &update_quota($lhomedir);
    }
  };

  if ($@) {
    if ($@ =~ /timeout/) {
      print "ERROR: Timeout !";
    }
    else {
      alarm(0);
#     die;
    }
  }

  return;
}

sub forward {
  my ($lhomedir) = @_;

  open(my $INJECTFH, "|-", "/var/qmail/bin/qmail-inject -f$sender $lhomedir") || croak "Could not invoke qmail-inject";
    print $INJECTFH $message;
  close($INJECTFH);

  if ($? == 0) {
    print "Message forwarded to $lhomedir\n";
    $error = 0;
  } else {
    print "ERROR: Forwarding to $lhomedir failed !\n";
    $error = 111;
  }

  return;
}  

sub write_pipe {
  my ($lhomedir) = @_;
  $lhomedir =~ s/\|//x;

  if (-x $lhomedir) {
    my $lpid = open(my $PIPEFH, "|-", "$lhomedir") || warn "ERROR: Could not fork $lhomedir => $!\n";
    if ($lpid) {
      print $PIPEFH $message;
      close($PIPEFH);  
    }
  
    if ($? == 0) {
      print "Message piped to $lhomedir\n";
      $error = 0;
    } else {
      print "ERROR: Piping to $lhomedir failed !\n";
      $error = 111;
    }
  } else {
    print "ERROR: $lhomedir not found or not executable !\n";
    $error = 111;
  }

  return;
}

sub get_homedir {
  $statement = "select distinct passwd.homedir,passwd.quota from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\"";
  &make_query();

  while (@data = $sth->fetchrow_array()) {
    &debug("adding $data[0] to delivery list\n");
    push(@homedirs, $data[0]);
    %quotas = ($data[0] => $data[1]);
  }

  return;
}

sub make_query {
  $sqlrows = 0;
  $sth = $dbh->prepare($statement);
  $success = $sth->execute();
  if ($success) {
    $sqlrows = $sth->rows();
  } else {
    $error = 111;
    &clean_exit();
  }
  
  return $success;
}

sub check_quota {
  my ($lhomedir) = @_;

  if (not( -f "$lhomedir/.mailquota" )) {
    open(my $MAILQUOTAFH, ">", "$lhomedir/.mailquota") || croak "Could not write to $lhomedir/.mailquota";
      print $MAILQUOTAFH "0";
    close($MAILQUOTAFH);
  }

  open(my $MAILQUOTAFH, ">", "$lhomedir/.mailquota") || croak "Could not write to $lhomedir/.mailquota";
    $diskusage = <$MAILQUOTAFH>;
  close($MAILQUOTAFH);

  if ($diskusage > $quota) {
    print "ERROR: Mailbox full ! Maximum Quota ($quota KB) exeeded.\n";
    $error = 1;
  }

  return;
}

sub update_quota {
  my ($lhomedir) = @_;
  my $homesize = 0;

  find(sub { $homesize += -s if -f $_ }, " $lhomedir");

  open(my $MAILQUOTAFH, ">", "$lhomedir/.mailquota") || croak "Could not write to $lhomedir/.mailquota";
    print $MAILQUOTAFH $homesize + $msgsize;
  close($MAILQUOTAFH);

  return;
}

sub defer {
  my ($lmessage) = @_;
  print $lmessage;
  exit(111);
}

sub create_homedir {
  mkdir("$homedir");
  mkdir("$homedir/INBOX");
  mkdir("$homedir/INBOX/tmp");
  mkdir("$homedir/INBOX/new");
  mkdir("$homedir/INBOX/cur");

  return;
}

sub autorespond {
  $statement = "select distinct passwd.artext,passwd.uid from passwd inner join mapping on passwd.uid = mapping.uid where user = \"$user\" and domain = \"$domain\" and arstart > 0 and arend >= UNIX_TIMESTAMP()";
  &make_query();

  # This handles RFC2919
  if ($message =~ /\nList-ID:/ix) {
    $sqlrows = 0;
  }

  if (not($message =~ /\nX-Mailer:/ix)) {
    $sqlrows = 0;
  }

  if ($sqlrows > 0) {
    #@data = $sth->fetchrow_array();
    my ($artext, $aruid) = $sth->fetchrow_array();
    $statement = "select * from responses where uid = \"$aruid\" and rcpt = \"$sender\" and time > (UNIX_TIMESTAMP() - 604800)";
    &make_query();

    my $subject;
    if ($message =~ /\nSubject: (.*)\n/x) {
      # RFC3834 recommends this
      $subject = "Subject: Auto: $1\n";
    } else {
      $subject = "Subject: Autoresponder reply\n";
    }

    if ( ($email && $sender) && ($sqlrows == 0) ) {
      open(my $INJECTFH, "|-", "/var/qmail/bin/qmail-inject -f$email $sender") || croak "Could not call qmail-inject";
        print $INJECTFH "From: \<$email\>\n";
        print $INJECTFH "To: \<$sender\>\n";
        print $INJECTFH $subject;
        print $INJECTFH "Message-ID: \<".timelocal(localtime)."\.$pid\@$hostname\>\n";
        print $INJECTFH "Date: ".&rfc2822_date()."\n\n";
        print $INJECTFH $artext;
      close($INJECTFH);

      $statement = "insert into responses values ('','$aruid','$sender',UNIX_TIMESTAMP())";
      &make_query();
    }
  }

  return;
}

sub spam_assassin {
  if (-x $spamcbin) {
    my $timestamp = timelocal(localtime);
    my $tempfile = "$tempdir\/$timestamp\.$pid\.$hostname";
  
    open(my $SPAMCFH, "|-", "$spamcbin > $tempfile") || warn "ERROR forking $spamcbin !\n";
      print $SPAMCFH $message;
    close($SPAMCFH);

    if ((-s $tempfile) > $msgsize) {
      $message = '';
      open(my $SARESULTFH, "<", $tempfile) || carp "Could not read result file";
      while(<$SARESULTFH>) {
        $message .= $_;
      }
      close($SARESULTFH);
      $msgsize = length($message);
    }
    unlink($tempfile);
  }

  return;
}

sub virus_scan {
  if (-x $vscanbin) {
    my $timestamp = timelocal(localtime);
    my $tempfile = "$tempdir\/$timestamp\.$pid\.$hostname";

    open(my $TEMPFH, ">", $tempfile) || warn "ERROR writing $tempfile !\n";
      print $TEMPFH $message;
    close($TEMPFH);

    system("$vscanbin $tempfile 2>&1 >/dev/null"); # || warn "ERROR forking $vscanbin !\n";
  }

  return;
}

sub rfc2822_date {
  # credits to Chip Rosenthal <chip@unicom.com>
  # taken from pxytest

  my $gm = gmtime(shift || time());
  my @Day_name = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
  my @Month_name = (
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");

  return sprintf("%-3s, %02d %-3s %4d %02d:%02d:%02d GMT",
  $Day_name[$gm->wday],
  $gm->mday, $Month_name[$gm->mon], 1900+$gm->year,
  $gm->hour, $gm->min, $gm->sec);
}

sub content {
  my ($file) = @_;
  my $input;
  if (-r $file) {
    open(my $FILEFH, "<", $file) || croak "Could not read from $file";
      $input = <$FILEFH>;
      if ($input) { chomp($input); }
    close($FILEFH);
  } else {
    $input = '';
  }
  return $input;
}

sub connect_mysql {
  $db = "dbi:mysql:qbox"; #; host='".&content("$configdir\/dbserver")."'";
  $dbh = DBI->connect($db, &content("$configdir\/dbuser"), &content("$configdir\/dbpass"));

  if ($dbh) {
    return 1;
  }
  return 0;
}

sub rewrite_domain {
  $statement = "select rewrite from domains where domain = \"$domain\" and rewrite != ''";
  &make_query();
  if ($sqlrows > 0) {
    @data = $sth->fetchrow_array();
    $domain = $data[0];
  }

  return;
}

sub debug {
  my ($lmessage) = @_;
  if ($ENV{'QBOX_DEBUG'}) { print STDERR $lmessage };

  return;
}

sub duplicate {
  if ($File::Find::name =~ /\.$msghash/x) {
    &debug("$File::Find::name is a duplocate with hash value $msghash\n");
    $isduplicate = 1;
  }

  return;
}

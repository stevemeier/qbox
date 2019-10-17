#!/usr/bin/perl -T

use strict;
use warnings;

use DBI;
use User::pwent;
use Crypt::PasswdMD5;
use MIME::Base64;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::HMAC_MD5 qw(hmac_md5 hmac_md5_hex);
# Only for OATH
use Authen::OATH;
use Time::Local;

$|=1;
$ENV{PATH} = '';

my $configdir = "/etc/qbox";

my $args = join (' ', @ARGV);
   $args =~ /^([\w\s\/\.-]+)$/;
   $args = $1;
my $ipaddr = $ENV{'TCPREMOTEIP'};
my $port = $ENV{'TCPLOCALPORT'};
my ($dbpassword, $salt, $cryptpw, $md5pw) = ('','','','');
my $dummy;
my ($homedir, $uid, $gid, $shell, $quota, $qboxuid, $qboxgid, $oathtoken);
my $sqlrows;
my ($db,$sth,$dbh,$statement,$success,$handle,$logok);
my ($sender,$user,$domain,$error,$diskusage,$msgsize);

if (not($ENV{'TCPLOCALPORT'})) {
  $port = "110";
}
if ($port eq "25" ) { $port = "smtp"; } 
if ($port eq "110") { $port = "pop";  }
if ($port eq "143") { $port = "imap"; }
if ($port eq "465") { $port = "smtp"; }
if ($port eq "993") { $port = "imap"; }
if ($port eq "995") { $port = "pop";  }

# this program does authentication against the
# qbox.passwd table. It's supposed to be run
# thorugh tcpserver

&connect_mysql() || warn "Could not connect to database: $!\n";

# Open and lock logfile if defined
if (defined($ENV{'QBOX_LOGFILE'})) {
  if (open(LOGFILE, ">> $ENV{'LOGFILE'}")) {
    flock(LOGFILE,2);
    $logok = 1;
  } else {
    print STDERR "Could not write to $ENV{'QBOX_LOGFILE'}: $!\n";
  }
}
  
# Collect login data
# ******************
my($len,$buf);
open (USER, "<&=3") or exit (-3);
$len = read(USER, $buf, 512);
close(USER);
exit(-3) if $len < 4;

# Put login data into variables
# *****************************
my($username, $password, $timestamp) = split /\x00/, $buf;
$username = lc($username);
chomp($timestamp);
&debug("$username\n$password\n$timestamp\n");
$buf = "\x00" x $len;

# Do not allow root logins
# ************************
if ($username eq 'root') {
  exit(1);
}
  
# Get the authenticating users data from MySQL
# ********************************************
&get_mysqldata();
if ($sqlrows == 0) {
  # Read /etc/passwd if SQL result is empty
  &get_unixdata();
}

# Abort if no password or homedir is defined
# ******************************************
if ( (not(defined($dbpassword))) or (not(defined($homedir))) ) {
  exit(1);
}

# Handle crypted passwords
# ************************
if ((length($dbpassword)) == 13) {
  $dbpassword =~ /^(.{2})/;
  $salt = $1;
  $cryptpw = crypt($password, $salt);
}

# Handle MD5 passwords
# ********************
if ((length($dbpassword)) == 34) {
  $dbpassword =~ /^\$1\$(.{8})\$/;
  $salt = $1;
  $md5pw = unix_md5_crypt($password, $salt);
}

# Handle CRAM-MD5 authentication (SMTP AUTH)
# ******************************************
if (($password =~ /^[0-9a-f]+$/) && ($port eq 'smtp')) {
  &debug("SMTP AUTH detected\n");
  $dbpassword = hmac_md5_hex($timestamp, $dbpassword);
}

# Handle APOP authentication (POP3)
# *********************************
if ((length($password) == 32) && ($port eq 'pop')) {
  &debug("APOP detected\nEncoding: $timestamp$dbpassword\n");
  $dbpassword = md5_hex($timestamp,$dbpassword);
}

# Handle OATH authentication
# **************************
my $oathdrift = 180;
my $oathok = 0;
my $epoch = timelocal(localtime);
my $oath = Authen::OATH->new();

if (defined($oathtoken)) {
  foreach my $x (($epoch - $oathdrift) .. ($epoch + $oathdrift)) {
    if (($x % 30) == 0) {
      if ( ($oath->totp($oathtoken, $x)) eq $password ) {
        &debug("OATH Token successful.");
        $oathok = 1;
      }
    }
  }
}

# Compare the supplied password to the stored data
# ************************************************
&debug("$dbpassword\n");

if ( ($password eq $dbpassword) || ($cryptpw eq $dbpassword) || ($md5pw eq $dbpassword) || ($oathok == 1) ) {
  $ENV{HOME} = $homedir;
  $ENV{USER} = $username;
  $ENV{UID} = $uid+0;
  $ENV{QBOXUID} = $qboxuid;
  $ENV{QBOXGID} = $qboxgid;
  chdir $ENV{HOME};

  $) = "$gid $gid";
  $( = $gid;
  $> = $ENV{UID};
  $< = $ENV{UID};
  if ($args) {
    &disconnect_mysql;
    exec $args;
  }

  #if ($quota > 0) {			<= THIS NEEDS TO BE DONE DIFFERENTLY
  #  &update_quota();
  #}

  exit(0);
}
# Abort on failed authentication
# ******************************
else {
  sleep(3);
  &disconnect_mysql;
  exit(-1);
}



# Subs related to database operations
# ***********************************
sub connect_mysql() {
  $db = "dbi:mysql:qbox; host=".&content("$configdir\/dbserver");
  $dbh = DBI->connect($db, &content("$configdir\/dbuser"), &content("$configdir\/dbpass"));
}

sub disconnect_mysql() {
  $sth->finish;
  $dbh->disconnect;
}

sub make_query() {
  $sth = $dbh->prepare($statement);
  $success = $sth->execute();
  $sqlrows = $sth->rows();
}
# ***********************************

# Subs related to fetching user data
# **********************************
sub get_mysqldata() {
  $statement = "select password,homedir,sysuid,sysgid,quota,uid,gid,oath_token from passwd where username = \"$username\" and $port != '' limit 1";
  &make_query();
  ($dbpassword,$homedir,$uid,$gid,$quota,$qboxuid,$qboxgid,$oathtoken) = $sth->fetchrow_array();
}

sub get_unixdata() {
  while($dummy = getpwent()) {
    if (($dummy->name) eq $username) {
      $homedir = $dummy->dir;
      $uid = $dummy->uid;
      $gid = $dummy->gid;
      $shell = $dummy->shell;
      $dbpassword = $dummy->passwd;
      $quota = 0;
    }
  }
}
# **********************************

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

sub debug() {
  if ($ENV{'QBOX_DEBUG'}) {
    if ($logok) {
      print LOGFILE @_;
    } else {
      print STDERR @_;
    }
  }
}

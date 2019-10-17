#!/usr/bin/perl -T

use strict;
use warnings;

use Carp;
use DBI;
use DBD::mysql;
use User::pwent;
use Crypt::PasswdMD5;
use Dancer ':script';
use English qw(-no_match_vars);
use Getopt::Long;
use MIME::Base64;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::HMAC_MD5 qw(hmac_md5 hmac_md5_hex);
# Logging
use File::Basename qw(basename);
#use Sys::Syslog;
use POSIX qw/strftime setuid setgid/;
# Only for OATH
use Authen::OATH;
use Time::Local;
use JSON ();

my ($port, $maxfail, $runas, $failscript);
my $cachetime = 3600;
GetOptions("port=i"       => \$port,
           "maxfail=i"    => \$maxfail,
           "user=s"       => \$runas,
	   "failscript=s" => \$failscript,
           "cachetime=s"  => \$cachetime);

# Disable output buffering
*STDOUT->autoflush();
*STDERR->autoflush();

local $ENV{PATH} = '';

my $configdir = "/etc/qbox";

my ($dbpassword, $salt, $cryptpw, $md5pw) = ('','','','');
my $dummy;
my ($homedir, $uid, $gid, $shell, $quota, $qboxuid, $qboxgid, $oathtoken);
my $sqlrows;
my ($db,$sth,$dbh,$statement,$success);
my %authfail;
my $epoch;
my $runasuser;

#  Drop privileges
if (defined($runas)) {
  $runasuser = getpwnam($runas);
  if (not(($runasuser->uid =~ /\d+/x) && ($runasuser->gid =~ /\d+/x))) {
    die("Could not determine UID/GID for $runas\n");
  }
  POSIX::setgid($runasuser->gid);
  POSIX::setuid($runasuser->uid);
  info "Droped privileges to $runas (gid $GID egid $EGID uid $UID euid $EUID)\n";
} else {
  warn "Still running with full privileges\n";
}

# Auth cache
my %authcache;

&connect_mysql() || die "Could not connect to database: $!\n";

# We are working with JSON
set serializer => 'JSON';

# Logger
set logger => 'console';

# TCP Port
if (not(defined($port))) { $port = 7520 }
set port => $port =~ /(\d+)/ix;
  
# Collect login data
# ******************
get '/:service/:username/:password/:timestamp/:source' => sub { &authenticate };
post '/' => sub { &authenticate };
get '/admin/authcache' => sub { &dump_authcache };

dance;
exit;

sub authenticate {

  my $service = param('service');
  my $username = param('username');
  my $password = param('password');
  my $ipaddr = param('source');
  my $timestamp = param('timestamp');

  # Check auth cache
  if (defined($authcache{$username}{$password})) {
    if ($authcache{$username}{$password}{'epoch'} > (time - $cachetime)) {
      print STDERR "Authentication succeeded for $username on $service from $ipaddr [cached]\n";
      return { %{$authcache{$username}{$password}{'data'}} };
    } else {
      print STDERR "Authcache entry for $username is too old (".$authcache{$username}{$password}{'epoch'}." vs ".time.")\n";
    }
  }

  # Is this service/protocol supported
  ####################################
  my @services = ('pop', 'smtp', 'imap');
  if (not(grep { /$service/ } @services)) {
    status 400;
    return;
  }

  # Do not allow root logins
  # ************************
  if ($username eq 'root') {
    print STDERR "User root denied on $service from $ipaddr\n";
    status 403;
    return;
  }

  # Check that MySQL is still there
  #################################
  if (not($dbh->ping)) {
    # connect again
    print STDERR "Database has gone away. Reconnecting\n";
    &connect_mysql;
  }
  
  # Get the authenticating users data from MySQL
  # ********************************************
  &get_mysqldata();
  if ($sqlrows == 0) {
    # Read /etc/passwd if SQL result is empty
    &get_unixdata($username);
  }

  # Abort if no password or homedir is defined
  # ******************************************
  if ( (not(defined($dbpassword))) or (not(defined($homedir))) ) {
    print STDERR "User unknown for $username on $service from $ipaddr [password: $password]\n";
    $epoch = time;
    $authfail{$ipaddr}{$epoch} = &timestamp." - User unknown for $username on $service from $ipaddr [password: $password]\n";
    &lockout($ipaddr);
    status 403;
    return;
  }

  # Handle crypted passwords
  # ************************
  if ((length($dbpassword)) == 13) {
    if ($dbpassword =~ /^(.{2})/x) { $salt = $1 }
    $cryptpw = crypt($password, $salt);
  }

  # Handle MD5 passwords
  # ********************
  if ((length($dbpassword)) == 34) {
    if ($dbpassword =~ /^\$1\$(.{8})\$/x) { $salt = $1 }
    $md5pw = unix_md5_crypt($password, $salt);
  }

  # Handle CRAM-MD5 authentication (SMTP AUTH)
  # ******************************************
  if (($password =~ /^[0-9a-f]+$/x) && ($service eq 'smtp')) {
#   debug("SMTP AUTH detected\n");
    $dbpassword = hmac_md5_hex($timestamp, $dbpassword);
  }

  # Handle APOP authentication (POP3)
  # *********************************
  if ((length($password) == 32) && ($service eq 'pop')) {
#   debug("APOP detected\nEncoding: $timestamp$dbpassword\n");
    $dbpassword = md5_hex($timestamp,$dbpassword);
  }

  # Handle OATH authentication
  # **************************
  my $oathdrift = 180;
  my $oathok = 0;
     $epoch = timelocal(localtime);
  my $oath = Authen::OATH->new();

  if (defined($oathtoken)) {
    foreach my $x (($epoch - $oathdrift) .. ($epoch + $oathdrift)) {
      if (($x % 30) == 0) {
        if ( ($oath->totp($oathtoken, $x)) eq $password ) {
#         debug("OATH Token successful.");
          $oathok = 1;
        }
      }
    }
  }

  # Compare the supplied password to the stored data
  # ************************************************
  if ( ($password eq $dbpassword) || ($cryptpw eq $dbpassword) || ($md5pw eq $dbpassword) || ($oathok == 1) ) {
    print STDERR "Authentication succeeded for $username on $service from $ipaddr\n";
    &update_lastlogin($qboxuid, $username, $service);
    status 200;
    undef($authfail{$ipaddr});
    $authcache{$username}{$password}{'epoch'} = time;
    $authcache{$username}{$password}{'data'}  = { home => $homedir, user => $username, uid => $uid+0, gid => $gid+0, qboxuid => $qboxuid+0, qboxgid => $qboxgid+0 };
    return { home => $homedir, user => $username, uid => $uid+0, gid => $gid+0, qboxuid => $qboxuid+0, qboxgid => $qboxgid+0 };
  }

  # Abort on failed authentication
  # ******************************
  else {
    print STDERR "Authentication failed for $username on $service from $ipaddr [password: $password]\n";
    $epoch = time;
    $authfail{$ipaddr}{$epoch} = &timestamp." - Authentication failed for $username on $service from $ipaddr [password: $password]\n";
    &lockout($ipaddr);
    status 403;
    return;
  }
}


# Subs related to database operations
# ***********************************
sub connect_mysql {
  $db = "dbi:mysql:qbox; host=".&content("$configdir\/dbserver");
  $dbh = DBI->connect($db, &content("$configdir\/dbuser"), &content("$configdir\/dbpass"));

  if ($dbh) {
    return 1;
  }
  return 0;
}

sub disconnect_mysql {
  $sth->finish;
  $dbh->disconnect;
  return;
}

sub make_query {
  $sth = $dbh->prepare($statement);
  $success = $sth->execute();
  $sqlrows = $sth->rows();
  return;
}
# ***********************************

# Subs related to fetching user data
# **********************************
sub get_mysqldata {
  $statement = "select password,homedir,sysuid,sysgid,quota,uid,gid,oath_token from passwd where username = \"".param('username')."\" and ".param('service')." != '' limit 1";
  &make_query();
  ($dbpassword,$homedir,$uid,$gid,$quota,$qboxuid,$qboxgid,$oathtoken) = $sth->fetchrow_array();
  return;
}

sub get_unixdata {
  my $username = shift;
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
  return;
}
# **********************************

sub content {
  my ($file) = @_;
  if (-r $file) {
    open(my $FILEFH, "<", $file) || croak "Could not read $file";
    my $input = <$FILEFH>;
    chomp($input);
    close($FILEFH);
    return $input;
  } else {
    return '';
  }
}

sub lockout {
  my ($ip) = @_;

  # Untaint IP
  if ($ip =~ /(\d+\.\d+\.\d+\.\d+)/ix) {
    $ip = $1;
  } else {
    return 0;
  }
  
  if (defined($maxfail)) {
    if (keys($authfail{$ip}) >= $maxfail) {
      if ($failscript =~ m/(\/.*)/ix) { $failscript = $1; }
      print STDERR "Calling $failscript for $ip\n";
      open(my $FSCRIPT, "|-", "$failscript $ip") || croak "Could not invoke $failscript\n";
        foreach (sort(keys(%{$authfail{$ip}}))) {
           print $FSCRIPT $authfail{$ip}{$_};
        }
      close($FSCRIPT);
      undef($authfail{$ip});
    }
  }
  return 1;
}

sub timestamp {
  return strftime('%b %d %H:%M:%S', gmtime);
}

sub update_lastlogin {
  my ($lluid, $llusername, $lservice) = @_;
  $statement = 'INSERT INTO lastlogin VALUES ("'.$lluid.'","'.$llusername.'",UNIX_TIMESTAMP(NOW()),TIMESTAMP(NOW()),"'.$lservice.'") ON DUPLICATE KEY UPDATE epoch=UNIX_TIMESTAMP(NOW()), timestamp=TIMESTAMP(NOW()), protocol="'.$lservice.'"';
  &make_query();

  return;
}

sub dump_authcache {
  status 200;
  return { %authcache };
}

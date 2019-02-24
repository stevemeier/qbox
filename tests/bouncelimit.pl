#!/usr/bin/perl

use strict;
use warnings;
use Capture::Tiny ':all';
use Data::Dumper;
use Test::Simple tests => 9;

my ($stdout, $stderr, $exit);

$ENV{'SMTPMAILFROM'} = 'johndoe@example.com';
$ENV{'SMTPRCPTCOUNT'} = "10";
($stdout, $stderr, $exit) = capture { system ('./bouncelimit', '') };

ok($stdout eq "\n", "STDOUT for valid sender and 10 recipients");
ok($stderr eq '', "STDERR for valid sender and 10 recipients");  
ok($exit eq 0, "Exit code for valid sender and 10 recipients");

$ENV{'SMTPMAILFROM'} = '';
$ENV{'SMTPRCPTCOUNT'} = "0";
($stdout, $stderr, $exit) = capture { system ('./bouncelimit', '') };

ok($stdout eq "\n", "STDOUT for bounce to one recipient");
ok($stderr eq '', "STDERR for bounce to one recipient");
ok($exit eq 0, "Exit code for bounce to one recipient");

$ENV{'SMTPMAILFROM'} = '';
$ENV{'SMTPRCPTCOUNT'} = "1";
($stdout, $stderr, $exit) = capture { system ('./bouncelimit', '') };

ok($stdout =~ /^E550/, "STDOUT for bounce to multiple recipients");
ok($stderr =~ /Empty/, "STDERR for bounce to multiple recipients");  
ok($exit eq 0, "Exit code for bounce to multiple recipients");

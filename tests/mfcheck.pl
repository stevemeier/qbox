#!/usr/bin/perl

use strict;
use warnings;
use Capture::Tiny ':all';
use Data::Dumper;
use Test::Simple tests => 9;

my ($stdout, $stderr, $exit);

$ENV{'SMTPMAILFROM'} = 'johndoe@example.com';
($stdout, $stderr, $exit) = capture { system ('./mfcheck', '') };

ok($stdout eq "\n", "STDOUT for valid email");
ok($stderr =~ /passed/, "STDERR for valid email");  
ok($exit eq 0, "Exit code for valid email");

$ENV{'SMTPMAILFROM'} = 'foobar@geiles-portal.de';
($stdout, $stderr, $exit) = capture { system ('./mfcheck', '') };

ok($stdout =~ /^E451/, "STDOUT for invalid email");
ok($stderr =~ /claimed sender/, "STDERR for invalid email");
ok($exit eq 0, "Exit code for invalid email");

$ENV{'SMTPMAILFROM'} = '';
($stdout, $stderr, $exit) = capture { system ('./mfcheck', '') };

ok($stdout eq "\n", "STDOUT for empty email");
ok($stderr eq '', "STDERR for empty email");  
ok($exit eq 0, "Exit code for empty email");

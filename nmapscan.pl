#!/usr/bin/perl
use strict;
use Getopt::Long;
#
# Input parameters
my $help;
my $ipaddresses;
GetOptions(
     "help!"=>\$help,
     "ipaddresses!"=>\$ipaddresses
) or exit(1);
#
# Get networks if non were specified
if (!$ipaddresses) {
     my @data=`ip add | grep inet | grep -v 127.0.0.1`;
     my @subnets;
     foreach my $subnet (@data) {
           push(@subnets,$1) if ($subnet =~ /inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3})\s/);
     }
     $ipaddresses=join(",",@subnets);
     print $ipaddresses."\n";
}
# 
# Scan subnets
my @subnets=split(/,/,$ipaddresses);
my %ip;
foreach my $subnet (@subnets) {
     my @data=`nmap -O -n $subnet`;
     my $info="";
     my $ipaddress="";
     foreach my $line (@data) {
          chomp($line);
	  if (($ipaddress !~ /^\s*$/) && ($line =~ /^\s*$/)) {
               $ip{$ipaddress}{'info'}=$info;
               print "ipaddress=$ipaddress\n$info";
	       $info="";
               next;
          } elsif ($line =~ /Nmap\sscan\sreport\sfor\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s/) {
               $ipaddress=$1;
          }
          $info.="$line\n";
     }
}

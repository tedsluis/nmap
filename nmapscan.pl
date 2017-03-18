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
     my $hostname="";
     my $macaddress="";
     my $vendor="";
     my $status="";
     my $latency="";
     my $hops="";
     my $devicetype="";
     my $running="";
     foreach my $line (@data) {
          chomp($line);
	  if ($line =~ /^\s*$/) {
               $ip{$ipaddress}{'info'}=$info;
               print "----------------------\nIP ADDRESS=$ipaddress\nHOSTNAME=$hostname\nMAC ADDRESS=$macaddress\nVENDOR=$vendor\nHOPS=$hops\nSTATUS=$status\nLATENCY=$latency\nDEVICE TYPE=$devicetype\nRUNNING=$running\n$info\n------------------------\n";
	       $info="";
	       $ipaddress="unknown";
	       $hostname="unknown";
	       $macaddress="unknown";
	       $vendor="unknown";
               $status="unknown";
               $latency="unknown";
               $hops="unknown";
               $devicetype="unknown";
               $running="unknown";
               next;
          } elsif ($line =~ /Nmap\sscan\sreport\sfor\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*/) {
               $ipaddress=$1;
               my @hostname=`nslookup $ipaddress`;
               foreach my $line (@hostname) {
                    chomp($line);
                    $hostname=$1 if ($line =~ /in-addr\.arpa\s+name\s=\s(.+)\.$/);               
               }
               my @route=`traceroute $ipaddress`;
               foreach my $line (@route) {
                    chomp($line);
#[root@pavilion nmap]# traceroute 192.168.1.254
#traceroute to 192.168.1.254 (192.168.1.254), 30 hops max, 60 byte packets
# 1  rb750 (192.168.11.1)  8.179 ms  8.803 ms  13.160 ms
# 2  192.168.1.254 (192.168.1.254)  20.443 ms  17.846 ms  20.429 ms
#[root@pavilion nmap]# traceroute 192.168.11.177
#traceroute to 192.168.11.177 (192.168.11.177), 30 hops max, 60 byte packets
# 1  ted1090-7 (192.168.11.177)  2.726 ms  4.043 ms  9.338 ms
               }
               next;
	       # MAC Address: C0:EE:FB:E2:96:AA (OnePlus Tech (Shenzhen))
          } elsif ($line =~ /MAC\sAddress:\s([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})\s+\((.+)\)$/i) {
               $macaddress=$1;
               $vendor=$2;
               next;
          } elsif ($line =~ /Host\sis\sup\s\((\d+\.\d+s\slatency)\)/) {
               $status="UP";
               $latency=$1;
               next;
          } elsif ($line =~ /Network\sDistance:\s(\d+)\shop/) {
               $hops=$1;
               next;
          } elsif ($line =~ /Device type:\s(.+)$/) {
               $devicetype=$1;
               next;
          } elsif ($line =~ /Running:\s(.+)$/) {
               $running=$1;
               next;
          }
          $info.="$line\n";
     }
}

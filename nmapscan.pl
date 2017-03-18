#!/usr/bin/perl
use strict;
use Getopt::Long;
#
# Input parameters
my $help;
my $ipaddresses;
GetOptions(
     "help!"=>\$help,
     "ipaddresses=s"=>\$ipaddresses
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
}
print $ipaddresses."\n";
# 
# Scan subnets
my @node;
my @link;
my $num=0;
my @subnets=split(/,/,$ipaddresses);
foreach my $subnet (@subnets) {
     my @data=`nmap -O -n $subnet`;
     my $info="";
     my $ipaddress="unknown";
     my $hostname="unknown";
     my $macaddress="unknown";
     my $vendor="unknown";
     my $status="unknown";
     my $latency="unknown";
     my $hops="unknown";
     my $devicetype="unknown";
     my $running="unknown";
     my $notshown="unknown";
     my $os_cpe="unknown";
     my $os_details="unknown";
     my $warning="unknown";
     my $aggressive_os_guesses="unknown";
     foreach my $line (@data) {
          chomp($line);
	  if (($ipaddress =~ /^unknown$/) && ($line =~ /^\s*$/)) {
               next;
	  } elsif ($line =~ /^\s*$/) {
               my @text;
               $num++;
               print "----------------------\nIP ADDRESS=$ipaddress\nHOSTNAME=$hostname\nMAC ADDRESS=$macaddress\nVENDOR=$vendor\nHOPS=$hops\nSTATUS=$status\nLATENCY=$latency\nDEVICE TYPE=$devicetype\nRUNNING=$running\nNOT SHOWN=$notshown\nOC CPE=$os_cpe\nOS DETAILS=$os_details\nWARNINGS=$warning\nAGRESSIVE OS GUESSES=$aggressive_os_guesses\n$info\n------------------------\n";
	       push(@text,"IP: $ipaddress")           if ($ipaddress  !~ /^unknown$/i);
	       push(@text,"HOSTNAME: $hostname")      if ($hostname   !~ /^unknown$/i);
	       push(@text,"MAC: $macaddress")         if ($macaddress !~ /^unknown$/i);
	       push(@text,"VENDOR: $vendor")          if ($vendor     !~ /^unknown$/i);
	       push(@text,"DEVICE TYPE: $devicetype") if ($devicetype !~ /^unknown$/i);
	       push(@text,"RUNNING: $running")        if ($running    !~ /^unknown$/i);
	       push(@node,"{ key: $num, text: \"".join("\\n",@text)."\" }");
               push(@link,"{ from: 1, to: $num}");
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
               $notshown="unknown";
               $os_cpe="unknown";
               $os_details="unknown";
               $warning="unknown";
               $aggressive_os_guesses="unknown";
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
          } elsif ($line =~ /Not\sshown:\s(.+)$/) {
               $notshown=$1;
               next;
          } elsif ($line =~ /OS\sCPE:\s(.+)$/) {
               $os_cpe=$1;
               next;
          } elsif ($line =~ /OS\sdetails:\s(.+)$/) {
               $os_details=$1;
               next;
          } elsif ($line =~ /Warning:\s(.+)$/) {
               $warning=$1.". ";
               next;
          } elsif ($line =~ /(All\s1000\sscanned\sports)\son\s(.+ )(\sare\sclosed)/) {
               $notshown=$1.$3;
               next;
          } elsif ($line =~ /Aggressive OS guesses:\s(.+)$/) {
               $aggressive_os_guesses=$1;
               next;
          } elsif ($line =~ /(Too\smany\sfingerprints.+)$/) {
               $warning.=$1.". ";
               next;
          } elsif ($line =~ /(No\sexact\sOS\smatches.+)$/) {
               $warning.=$1.".";
               next;
          }
          $info.="$line\n";
     }
}
my $node= "var nodeDataArray = [".join(",",@node)."];";
my $link= "var linkDataArray = [".join(",",@link)."];";
print "\nnode=$node\n\nlink=$link\n\n";

open my $in,  '<', "map.html.org" or die "Can't read map.html.org file: $!";
open my $out, '>', "map.html"     or die "Can't write map.html file: $!";

while( <$in> )
     {
     s/^.+var\snodeDataArray.+$/${node}/g;
     s/^.+var\slinkDataArray.+$/${link}/g;
    print $out $_;
    }

close $in;
close $out;


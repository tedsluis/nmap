#!/usr/bin/perl
use strict;
use Getopt::Long;
#
# Input parameters
my $help;
my $ipaddresses;
my $defaultgateway;
my $debug;
GetOptions(
     "help!"=>\$help,
     "debug!"=>\$debug,
     "gw=s"=>\$defaultgateway,
     "ipaddresses=s"=>\$ipaddresses
) or exit(1);
#
# Help
if ($help) {
     print "Help

usage: 
       $0 
optional:
       $0 -ip <subnet>|<ip address>[,<subnet>|<ip address>]    Scan subnet(s) and/or ip address(es).
       $0 -gw <ip address>,[<ip addres>]                       Specify default gateway(s).
       $0 -debug                                               Display debug info.
       $0 -help                                                This helptext.

examples:
       $0 -ip 192.168.1.0/24,192.168.100.0/24
       $0 -ip 192.168.1.254,192.168.1.1
       $0 -ip 192.168.1.0/24 -gw 192.168.1.254

view result 'map.html' in a webbrowser.

note: be sure you have installed nmap!\n\n";
exit 0;
}
    

#
# Get networks if non were specified
if (!$ipaddresses) {
     my @data=`ip add | grep inet | grep -v 127.0.0.1`;
     my @subnets;
     foreach my $subnet (@data) {
           print $subnet if ($debug);
           push(@subnets,$1) if ($subnet =~ /inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3})\s/);
     }
     $ipaddresses=join(",",@subnets);
}
print $ipaddresses."\n";
 
# 
# Scan subnets
my @node;
my @link;
my %host;
my %hosts;    # hosts{ip} => ip+name
my %ips;      # ips{subnet}{ip} => ip+name
my %subnets;  # subnets{ip} => subnet
my %gateway;  # gateway{subnet} => ip gateway
my @subnets=split(/,/,$ipaddresses);
foreach my $subnet (@subnets) {
     print "SUBNET=$subnet\n" if ($debug);
     my @data=`nmap -O -n $subnet`;
     my $info="";
     my @key;
     my @desc;
     my $color="lightyellow";
     my $category="simple";
     my $ipaddress="unknown";
     foreach my $line (@data) {
          chomp($line);
          if (($ipaddress =~ /^unknown$/) && ($line =~ /^\s*$/)) {
               next;
          } elsif ($line =~ /^\s*$/) {
               # Reached end of host info: start processing host info.
               print "IP ADDRESS=$ipaddress\n" if ($debug);
               $hosts{$ipaddress}=join(",",@key);
               $ips{$subnet}{$ipaddress}=join(",",@key); 
               push(@node,"{ key: \"".join(",",@key)."\", desc: \"".join("\\n",@desc)."\", color: \"$color\", category: \"$category\" }");
               push(@link,"{ from: \"DEFAULTGATEWAY$subnet\", to: \"".join(",",@key)."\" }");
               # clear variables for next hosts.
               $info="";
               @key=();
               @desc=();
               $color="lightyellow";
               $category="simple";
               $ipaddress="unknown";
               next;
          } elsif ($line =~ /Nmap\sscan\sreport\sfor\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*/) {
               # parse IP address  
               $ipaddress=$1;
               $host{$ipaddress}{'subnet'}=$subnet;
               $subnets{$ipaddress}=$subnet;
               push(@key,$1);
               #
               # Add gateway
               my @gw=split(/,/,$defaultgateway);
               for my $gw (@gw) {
                    if ($gw =~ /^${ipaddress}$/) {
                         $host{$ipaddress}{'gateway'}=$ipaddress;
                         $gateway{$subnet}=$gw;
                         $host{$ipaddress}{'color'}='red';
                         $color="red";
                         print "GATEWAY=$gw\n" if ($debug);
                    }
               }
               my @hostname=`nslookup $ipaddress`;
               foreach my $line (@hostname) {
                    chomp($line);
                    # Parse hostname   
                    if ($line =~ /in-addr\.arpa\s+name\s=\s(.+)\.$/){
                         $host{$ipaddress}{'hostname'}=$1;
                         push(@key,$1);
                         $host{$ipaddress}{'color'}='lightblue' if (! exists $host{$ipaddress}{'color'});
                         $color="lightblue";
                         print "HOSTNAME=$1\n" if ($debug);
                    }
               }
               my @route;
               my @traceroute=`traceroute $ipaddress`;
               foreach my $line (@traceroute) {
                    chomp($line);
                    # Parse route    
                    if ($line =~ /^\s*(\d+)\s+([a-z0-9\.\-]+)\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+/i) {
                         push(@route,"\[$2 ($3)\]");
                         print "HOP=$2 $3\n" if ($debug);
                         # Store gateway subnet.
                         if ($1 !~ /^1$/) {
                              $gateway{$subnets{$3}} = $3 if ((exists $subnets{$3}) && (!exists $gateway{$subnets{$3}}));
                              if ($route[0] =~ /\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/) {
                                    $gateway{$subnets{$1}} = $1 if ((exists $subnets{$1}) && (!exists $gateway{$subnets{$1}}));
                              }
                         }
                    }
               }
               push(@desc,"Route: ".join("-->",@route));
               next;
          } elsif ($line =~ /MAC\sAddress:\s([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})\s+\((.+)\)$/i) {
               $host{$ipaddress}{'mac'}=$1;
               push(@desc,"MAC: $1");
               $host{$ipaddress}{'vendor'}=$2;
               push(@desc,"Vendor: $2");
               print "MAC ADDRESS=$1 $2\n" if ($debug);
               next;
          } elsif ($line =~ /Host\sis\sup\s\((\d+\.\d+s\slatency)\)/) {
               $host{$ipaddress}{'status'}='up';
               push(@desc,"Status: Up");
               $host{$ipaddress}{'latency'}=$1;
               push(@desc,"Latency: $1");
               print "LATENCY=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Network\sDistance:\s(\d+)\shop/) {
               $host{$ipaddress}{'hops'}=$1;
               push(@desc,"Hops: $1");
               print "HOPS=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Device type:\s(.+)$/) {
               $host{$ipaddress}{'devicetype'}=$1;
               push(@desc,"Device type: $1");
               print "DEVICE TYPE=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Running:\s(.+)$/) {
               $host{$ipaddress}{'running'}=$1;
               push(@desc,"Running: $1");
               print "RUNNING=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Not\sshown:\s(.+)$/) {
               $host{$ipaddress}{'notshown'}.="$1\n";
               push(@desc,"Not shown: $1");
               print "NOT SHOWN=$1\n" if ($debug);       
               next;
          } elsif ($line =~ /OS\sCPE:\s(.+)$/) {
               $host{$ipaddress}{'os'}.="$1\n";
               push(@desc,"OS CPE: $1");
               print "OS CPE=$1\n" if ($debug);
               next;
          } elsif ($line =~ /OS\sdetails:\s(.+)$/) {
               $host{$ipaddress}{'os'}.="$1\n";
               push(@desc,"Os Details: $1");
               print "OS DETAILS=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Warning:\s(.+)$/) {
               $host{$ipaddress}{'warning'}.="$1.\n";
               push(@desc,"Warning: $1.");
               print "WARNING=$1\n" if ($debug);
               next;
          } elsif ($line =~ /(All\s1000\sscanned\sports)\son\s(.+ )(\sare\sclosed)/) {
               $host{$ipaddress}{'notshown'}.="$1.$3\n";
               push(@desc,"Not shown: $1.$3");
               print "NOT SHOWN=$1.$3\n" if ($debug);
               next;
          } elsif ($line =~ /Aggressive OS guesses:\s(.+)$/) {
               $host{$ipaddress}{'os'}.="$1\n";
               push(@desc,"Aggressive OS guesses: $1");
               print "AGGRESSIVE OS GUESSES=$1\n" if ($debug);
               next;
          } elsif ($line =~ /(Too\smany\sfingerprints.+)$/) {
               $host{$ipaddress}{'warning'}.="$1.\n";
               push(@desc,"Warning: $1. ");
               print "TOO MANY FINGERPRINTS=$1.\n" if ($debug);
               next;
          } elsif ($line =~ /(No\sexact\sOS\smatches.+)$/) {
               $host{$ipaddress}{'warning'}.="$1.\n";
               push(@desc,"Warning: $1.");
               print "NO EXACT OS MATCHES=$1\n" if ($debug);
               next;
          }
          $info.="$line\n";
     }


}

#
# Add data to map.html
my $node= "diagram.model.nodeDataArray = [".join(",",@node)."];";
my $link= "diagram.model.linkDataArray = [".join(",",@link)."];";

open my $in,  '<', "map.html.org" or die "Can't read map.html.org file: $!";
open my $out, '>', "map.html"     or die "Can't write map.html file: $!";

while( <$in> )
     {
     # Insert host data and links
     s/^\s*diagram\.model\.nodeDataArray\s=\s\[.+$/${node}/g;
     s/^\s*diagram\.model\.linkDataArray\s=\s\[.+$/${link}/g;
     # replace dummy gateway
     foreach my $subnet (@subnets) {
          my $gatewayname;
          if ((exists $gateway{$subnet}) && ($hosts{$gateway{$subnet}})) {
               $gatewayname=$hosts{$gateway{$subnet}};
          } else {
               my ($key,@x)=(sort keys %{$ips{$subnet}});
               $gatewayname=$hosts{$key};
	       print "KEY=$key,gatewayname=$gatewayname\n" if ($debug);
          }       
          s/DEFAULTGATEWAY${subnet}/${gatewayname}/g;
     } 
     print $out $_;
     }

close $in;
close $out;


#!/usr/bin/perl
use strict;
use Getopt::Long;
#
# Input parameters
my $help;
my $cidrs;
my $debug;
GetOptions(
     "help!"=>\$help,
     "debug!"=>\$debug,
     "subnets=s"=>\$cidrs
) or exit(1);
#
# Help
if ($help) {
     print "Help

Usage: 
       $0 
Optional:
       $0 -subnet <cidr>[,<cidr>]    Subnet(s) in CIDR notation.
       $0 -debug                     Display debug info.
       $0 -help                      This helptext.

Examples:
       $0 -subnet 192.168.1.0/24
       $0 -subnet 192.168.1.0/24,192.168.11.0/24

View result 'map.html' in a webbrowser.

Lookup your Netbits:
+------+----------+------------------------------------+
| Net  | Number   |                                    |
| bits | of hosts |  Netmask                           |
+------+----------+------------------------------------+
| /8   | 16777214 |  255.0.0.0                         |
| /9   | 8388606  |  255.128.0.0                       |
| /10  | 4194302  |  255.192.0.0                       |
| /11  | 2097150  |  255.224.0.0                       |
| /12  | 1048574  |  255.240.0.0                       |
| /13  | 524286   |  255.248.0.0                       |
| /14  | 262142   |  255.252.0.0                       |
| /15  | 131070   |  255.254.0.0                       |
| /16  | 65534    |  255.255.0.0                       |
| /17  | 32766    |  255.255.128.0                     |
| /18  | 16382    |  255.255.192.0                     |
| /19  | 8190     |  255.255.224.0                     |
| /20  | 4094     |  255.255.240.0                     |
| /21  | 2046     |  255.255.248.0                     |
| /22  | 1022     |  255.255.252.0                     |
| /23  | 510      |  255.255.254.0                     |
| /24  | 254      |  255.255.255.0                     |
| /25  | 126      |  255.255.255.128                   |
| /26  | 62       |  255.255.255.192                   |
| /27  | 30       |  255.255.255.224                   |
| /28  | 14       |  255.255.255.240                   |
| /29  | 6        |  255.255.255.248                   |
| /30  | 2        |  255.255.255.252                   |
| /31  | -        |  point to point links only         |
| /32  | 1        |  255.255.255.255 single IP address |
+------+----------+------------------------------------+
Notes: 
   - Number of hosts = usable number of hosts.
   - CIDR = network address + /netbits, for example: 192.168.1.0/24
   - Instead of the network address, any IP within the subnet is accepted.
   - Be sure 'nmap', 'traceroute' and 'network manager' are installed!

\n";
exit 0;
}

#
# Get host IP(s), interfaces and subnets
my @data=`ip add | grep inet | grep -v inet6 | grep -v 127.0.0.1`;
my %hostips;
my @cidrs;
@cidrs=split(/,/,$cidrs) if ($cidrs);
foreach my $hostip (@data) {
     print $hostip if ($debug);
     if ($hostip =~ /inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,3})\s.+\s([a-z0-9\-]+)$/i) {
          # Get IP's and interface name
          $hostips{$1}=$3;
          print "Interface=$3 (ip=$1)\n";
          # Get networks if non were specified
          push(@cidrs,"$1/$2") if ((!$cidrs) || (($cidrs) && ($cidrs !~ /^$1\/$2$/)));
     }
}

#
# default gateway
@data=`ip route`;
my $hostgateway;
foreach my $line (@data) {
     $hostgateway = $1 if ($line =~ /^default\s+via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+/);
}
print "Host gateway=$hostgateway\n";

#
# Initialize variables
my @node;
my @link;
my %fact;
my %host;
my %route;
my %trace;
my %reverse;
my %interface;
my %interfacesubnet;
my %hosts;    # hosts{ip} => ip+name
my %ips;      # ips{subnet}{ip} => ip+name
my %subnets;  # subnets{ip} => subnet
my %gateway;  # gateway{subnet} => ip gateway
my %cidr;
my %subnet2ip;
my %ip2subnet;
my @subnets;

#
# Get CIDR, network address & broadcast address
foreach my $subnet (@cidrs) {
     # Validate CIDR
     if ($subnet !~ /(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$)/) {
          print "Error: CIDR '$1' is invalid!\n";
          exit 1;
     }
     # 10.0.0.0/24 192.168.1.0/16
     my($subnetwork, $netbit)=split(m'/',$subnet);
     # Decimal representation of mask
     my $mask  = (2 ** $netbit - 1) << (32 - $netbit); 
     # Convert decimal representation to ip format
     my $netmask = join( '.', unpack( "C4", pack( "N", $mask ) ) );
     # Split to decimals
     my ($ip1,$ip2,$ip3,$ip4)=($1,$2,$3,$4) if ($subnet  =~ /\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/\d{1,2}\s*/);
     my ($ma1,$ma2,$ma3,$ma4)=($1,$2,$3,$4) if ($netmask =~ /\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*/);
     # Convert to bits
     my ($ip)      = unpack( "N", pack( "C4", $ip1,$ip2,$ip3,$ip4 ) );
     my ($mask)    = unpack( "N", pack( "C4", $ma1,$ma2,$ma3,$ma4 ) );
     my ($fullmask)= unpack( "N", pack( "C4", 255,255,255,255 ) );
     # Calculate network and broadcast, convert to ip format
     my $network   = join( '.', unpack( "C4", pack( "N", ( $ip & $mask ) ) ) );
     my $broadcast = join( '.', unpack( "C4", pack( "N", ( $ip | ($fullmask ^ $mask )) ) ) );
     next if (exists $cidr{"$network/$netbit"});
     $cidr{"$network/$netbit"}{'subnetmask'}=$netmask;
     $cidr{"$network/$netbit"}{'network'}=$network;
     $cidr{"$network/$netbit"}{'broadcast'}=$broadcast;
     push(@subnets,"$network/$netbit");
     # Determine IP's per subnet
     my ($n1,$n2,$n3,$n4)=($1,$2,$3,$4) if ($cidr{"$network/$netbit"}{'network'}   =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
     my ($b1,$b2,$b3,$b4)=($1,$2,$3,$4) if ($cidr{"$network/$netbit"}{'broadcast'} =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
     for (my $ip1 = $n1; $ip1 <= $b1; $ip1++) {
          for (my $ip2 = $n2; $ip2 <= $b2; $ip2++) {
               for (my $ip3 = $n3; $ip3 <= $b3; $ip3++) {
                    for (my $ip4 = $n4; $ip4 <= $b4; $ip4++) {
                         my $ip="$ip1.$ip2.$ip3.$ip4";
                         $subnet2ip{$subnet}{$ip}="";
                         $ip2subnet{$ip}=$subnet;
                    }
               }
          }
     }
     print "  $subnet (subnetwork=$network/$netbit, netbit=$netbit, subnetmask=$netmask, network=$network, broadcast=$broadcast), number of IP's=".(((keys %{$subnet2ip{$subnet}})-2)||1)."\n";
}

#
# subroutine traceroute
sub TraceRoute(@) {
     my $ipaddress = shift;
     my $subnet= shift;
     my @route;
     foreach my $hostip (keys %hostips) {
          next if ((exists $interface{$hostip}) && (exists $interface{$hostip}{$subnet}) && ($interface{$hostip}{$subnet} =~ /UNREACHABLE/));
          my @traceroute=`traceroute -i $hostips{$hostip} $ipaddress`;
          print "traceroute -i $hostips{$hostip} $ipaddress " if ($debug);
          foreach my $line (@traceroute) {
               chomp($line);
               print "\n" if ($debug);
               # Parse route    
               if ($line =~ /^\s*(\d+)\s+\*\s+\*\s+\*/) {
                    my $hop=$1;
                    print "." if ($debug);
                    $interface{$hostip}{$subnet}="UNREACHABLE" if (! exists $interface{$hostip}{$subnet});
                    if (($hop>1) && (exists $trace{$ipaddress}{($hop-1)}) && ($trace{$ipaddress}{($hop-1)} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)) {
                         my $gw=$trace{$ipaddress}{($hop-1)};
                         if (exists $subnets{$gw}) {
                              $gateway{$subnets{$gw}} = $gw;
                              print "      GATEWAY FOUND: $gw in $subnets{$gw} (HOP=$hop)\n";
                         }
                    } 
               } elsif ($line =~ /^\s*(\d+)\s+([a-z0-9\.\-]+)\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s(.+)$/i) {
                    my ($hop,$name,$ip,$rest)=($1,$2,$3,$4);
                    $subnets{$ip}=$ip2subnet{$ip} if ((!exists $subnets{$ip}) && (exists $ip2subnet{$ip}));
                    $trace{$ipaddress}{$hop}=$ip;
                    $reverse{$ipaddress}{$ip}=$hop;
                    push(@route,"\[$name ($ip)\]");
                    print "    IPADDRESS=$ipaddress ---> HOP=$name $ip ($hop)  [via: interface=$hostips{$hostip} ($hostip)]\n" if ($debug);
                    # Store gateway subnet.
                    if ($hop > 1) {
			    #print "Debug: ipaddres=$ipaddress,hop=$hop,name=$name,ip=$ip,rest=$rest\n";
			    #print "hop (".($hop).")=$trace{$ipaddress}{($hop)}\n" if ((exists $trace{$ipaddress}) && (exists $trace{$ipaddress}{($hop)}));
			    #print "hop-1 (".($hop-1).")=$trace{$ipaddress}{($hop-1)}\n" if ((exists $trace{$ipaddress}) && (exists $trace{$ipaddress}{($hop-1)}));
                         if (($rest =~ /\s!H\s/) && (exists $trace{$ipaddress}) && (exists $trace{$ipaddress}{$hop-1})){
                              $route{$ip}=$trace{$ipaddress}{$hop-1};
                              print "      ROUTE FOUND: $ip in subnet $subnets{$ip} to gateway $trace{$ipaddress}{$hop-1} in subnet $subnets{$trace{$ipaddress}{$hop-1}} (HOP=$hop)\n";
                         }
                         if ((exists $trace{$ipaddress}{($hop-1)}) && ($trace{$ipaddress}{($hop-1)} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)) {
                              my $gw=$trace{$ipaddress}{($hop-1)};
                              if (exists $subnets{$gw}) {
                                   $gateway{$subnets{$gw}} = $gw;
                                   print "      GATEWAY FOUND: $gw in $subnets{$gw} (HOP=$hop)\n";
                              } else { 
                                   print "      NO GATEWAY FOUND: (hop=$hop), ip $gw not jet scanned.\n";
                              }
                         } else {
                              print "      NO GATEWAY FOUND: (HOP=$hop)\n";
                         }
                    } else {
                         if ((exists $subnets{$ip}) && (exists $subnets{$hostip}) && ($subnets{$ip} !~ /^$subnets{$hostip}$/) && (exists $gateway{$subnets{$hostip}})) {
                              $route{$ip}=$gateway{$subnets{$hostip}};
                              print "      ROUTE FOUND: $ip in subnet $subnets{$ip} to $gateway{$hostip} in subnet $subnets{$hostip} (HOP=1) \n";
                         }
                         if ($subnets{$hostgateway} =~ /^$subnet$/) {
                              $gateway{$subnet}=$hostgateway;
                              print "      GATEWAY FOUND: $hostgateway in subnet $subnets{$hostgateway} (HOP=1) (host gateway)\n";
                         } else {
                              print "      NO GATEWAY FOUND (HOP=1)\n";
                         }
                    }
                    # subnet is reachable using hostip
                    $interface{$hostip}{$subnet}=$hostips{$hostip};
                    $interfacesubnet{$subnet}=$hostip;
               }
          }
     }    
     return @route;
}

#
# Scan subnets
foreach my $subnet (@subnets) {
     print "~~~~~~~~~~~~~~~~~ Start scanning SUBNET=$subnet ~~~~~~~~~~~~~~~~~\n" if ($debug);
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
               $host{$ipaddress}{'color'}='lightyellow';
               $subnets{$ipaddress}=$subnet;
               print "++++++++++++++ SCAN HOST IP =$ipaddress, subnet=$subnet +++++++++++++++++\n" if ($debug);
               push(@key,$1);
               #
               # get hostname
               my @hostname=`nslookup $ipaddress`;
               foreach my $line (@hostname) {
                    chomp($line);
                    # Parse hostname   
                    if ($line =~ /in-addr\.arpa\s+name\s=\s(.+)\.$/){
                         $host{$ipaddress}{'hostname'}=$1;
                         push(@key,$1);
                         $host{$ipaddress}{'color'}='lightcyan' if (! exists $host{$ipaddress}{'color'});
                         $color="lightcyan";
                         print "HOSTNAME=$1\n" if ($debug);
                    }
               }
               my $route=join("-->",TraceRoute($ipaddress,$subnet));
               print "\nROUTE=$route\n" if ($debug);    
               push(@desc,"Route: $route");
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
               push(@{$fact{$ipaddress}},"$1");
               push(@desc,"Not shown: $1");
               print "NOT SHOWN=$1\n" if ($debug);       
               next;
          } elsif ($line =~ /OS\sCPE:\s(.+)$/) {
               $host{$ipaddress}{'oc_cpe'}="$1";
               push(@desc,"OS CPE: $1");
               print "OS CPE=$1\n" if ($debug);
               next;
          } elsif ($line =~ /OS\sdetails:\s(.+)$/) {
               $host{$ipaddress}{'os_details'}="$1.";
               push(@desc,"Os Details: $1");
               print "OS DETAILS=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Warning:\s(.+)$/) {
               push(@{$fact{$ipaddress}},"$1.");
               push(@desc,"Warning: $1.");
               print "WARNING=$1\n" if ($debug);
               next;
          } elsif ($line =~ /(All\s1000\sscanned\sports)\son\s(.+ )(\sare\sclosed)/) {
               push(@{$fact{$ipaddress}},"$1.$3");
               push(@desc,"Not shown: $1.$3");
               print "NOT SHOWN=$1.$3\n" if ($debug);
               next;
          } elsif ($line =~ /Aggressive OS guesses:\s(.+)$/) {
               push(@{$fact{$ipaddress}},"$1");
               push(@desc,"Aggressive OS guesses: $1");
               print "AGGRESSIVE OS GUESSES=$1\n" if ($debug);
               next;
          } elsif ($line =~ /(Too\smany\sfingerprints.+)$/) {
               push(@{$fact{$ipaddress}},"$1.");
               push(@desc,"Warning: $1. ");
               print "TOO MANY FINGERPRINTS=$1.\n" if ($debug);
               next;
          } elsif ($line =~ /(No\sexact\sOS\smatches.+)$/) {
               push(@{$fact{$ipaddress}},"$1.");
               push(@desc,"Warning: $1.");
               print "NO EXACT OS MATCHES=$1\n" if ($debug);
               next;
          }
          $info.="$line\n";
     }
}

#
# Trace a non scanned IP in every subnets
print "--------------- TRACEROUTE a non scanned IP in every subnet -------------------------------\n";
foreach my $subnet (sort keys %cidr) {
     foreach my $ip (keys %{$subnet2ip{$subnet}}) {
          next if (($ip =~ /^$cidr{$subnet}{'network'}$/) || ($ip =~ /^$cidr{$subnet}{'broadcast'}$/)); 
          next if ((exists $subnets{$ip}) || (exists $cidr{$subnet}{'scanned_non_existing_ip'}));
          $subnets{$ip}=$subnet;
          $cidr{$subnet}{'scanned_non_existing_ip'}="yes";
          print "--------------------->>> START=$cidr{$subnet}{'network'}, END=$cidr{$subnet}{'broadcast'}, IP=$ip\n";
          print "  ".join("-->",TraceRoute($ip,$subnet))."\n"; 
     }
}

#
# Scan internet gateway
print "--------------- SCAN INTERNET GATEWAY -------------------------------\n";
print "INTERNET GATEWAY  ".join("-->",TraceRoute("8.8.8.8","8.8.8.8/31"))."\n";

#
# get default gateways & routes
print "--------------- RESCAN GATEWAYS & ROUTES -------------------------------\n";
foreach my $ipaddress (sort keys %subnets) {
     my $subnet=$subnets{$ipaddress};
     print "  IP=$ipaddress  ".join("-->",TraceRoute($ipaddress,$subnet))."\n\n";
}

sub NAME(@) {
     my $ipaddress=shift;
     my $name=$ipaddress;
     $name.=",".$host{$ipaddress}{'hostname'} if (exists $host{$ipaddress}{'hostname'});
     return $name;
}

my @nodes;
my @links;
foreach my $ipaddress (sort keys %subnets) {
     my @basics;
     my @details;
     my @ports;
     my $subnet=$subnets{$ipaddress};
     push(@basics, "Subnet: "     .$subnet);
     push(@basics, "Gateway: "    .$gateway{$subnets{$ipaddress}});
     push(@basics, "Device type: ".$host{$ipaddress}{'devicetype'}) if  (exists $host{$ipaddress}{'devicetype'});
     push(@basics, "Running: "    .$host{$ipaddress}{'running'}   ) if  (exists $host{$ipaddress}{'running'});
     push(@basics, "MAC: "        .$host{$ipaddress}{'mac'}       ) if  (exists $host{$ipaddress}{'mac'});
     push(@basics, "Vendor: "     .$host{$ipaddress}{'vendor'}    ) if  (exists $host{$ipaddress}{'vendor'});
     push(@details,"Status: "     .$host{$ipaddress}{'status'}    ) if  (exists $host{$ipaddress}{'status'});
     push(@details,"Latency: "    .$host{$ipaddress}{'latency'}   ) if  (exists $host{$ipaddress}{'latency'});
     push(@details,"Hops: "       .$host{$ipaddress}{'hops'}      ) if  (exists $host{$ipaddress}{'hops'});
     push(@details,"OC CPE: "     .$host{$ipaddress}{'oc_cpe'}    ) if  (exists $host{$ipaddress}{'oc_cpe'});
     push(@details,"OS Details: " .$host{$ipaddress}{'os_details'}) if  (exists $host{$ipaddress}{'os_details'});
     push(@details,"Warnings: ",join("\\n",@{$fact{$ipaddress}}))   if ((exists $fact{$ipaddress}) && (@{$fact{$ipaddress}}));
     $name=NAME($ipaddress);
     my $color=$host{$ipaddress}{'color'} || "lightyellow";
     $color="lightsalmon" if ((exists $host{$ipaddress}{'oc_cpe'}) && ($host{$ipaddress}{'oc_cpe'} =~ /linux/i));
     $color="green"       if ((exists $host{$ipaddress}{'vendor'}) && ($host{$ipaddress}{'vendor'} =~ /apple/i));
     $color="lightblue"   if ((exists $host{$ipaddress}{'vendor'}) && ($host{$ipaddress}{'vendor'} =~ /raspberry/i));
     $color="lightgreen"  if ((exists $host{$ipaddress}{'vendor'}) && ($host{$ipaddress}{'vendor'} =~ /intel/i));
     $color="orange"      if  (exists $route{$ipaddress});
     $color="yellow"      if  (exists $gateway{$ipaddress});
     push(@nodes,"{ key:  \"${name}\", basics: \"".join("\\n",@basics)."\", details: \"".join("\\n",@details)."\",ports: \"".join("\\n",@ports)."\", color: \"$color\", category: \"name\" }");
     if (exists $gateway{$subnets{$ipaddress}}) {
          push(@links,"{ from: \"${name}\", to: \"".NAME($gateway{$subnets{$ipaddress}})."\" }");
     } else {
          push(@links,"{ from: \"${name}\", to: \"${name}\" }");
     }
}

#
# Add routes
foreach my $route (keys %route) {
     next if (! exists $subnets{$route});
     my $gateway=$route{$route};
     next if (! exists $subnets{$gateway});
     if ($gateway =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
          push(@links,"{ from: \"".NAME($gateway)."\", to: \"".NAME($route)."\" }");
     } else {
          push(@links,"{ from: \"".NAME($route)."\", to: \"".NAME($route)."\" }");
     }
}


#
# Add data to map.html
my $node= "diagram.model.nodeDataArray = [".join(",",@nodes)."];";
my $link= "diagram.model.linkDataArray = [".join(",",@links)."];";

open my $in,  '<', "map.html.org" or die "Can't read map.html.org file: $!";
open my $out, '>', "map.html"     or die "Can't write map.html file: $!";

while( <$in> )
     {
     # Insert host data and links
     s/^\s*diagram\.model\.nodeDataArray\s=\s\[.+$/${node}/g;
     s/^\s*diagram\.model\.linkDataArray\s=\s\[.+$/${link}/g;
     print $out $_;
}

close $in;
close $out;


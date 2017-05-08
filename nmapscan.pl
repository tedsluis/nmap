#!/usr/bin/perl
use strict;
use Getopt::Long;
use POSIX qw/strftime/;
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
   - Be sure 'nmap', 'traceroute', 'iproute' and 'gojs' are installed!

\n";
     exit 0;
}

#
# Prerequisites check
if (! -e "go.js") {
     print "\nNo 'go.js' file found!\nIf you wish to use the GoJS library for your private evaluation, you may do so only under the terms of the Evaluation License Agreement.\nCheck http://gojs.net/latest/doc/download.html\n\n";
     exit;
}
my @cmd;
@cmd=`which nmap`;
if (join('',@cmd) !~ /nmap/) {
     print "\nPackage 'nmap' not found!";
     exit;
}
@cmd=`which ip`;
if (join('',@cmd) !~ /ip/) {
     print "\nPackage 'iproute' not found!";
     exit;
}@cmd=`which traceroute`;
if (join('',@cmd) !~ /traceroute/) {
     print "\nPackage 'traceroute' not found!";
     exit;
}

#
# Get host IP(s), interfaces and subnets
my @data=`ip add | grep inet | grep -v inet6 | grep -v 127.0.0.1`;
my %hostips;
my %hostmac;
my @cidrs;
@cidrs=split(/,/,$cidrs) if ($cidrs);
foreach my $hostip (@data) {
     print $hostip if ($debug);
     if ($hostip =~ /inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,3})\s.+\s([a-z0-9\-]+)$/i) {
          my ($ip,$netbit,$interface)=($1,$2,$3);
          # Get IP's and interface name
          $hostips{$ip}=$interface;
          # Get networks if non were specified
          push(@cidrs,"$ip/$netbit") if ((!$cidrs) || (($cidrs) && ($cidrs !~ /^$ip\/$netbit$/)));
          # Get mac address interface
          my @mac=`ifconfig $interface | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`;
          $hostmac{$ip}=$1 if ($mac[0] =~ /^([0-9a-f:]+)$/i);
          print "Interface=$interface (ip=$ip,mac=$hostmac{$ip})\n";
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
my %fact;
my %port;
my %host;
my %route;
my %trace;
my %reverse;
my %interface;
my %interfacesubnet;
my %subnets;          # subnets{ip} => subnet
my %gateway;          # gateway{subnet} => ip gateway
my %cidr;
my %subnet2ip;
my %ip2subnet;
my $internetgateway;
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
               # Parse route    
               if ($line =~ /^\s*(\d+)\s+\*\s+\*\s+\*/) {
                    my $hop=$1;
                    $interface{$hostip}{$subnet}="UNREACHABLE" if (! exists $interface{$hostip}{$subnet});
                    if (($hop>1) && (exists $trace{$ipaddress}{($hop-1)}) && ($trace{$ipaddress}{($hop-1)} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)) {
                         my $gw=$trace{$ipaddress}{($hop-1)};
                         if (exists $subnets{$gw}) {
                              $gateway{$subnets{$gw}} = $gw;
                              if ($ipaddress =~ /^8\.8\.8\.8$/) {
                                   print "      INTERNET GATEWAY FOUND: $gw in $subnets{$gw} (HOP=$hop)\n" if ($debug);
                                   $internetgateway=$gw;
                              } else {
                                   print "      GATEWAY FOUND: $gw in $subnets{$gw} (HOP=$hop)\n" if ($debug);
                              }
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
                         if (($rest =~ /\s!H\s/) && (exists $trace{$ipaddress}) && (exists $trace{$ipaddress}{$hop-1})){
                              $route{$ip}=$trace{$ipaddress}{$hop-1};
                              print "      ROUTE FOUND: $ip in subnet $subnets{$ip} to gateway $trace{$ipaddress}{$hop-1} in subnet $subnets{$trace{$ipaddress}{$hop-1}} (HOP=$hop)\n" if ($debug);
                         }
                         if ((exists $trace{$ipaddress}{($hop-1)}) && ($trace{$ipaddress}{($hop-1)} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)) {
                              my $gw=$trace{$ipaddress}{($hop-1)};
                              if (exists $subnets{$gw}) {
                                   $gateway{$subnets{$gw}} = $gw;
                                   print "      GATEWAY FOUND: $gw in $subnets{$gw} (HOP=$hop)\n" if ($debug);
                              } else { 
                                   print "      NO GATEWAY FOUND: (hop=$hop), ip $gw not jet scanned.\n" if ($debug);
                              }
                         } else {
                              print "      NO GATEWAY FOUND: (HOP=$hop)\n" if ($debug);
                         }
                    } else {
                         if ((exists $subnets{$ip}) && (exists $subnets{$hostip}) && ($subnets{$ip} !~ /^$subnets{$hostip}$/) && (exists $gateway{$subnets{$hostip}})) {
                              $route{$ip}=$gateway{$subnets{$hostip}};
                              print "      ROUTE FOUND: $ip in subnet $subnets{$ip} to $gateway{$hostip} in subnet $subnets{$hostip} (HOP=1) \n" if ($debug);
                         }
                         if ($subnets{$hostgateway} =~ /^$subnet$/) {
                              $gateway{$subnet}=$hostgateway;
                              print "      GATEWAY FOUND: $hostgateway in subnet $subnets{$hostgateway} (HOP=1) (host gateway)\n" if ($debug);
                         } else {
                              print "      NO GATEWAY FOUND (HOP=1)\n" if ($debug);
                         }
                    }
                    # Gateway Host IP's other subnets
                    if ((exists $hostips{$ipaddress}) && (!exists $gateway{$subnets{$ipaddress}}) && (exists $subnets{$hostgateway})){
                         foreach my $ip (keys %hostips) {
                              if ($subnets{$ip} =~ /^$subnets{$hostgateway}$/) {
                                   $gateway{$subnets{$ipaddress}}=$ip;
                                   print "IPADRESS=$ipaddress (subnet=".$subnets{$ipaddress}."), hostip/gateway=$ip (subnet=".$subnets{$ip}.")\n" if ($debug);
                              }
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
# Get cache files
mkdir("nmapdata");
my %ipcache;
my @datafiles=`find nmapdata -name '*.txt'`;
foreach my $file (@datafiles) {
     chomp($file);
     my $ipaddress=$1 if ($file =~ /nmapdata\/(.+)\.txt$/);
     $ipaddress=~s/_/\./g;
     print "READ IP=$ipaddress, CACHE_FILE=$file\n" if ($debug);
     next unless (exists $ip2subnet{$ipaddress});
     $ipcache{$ipaddress}=$file;
}


#
# Scan subnets 
foreach my $subnet (@subnets) {
     print "~~~~~~~~~~~~~~~~~ Start scanning SUBNET=$subnet ~~~~~~~~~~~~~~~~~\n" if ($debug);
     my @data=`nmap -A -n $subnet`;
     my $ipaddress="unknown";
     # Parse scan output
     foreach my $line (@data) {
          chomp($line);
          next if ($line =~ /^\s*$/);
          if ($line =~ /Nmap\sscan\sreport\sfor\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*/) {
               # parse IP address  
               $ipaddress=$1;
               $host{$ipaddress}{'subnet'}=$subnet;
               $host{$ipaddress}{'color'}='gold';
               $subnets{$ipaddress}=$subnet;
               print "++++++++++++++ SCAN HOST IP =$ipaddress, subnet=$subnet +++++++++++++++++\n" if ($debug);
               #
               # get hostname
               my @hostname=`nslookup $ipaddress`;
               foreach my $line (@hostname) {
                    chomp($line);
                    # Parse hostname   
                    if ($line =~ /in-addr\.arpa\s+name\s=\s(.+)\.$/){
                         $host{$ipaddress}{'hostname'}=uc($1);
                         $host{$ipaddress}{'color'}='lightcyan' if (! exists $host{$ipaddress}{'color'});
                         print "HOSTNAME=".uc($1)."\n" if ($debug);
                    }
               }
               my $route=join("-->",TraceRoute($ipaddress,$subnet));
               print "\nROUTE=$route\n" if ($debug);    
               next;
          } elsif ($line =~ /MAC\sAddress:\s+([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})\s+\((.+)\)$/i) {
               $host{$ipaddress}{'mac'}=$1;
               $host{$ipaddress}{'vendor'}=$2;
               print "MAC ADDRESS=$1 $2\n" if ($debug);
               next;
          } elsif ($line =~ /Host\sis\sup\s\((\d+\.\d+s\slatency)\)/) {
               $host{$ipaddress}{'status'}='up';
               $host{$ipaddress}{'latency'}=$1;
               print "LATENCY=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Network\sDistance:\s(\d+)\shop/) {
               $host{$ipaddress}{'hops'}=$1;
               print "HOPS=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Device type:\s(.+)$/) {
               $host{$ipaddress}{'devicetype'}=$1;
               print "DEVICE TYPE=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Running:?\s(.+)$/) {
               $host{$ipaddress}{'running'}=$1;
               print "RUNNING=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Not\sshown:\s(.+)$/) {
               push(@{$port{$ipaddress}},"$1");
               print "NOT SHOWN=$1\n" if ($debug);       
               next;
          } elsif ($line =~ /OS\sCPE:\s(.+)$/) {
               $host{$ipaddress}{'os_cpe'}="$1";
               print "OS CPE=$1\n" if ($debug);
               next;
          } elsif ($line =~ /OS\sdetails:\s(.+)$/) {
               $host{$ipaddress}{'os_details'}="$1.";
               print "OS DETAILS=$1\n" if ($debug);
               next;
          } elsif ($line =~ /Warning:\s(.+)$/) {
               push(@{$fact{$ipaddress}},"$1.");
               print "WARNING=$1\n" if ($debug);
               next;
          } elsif ($line =~ /(All\s1000\sscanned\sports)\son\s(.+)\s(are\s.+)/) {
               push(@{$port{$ipaddress}},"$1 $3");
               print "NOT SHOWN=$1.$3\n" if ($debug);
               next;
          } elsif ($line =~ /Aggressive\sOS\sguesses:\s(.+)$/) {
               push(@{$fact{$ipaddress}},"$1");
               print "AGGRESSIVE OS GUESSES=$1\n" if ($debug);
               next;
          } elsif ($line =~ /(Too\smany\sfingerprints.+)$/) {
               push(@{$fact{$ipaddress}},"$1.");
               print "TOO MANY FINGERPRINTS=$1.\n" if ($debug);
               next;
          } elsif ($line =~ /(No\sexact\sOS\smatches.+)$/) {
               push(@{$fact{$ipaddress}},"$1.");
               print "NO EXACT OS MATCHES=$1\n" if ($debug);
               next;
          } elsif ($line =~ /^(\d+\/[tu][cd]p)\s+([^\s]+)\s+([^\s]+)\s*(.*)$/i) {
               my ($p,$s,$t,$d)=($1,$2,$3,$4);
               my $port=sprintf("%-9s %-8s %-14s %-50s",$p,$s,$t,($d||""));
               $port =~ s/\s*$//;
               push(@{$port{$ipaddress}},"$port.");
               $host{$ipaddress}{'ports'}=($host{$ipaddress}{'ports'}||"").$p." ";
               print "PORT=$port\n" if ($debug);
          } elsif ($line =~ /http-title:\s+(\S.+)$/i) {
               $host{$ipaddress}{'http-title'}="$1";
               print "HTTP-TITLE=$1\n" if ($debug);
          } elsif ($line =~ /Service Info:\s+(\S.+)$/i) {
               $host{$ipaddress}{'service_info'}="$1";
               print "Service Info=$1\n" if ($debug);
               #
               # Parse service info
               my @info=split(/;\s/,$host{$ipaddress}{'service_info'});
               foreach my $type (@info) {
                    if ($type =~ /^(\w+):\s(.+)$/){
                         my $t=$1;
                         my @i=split(/,/,$2);
                         foreach my $info (@i) {
                              if (($t =~ /CPE/) && ((! exists $host{$ipaddress}{'os_cpe'}) || ((exists $host{$ipaddress}{'os_cpe'}) && ($host{$ipaddress}{'os_cpe'} !~ /\Q$info\E/i)))) {
                                   $host{$ipaddress}{'os_cpe'}=$info." ".($host{$ipaddress}{'os_cpe'}||"");
                                   print "  + SERVICE_INFO/OS_CPE=$host{$ipaddress}{'os_cpe'} -> $ipaddress\n" if ($debug);
                              } elsif (($t =~ /OSs?/) && ((! exists $host{$ipaddress}{'running'}) || ((exists $host{$ipaddress}{'running'}) && ($host{$ipaddress}{'running'} !~ /\Q$info\E/i)))) {
                                   $host{$ipaddress}{'running'}=$info." ".($host{$ipaddress}{'running'}||"");
                                   print "  + SERVICE_INFO/RUNNING=$host{$ipaddress}{'running'} -> $ipaddress\n" if ($debug);
                              } elsif (($t =~ /Device/) && ((! exists $host{$ipaddress}{'devicetype'}) || ((exists $host{$ipaddress}{'devicetype'}) && ($host{$ipaddress}{'devicetype'} !~ /\Q$info\E/i)))) {
                                   $host{$ipaddress}{'devicetype'}=$info||$host{$ipaddress}{'devicetype'};
                                   print "  + SERVICE_INFO/DEVICE_TYPE=$host{$ipaddress}{'devicetype'} -> $ipaddress\n" if ($debug);
                             }
                         }
                    }
               }
          } else {
               print "NOT PARSED! >>>$line<<<\n" if ($debug);
          }
     }
}

#
# Trace a non scanned IP in every subnets
print "--------------- TRACEROUTE a non scanned IP in every subnet -------------------------------\n" if ($debug);
foreach my $subnet (sort keys %cidr) {
     foreach my $ip (keys %{$subnet2ip{$subnet}}) {
          next if (($ip =~ /^$cidr{$subnet}{'network'}$/) || ($ip =~ /^$cidr{$subnet}{'broadcast'}$/)); 
          next if ((exists $subnets{$ip}) || (exists $cidr{$subnet}{'scanned_non_existing_ip'}));
          $subnets{$ip}=$subnet;
          $cidr{$subnet}{'scanned_non_existing_ip'}="yes";
          print "--------------------->>> START=$cidr{$subnet}{'network'}, END=$cidr{$subnet}{'broadcast'}, IP=$ip\n" if ($debug);
          print "  ".join("-->",TraceRoute($ip,$subnet))."\n" if ($debug);
          delete $subnets{$ip}; 
     }
}

#
# Scan internet gateway
print "--------------- SCAN INTERNET GATEWAY -------------------------------\n" if ($debug);
my @internetroute=TraceRoute("8.8.8.8","8.8.8.8/31");
print "INTERNET GATEWAY  ".join("-->",@internetroute)."\n" if ($debug);

#
# get default gateways & routes
print "--------------- RESCAN GATEWAYS & ROUTES -------------------------------\n" if ($debug);
foreach my $ipaddress (sort keys %subnets) {
     my $subnet=$subnets{$ipaddress};
     print "  IP=$ipaddress  ".join("-->",TraceRoute($ipaddress,$subnet))."\n\n" if ($debug);
}

#
# Add hostname to IP
sub NAME(@) {
     my $ipaddress=shift;
     my $name=$ipaddress;
     $name=$host{$ipaddress}{'hostname'}."\\n".$name if (exists $host{$ipaddress}{'hostname'});
     return $name;
}

#
# gather scanned and cached ip(s).
my %ipall;
foreach my $ipaddress (sort keys %subnets) {
     print "ipaddress=$ipaddress,subnet=$subnets{$ipaddress}\n"   if ($debug);
     $ipall{$ipaddress}=$subnets{$ipaddress};
}
foreach my $ipaddress (sort keys %ipcache) {
     print "ipaddress=$ipaddress,subnet=$ip2subnet{$ipaddress}\n" if ($debug);
     $ipall{$ipaddress}=$ip2subnet{$ipaddress};
}

#
# Compose subnet and host data
my @nodes;
my @links;
my $tabledata="";
foreach my $ipaddress (sort keys %ipall) {
     print "-------------->> $ipaddress is scanned\n" if ((exists $subnets{$ipaddress}) && ($debug));
     print "-------------->> $ipaddress is cached\n"  if ((exists $ipcache{$ipaddress}) && ($debug));
     my @basics;
     my @details;
     my @ports;
     my ($subnet,$hostname,$name,$gateway,$subnetmask,$devicetype,$running,$mac,$vendor,$status,$latency,$hop,$os_cpe,$os_details,$ports,$fact,$port,$link,$firstscanned,$lastscanned,$timesscanned,$totalscans,$color,$ostype);
     $subnet= $ip2subnet{$ipaddress};
     if (exists $subnets{$ipaddress}) {
          $gateway=   $gateway{$subnets{$ipaddress}}         if  (exists $gateway{$subnets{$ipaddress}});
          $subnetmask=$cidr{$subnet}{'subnetmask'}           if  (exists $cidr{$subnet});
          $hostname=  $host{$ipaddress}{'hostname'}          if  (exists $host{$ipaddress}{'hostname'});
          $devicetype=$host{$ipaddress}{'devicetype'}        if  (exists $host{$ipaddress}{'devicetype'});
          $running=   $host{$ipaddress}{'running'}           if  (exists $host{$ipaddress}{'running'});
          $running=~  s/(.{45,60}[^\s,]+)[\s,]+/$1\\n/g;
          $vendor=    $host{$ipaddress}{'vendor'}            if  (exists $host{$ipaddress}{'vendor'});
          $status=    $host{$ipaddress}{'status'}||"up";
          $latency=   $host{$ipaddress}{'latency'}           if  (exists $host{$ipaddress}{'latency'});
          $hop=       $host{$ipaddress}{'hops'}              if  (exists $host{$ipaddress}{'hops'});
          $os_cpe=    $host{$ipaddress}{'os_cpe'}            if  (exists $host{$ipaddress}{'os_cpe'});
          $os_cpe=~   s/(.{45,60}[^\s,]+)[\s,]+/$1\\n/g;
          $os_details=$host{$ipaddress}{'os_details'}        if  (exists $host{$ipaddress}{'os_details'});
          $os_details=~s/(.{45,60}[^\s,]+)[\s,]+/$1\\n/g;
          $ports=     $host{$ipaddress}{'ports'}             if  (exists $host{$ipaddress}{'ports'});
          $mac=       $host{$ipaddress}{'mac'}               if  (exists $host{$ipaddress}{'mac'});
          $mac=       $hostmac{$ipaddress}                   if ((exists $hostmac{$ipaddress}) && (!$mac));
          $fact=      join("\\n",@{$fact{$ipaddress}})       if ((exists $fact{$ipaddress}) && (@{$fact{$ipaddress}}));
          $fact=~     s/(.{45,60}[^\s,]+)[\s,]+/$1\\n/g;
          $port=      join("\\n",@{$port{$ipaddress}})       if ((exists $port{$ipaddress}) && (@{$port{$ipaddress}}));
          $firstscanned=strftime("%F %T", localtime);
          $lastscanned= strftime("%F %T", localtime);

          #
          # Gather host info 
          my $info="";
          $info.= $host{$ipaddress}{'os_cpe'}                if (exists $host{$ipaddress}{'os_cpe'});
          $info.= $host{$ipaddress}{'os_details'}            if (exists $host{$ipaddress}{'os_details'});
          $info.= $host{$ipaddress}{'vendor'}                if (exists $host{$ipaddress}{'vendor'});
          $info.= $host{$ipaddress}{'devicetype'}            if (exists $host{$ipaddress}{'devicetype'});
          $info.= $host{$ipaddress}{'http-title'}            if (exists $host{$ipaddress}{'http-title'});
          $info.= $host{$ipaddress}{'service_info'}          if (exists $host{$ipaddress}{'service_info'});
          $info.= $port                                      if ($port);

          #
          # Determine color, os and hosttype
          my ($c,$o,$d,$r)=(($host{$ipaddress}{'color'} || "gold"),"unknown",($devicetype||"unknown"));
          ($c,$o)=   ("tomato","unknown")                    if ($info =~ /hewlett\spackard/i);
          ($c,$o)=   ("lightgreen","unknown")                if ($info =~ /intel/i);
          ($c,$o)=   ("lightsalmon","Linux")                 if ($info =~ /linux/i);
          ($c,$o,$d)=("lime","IOS","media device|phone")     if ($info =~ /\bios|apple/i);
          ($c,$o,$d)=("green","Android","phone")             if ($info =~ /android|Motorola\sMobility/i);
          ($c,$o,$d)=("dodgerblue","Windows","general purpose") if ($info =~ /windows/i);
          ($c,$o,$d)=("chartreuse","Linux","switch")         if ($info =~ /switch|netgear/i);
          ($c,$o,$d)=("olivedrab","Android","phone")         if ($info =~ /oneplus/i);
          ($c,$o,$d)=("chocolate","Linux","router")          if ($info =~ /router/i);
          ($c,$o,$d)=("tomato","Linux","printer")            if ($info =~ /printer|laserjet/i);
          ($c,$o,$d)=("antiquewhite","Linux","nas")          if ($info =~ /Segate\sTechnology/i);
          ($c,$o,$r)=("orchid","Linux","Google Chrome Cast") if ($port =~ /chromecast/i);
          ($c,$o,$d,$r)=("sienna","Linux","bridge","philips hue bridge") if ($info =~ /Philips\sHue/i);
          ($c,$o,$r)=("yellowgreen","Linux","samsung tv")    if ($info =~ /Samsung\sAllShare/i);
          ($c,$o,$r)=("palevioletred","Linux","QNAP")        if ($info =~ /qnap/i);
          ($c,$o,$r)=("orangered","Linux","internet radio")  if ($info =~ /Internet\sRadio/i);
          $c=        "lightblue"                             if ($info =~ /raspberry/i);
          $c=        "orange"                                if  (exists $route{$ipaddress});
          $c=        "aquamarine"                            if ((exists $gateway{$subnet}) && ($gateway{$subnet} =~ /^$ipaddress$/));
          $color=$c;
          $ostype=$o;
          $devicetype=$d;
          $running=$r." ".$running if ($r);
 
          #
          # Remove cpe: and double words
          print ">>$os_cpe<< "   if ($debug);
          $os_cpe =~ s/cpe://g;
          print ">>$os_cpe<< "   if ($debug);
          $os_cpe =~ s/(\/?\b\S{4,50})\s*(.+)\1/${1}${2}\//i;
          print ">>$os_cpe<< \n" if ($debug);
     
          #
          # Gather basics, details and ports
          push(@basics, "Subnet: "       .$subnet);
          push(@basics, "Gateway: "      .$gateway)      if ($gateway);
          push(@basics, "Netmask: "      .$subnetmask)   if ($subnetmask);
          push(@basics, "Device type: "  .$devicetype)   if ($devicetype);
          push(@basics, "Running: "      .$running)      if ($running);
          push(@basics, "MAC: "          .$mac)          if ($mac);
          push(@basics, "MAC Vendor: "   .$vendor)       if ($vendor);
          push(@basics, "OS type: "      .$ostype)       if ($ostype);
          push(@details,"First Scanned: ".$firstscanned) if ($firstscanned);
          push(@details,"Last Scanned: " .$lastscanned)  if ($lastscanned);
          push(@details,"Times Scanned: "."first time");
          push(@details,"Status: "       .$status)       if ($status);
          push(@details,"Latency: "      .$latency)      if ($latency);
          push(@details,"Hops: "         .$hop)          if ($hop);
          push(@details,"OC CPE: "       .$os_cpe)       if ($os_cpe);
          push(@details,"OS Details: "   .$os_details)   if ($os_details);
          push(@details,"Warnings: "     .$fact)         if ($fact);
          push(@ports,                    $port)         if ($port);

          #
          # IP address and hostname
          $name=NAME($ipaddress);
     }

     #
     # Read host object from file
     if (exists $ipcache{$ipaddress}) {
          my $file=$ipcache{$ipaddress};
          print "READ CACHE FILE=$file\n" if ($debug);
          my @file=`cat $file`;
          foreach my $line (@file) {
               chomp($line);
               next if ($line=~/^\s*$/);
               my @var=split(/##/,$line);
               foreach my $var (@var) {
                    $var=~s/NEWLINE/\\n/g;
                    print "VAR=>>$var<<\n";
                    if (exists $subnets{$ipaddress}) {
                         #
                         # Host is scanned
                         my $h=$1 if ($var =~ /HOSTNAME:(.+)$/);
                         my $m=$1 if ($var =~ /MAC:(.+)$/);
                         my $d=$1 if ($var =~ /DEVICETYPE:(.+)$/);
                         my $r=$1 if ($var =~ /RUNNING:(.+)$/);
                         if ((($h) && ($hostname)   && ($h !~ /^$hostname$/))   ||
                             (($m) && ($mac)        && ($m !~ /^$mac$/))        ||
                             (($d) && ($devicetype) && ($d !~ /^$devicetype$/)) ||
                             (($r) && ($running)    && ($r !~ /^$running$/))) {
                              print "Cache file does not match scanned host $ipaddress! Cache file $file will be removed!\n" if ($debug);
                              unlink($file);
                         } else {
                              if ($var =~ /TIMESSCANNED:(.+)$/) {
                                   $timesscanned=$1;
                                   if ($timesscanned=~ /^(\d+)\/(\d+)$/) {
                                        ($timesscanned,$totalscans)=($1,$2);
                                   } elsif ($timesscanned=~/^(\d+)$/) {
                                        ($timesscanned,$totalscans)=($1,$1);
                                   } else {
                                        ($timesscanned,$totalscans)=(1,1);
                                   }
                                   $totalscans+=1;
                                   $timesscanned+=1;
                              }
                              $firstscanned=$1   if ($var =~ /FIRSTSCANNED:(.+)$/);
                              foreach my $index (0 .. $#details) {
                                   $details[$index]=~s/Times\sScanned:.*$/Times Scanned: $timesscanned\/$totalscans/g;
                                   $details[$index]=~s/First\sScanned:\s.+$/First Scanned: $firstscanned/g;
                              }
                         }
                    } else {
                         #
                         # Host is down
                         @basics      =split(/@@/,$1) if ($var =~ /BASICS:(.+)\z/sm);
                         @details     =split(/@@/,$1) if ($var =~ /DETAILS:(.+)\z/sm);
                         @ports       =split(/@@/,$1) if ($var =~ /PORTS:(.+)\z/sm);
                         $name        =$1             if ($var =~ /^NAME:(.+)\z/sm);
                         $color       =$1             if ($var =~ /COLOR:(.+)$/);
                         $subnet      =$1             if ($var =~ /SUBNET:(.+)$/);
                         $hostname    =$1             if ($var =~ /HOSTNAME:(.+)$/);
                         $mac         =$1             if ($var =~ /MAC:(.+)$/);
                         $vendor      =$1             if ($var =~ /VENDOR:(.+)$/);
                         $subnetmask  =$1             if ($var =~ /SUBNETMASK:(.+)$/);
                         $gateway     =$1             if ($var =~ /GATEWAY:(.+)$/);
                         $devicetype  =$1             if ($var =~ /DEVICETYPE:(.+)$/);
                         $ostype      =$1             if ($var =~ /OSTYPE:(.+)$/);
                         $running     =$1             if ($var =~ /RUNNING:(.+)$/);
                         $hop         =$1             if ($var =~ /HOP:(.+)$/);
                         $os_cpe      =$1             if ($var =~ /OS_CPE:(.+)\z/sm);
                         $os_details  =$1             if ($var =~ /OS_DETAILS:(.+)\z/sm);
                         $ports       =$1             if ($var =~ /PORTS:(.+)\z/sm);
                         $link        =$1             if ($var =~ /LINK:(.+)\z/sm);
                         $firstscanned=$1             if ($var =~ /FIRSTSCANNED:(.+)$/);
                         $lastscanned =$1             if ($var =~ /LASTSCANNED:(.+)$/);
                         if ($var =~ /TIMESSCANNED:(.+)$/) {
                              $timesscanned=$1;
                              if ($timesscanned=~ /^(\d+)\/(\d+)$/) {
                                   ($timesscanned,$totalscans)=($1,$2);
                              } elsif ($timesscanned=~/^(\d+)$/) {
                                   ($timesscanned,$totalscans)=($1,$1);
                              } else {
                                   ($timesscanned,$totalscans)=(1,1);
                              }
                              $totalscans+=1;
                         }
                         $status      ="down";
                         foreach my $index (0 .. $#details) {
                              $details[$index]=~s/Times\sScanned:.*$/Times Scanned: $timesscanned\/$totalscans/g;
                              $details[$index]=~s/Status:\s.+$/Status: down/g;
                         }
                    }
               }
          }
          print "IPADDRESS=$ipaddress, TIMES_SCANNED=$timesscanned/$totalscans, FIRST_SCANNED=$firstscanned, LAST_SCANNED=$lastscanned, STATUS=$status, FILE=$file\n" if ($debug);
          $timesscanned="$timesscanned/$totalscans";
     }

     #
     # Save links between hostobjects
     if ($link) {
          print "PUSH LINK FROM CACHE: -->>$link<<-- \nNAME: -->>$name<<--\n";
          push(@links,$link);
     } elsif ((exists $gateway{$ipall{$ipaddress}}) && (NAME($gateway{$ipall{$ipaddress}}) !~ /${name}/)) {
          $link="{ from: \"${name}\", to: \"".NAME($gateway{$ipall{$ipaddress}})."\" }";
          print "PUSH NEW CREATED LINK: -->>$link<<--\nNAME: -->>$name<<--\n";
          push(@links,$link);
     } else {
          print "NO LINK PUSHED! NAME [".NAME($gateway{$ipall{$ipaddress}})."] matches [".$name."]! Gateway=".($gateway{$ipaddress}||"none").", subnet=".$ipall{$ipaddress}.", gateway=".$gateway{$ipall{$ipaddress}}.", ip=$ipaddress\n";
     }

     # 
     # Store host objects
     push(@nodes,"{ key:  \"${name}\", basics: \"".join("\\n",@basics)."\", details: \"".join("\\n",@details)."\",ports: \"".join("\\n",@ports)."\", color: \"$color\", category: \"name\" }");

     #
     # Write to cache file
     if (exists $subnets{$ipaddress}) {
          my $output="##BASICS:"      .join("@@",@basics).
                     "##DETAILS:"     .join("@@",@details).
                     "##PORTS:"       .join("@@",@ports).
                     "##NAME:"        .$name.
                     "##COLOR:"       .$color.
                     "##SUBNET:"      .$subnet.
                     "##HOSTNAME:"    .($hostname    ||"").
                     "##MAC:"         .($mac         ||"").
                     "##VENDOR:"      .($vendor      ||"").
                     "##SUBNETMASK:"  .($subnetmask  ||"").
                     "##GATEWAY:"     .($gateway     ||"").
                     "##DEVICETYPE:"  .($devicetype  ||"").
                     "##OSTYPE:"      .($ostype      ||"").
                     "##RUNNING:"     .($running     ||"").
                     "##HOP:"         .($hop         ||"").
                     "##OS_CPE:"      .($os_cpe      ||"").
                     "##OS_DETAILS:"  .($os_details  ||"").
                     "##PORTS:"       .($ports       ||"").
                     "##LINK:"        .($link        ||"").
                     "##FIRSTSCANNED:".($firstscanned||strftime("%F %T", localtime)).
                     "##LASTSCANNED:" .($lastscanned ||strftime("%F %T", localtime)).
                     "##TIMESSCANNED:".($timesscanned||"1/1")."##";
          $output=~s/\Q\n\E/NEWLINE/gm;
          my $datafile="nmapdata/$ipaddress";
          $datafile=~s/\./_/g;
          $datafile.=".txt";
          open my $out, '>', "$datafile" or die "Can't write '$datafile' file: $!";
          print $out $output;
          close $out;
     }

     # 
     # construct html table row
     $tabledata.='  <tr bgcolor="'.$color.'">
    <td>'.($status      ||"" ).'</td>
    <td>'.($firstscanned||"" ).'</td>
    <td>'.($lastscanned ||"" ).'</td>
    <td>'.($timesscanned||"1").'</td>
    <td>'.($subnet      ||"" ).'</td>
    <td>'.($hostname    ||"" ).'</td>
    <td>'.($ipaddress   ||"" ).'</td>
    <td>'.($mac         ||"" ).'</td>
    <td>'.($vendor      ||"" ).'</td>
    <td>'.($subnetmask  ||"" ).'</td>
    <td>'.($gateway     ||"" ).'</td>
    <td>'.($devicetype  ||"" ).'</td>
    <td>'.($ostype      ||"" ).'</td>
    <td>'.($running     ||"" ).'</td>
    <td>'.($hop         ||'0' ).'</td>
    <td>'.($os_cpe      ||"" ).'</td>
    <td>'.($os_details  ||"" ).'</td>
    <td>'.($ports       ||"" ).'</td>
  </tr>
';
}

#
# Add Internet host object + link
if ($internetgateway) {
     push(@nodes,"{ key:  \"Internet Gateway\", basics: \"Hops:".join("\\n",@internetroute)."\", details: \"".join("--->",@internetroute)."\",ports: \"*any*\", color: \"yellow\", category: \"name\" }");
     push(@links,"{ from: \"".NAME($internetgateway)."\", to: \"Internet Gateway\" }");
}

#
# Add link for each routes
foreach my $route (keys %route) {
     next if (! exists $subnets{$route});
     my $gateway=$route{$route};
     next if (! exists $subnets{$gateway});
     if ($gateway =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
          push(@links,"{ from: \"".NAME($gateway)."\", to: \"".NAME($route)."\" }");
     }
}


#
# Add data to map.html
my $node= "diagram.model.nodeDataArray = [".join(",",@nodes)."];";
my $link= "diagram.model.linkDataArray = [".join(",",@links)."];";
#
# Open output file
open my $out, '>', "map.html" or die "Can't write map.html file: $!";
#
# Read html data from __DATA__
while( <DATA> )
     {
     # Insert host data and links
     s/^\s*diagram\.model\.nodeDataArray\s=\s\[.+$/${node}/g;
     s/^\s*diagram\.model\.linkDataArray\s=\s\[.+$/${link}/g;
     s/^INSERTTABLEDATA/${tabledata}/;
     print $out $_;
}

close $out;

#
# End for perl script
exit

#
# HTML data for map.html 
__DATA__
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="Nmap Scan" >
  <title>Nmap scan</title>
  <script src="go.js"></script>
  <script id="code">
var head = document.getElementsByTagName("head")[0];

function goCode(pre, w, h, diagramclass, parentid) {
  if (diagramclass === undefined) diagramclass = go.Diagram;
  if (typeof pre === "string") pre = document.getElementById(pre);
  var div = document.createElement("div");
  div.style.width = w + "%";
  div.style.height = h + "px";
  div.className = "diagramStyling";
  var parent;
  if (parentid === undefined) {
    parent = pre.parentNode;
  } else {
    parent = document.getElementById(parentid);
  }
  parent.appendChild(div);
  var f = eval("(function (diagram, $) {" + pre.textContent + "})");
  f(new diagramclass(div), go.GraphObject.make);
}

function goIntro() {
  _traverseDOM(document);
}

function _traverseDOM(node) {
  if (node.nodeType === 1 && node.nodeName === "A" && !node.getAttribute("href")) {
    var text = node.innerHTML.split(".");
    if (text.length === 1) {
      node.setAttribute("href", "../api/symbols/" + text[0] + ".html");
      node.setAttribute("target", "api");
    } else if (text.length === 2) {
      node.setAttribute("href", "../api/symbols/" + text[0] + ".html" + "#" + text[1]);
      node.setAttribute("target", "api");
    } else {
      alert("Unknown API reference: " + node.innerHTML);
    }
  }
  for (var i = 0; i < node.childNodes.length; i++) {
    _traverseDOM(node.childNodes[i]);
  }
}

  </script>
</head>
<body onload="goIntro()">
<div id="content">


<h2 id="ChangingCategoryOfPart">Network map</h2>
<script data-language="javascript" id="changingCategory">
  function changeCategory(obj, category) {
    var node = obj.part;
    if (node) {
      var diagram = node.diagram;
      diagram.startTransaction("changeCategory");
      diagram.model.setCategoryForNodeData(node.data, category);
      diagram.commitTransaction("changeCategory");
    }
  }

  var name=
    $(go.Node, "Spot",
      $(go.Panel, "Auto",
        $(go.Shape, "RoundedRectangle",
          new go.Binding("fill", "color")),
        $(go.TextBlock, { row: 0, column: 0, columnSpan: 2, font: "bold 10pt sans-serif" },
          new go.Binding("text", "key"))
      ),
      $("Button",
        { alignment: go.Spot.TopRight },
        $(go.Shape, "ThinCross", { width: 3, height: 3 }),
          { click: function(e, obj) { changeCategory(obj,'basics');} }),
      $("Button",
        { alignment: go.Spot.TopLeft },
        $(go.Shape, "ThinCross", { width: 3, height: 3 }),
          { click: function(e, obj) { changeCategory(obj,'ports');} }),
      $("Button",
        { alignment: go.Spot.BottomRight },
        $(go.Shape, "ThinCross", { width: 3, height: 3 }),
          { click: function(e, obj) { changeCategory(obj,'details');} })
    );

  var basics =
    $(go.Node, "Spot",
      $(go.Panel, "Auto",
        $(go.Shape, "RoundedRectangle",
          new go.Binding("fill", "color")),
        $(go.Panel, "Table",
          { defaultAlignment: go.Spot.Left },
          $(go.TextBlock, { row: 0, column: 0, columnSpan: 2, font: "bold 10pt sans-serif" },
            new go.Binding("text", "key")),
          $(go.TextBlock, { row: 1, column: 0, font: "bold 10pt sans-serif" }, "Basics:"),
          $(go.TextBlock, { row: 1, column: 1 }, new go.Binding("text", "basics"))
        )
      ),
      $("Button",
        { alignment: go.Spot.TopRight },
        $(go.Shape, "CircleLine", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'name');} }),
     $("Button",
        { alignment: go.Spot.TopLeft },
        $(go.Shape, "ThinCross", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'ports');} }),
     $("Button",
        { alignment: go.Spot.BottomRight },
        $(go.Shape, "ThinCross", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'details');} })
    );

  var ports =
    $(go.Node, "Spot",
      $(go.Panel, "Auto",
        $(go.Shape, "RoundedRectangle",
          new go.Binding("fill", "color")),
        $(go.Panel, "Table",
          { defaultAlignment: go.Spot.Left },
          $(go.TextBlock, { row: 0, column: 0, columnSpan: 2, font: "bold 10pt sans-serif" },
            new go.Binding("text", "key")),
          $(go.TextBlock, { row: 1, column: 0, font: "bold 10pt sans-serif" }, "ports:"),
          $(go.TextBlock, { row: 1, column: 1,font: "10pt monospace" }, new go.Binding("text", "ports"))
        )
      ),
      $("Button",
        { alignment: go.Spot.TopRight },
        $(go.Shape, "ThinCross", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'basics');} }),
     $("Button",
        { alignment: go.Spot.TopLeft },
        $(go.Shape, "CircleLine", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'name');} }),
     $("Button",
        { alignment: go.Spot.BottomRight },
        $(go.Shape, "ThinCross", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'details');} })
    );

var details =
    $(go.Node, "Spot",
      $(go.Panel, "Auto",
        $(go.Shape, "RoundedRectangle",
          new go.Binding("fill", "color")),
        $(go.Panel, "Table",
          { defaultAlignment: go.Spot.Left },
          $(go.TextBlock, { row: 0, column: 0, columnSpan: 2, font: "bold 10pt sans-serif" },
            new go.Binding("text", "key")),
          $(go.TextBlock, { row: 1, column: 0, font: "bold 10pt sans-serif" }, "Details:"),
          $(go.TextBlock, { row: 1, column: 1 }, new go.Binding("text", "details"))
        )
      ),
      $("Button",
        { alignment: go.Spot.TopRight },
        $(go.Shape, "ThinCross", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'basics');} }),
     $("Button",
        { alignment: go.Spot.TopLeft },
        $(go.Shape, "ThinCross", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'ports');} }),
     $("Button",
        { alignment: go.Spot.BottomRight },
        $(go.Shape, "CircleLine", { width: 4, height: 4 }),
          { click: function(e, obj) { changeCategory(obj,'name');} })
    );

  var templmap = new go.Map("string", go.Node);
  templmap.add("name", name);
  templmap.add("basics", basics);
  templmap.add("ports", ports);
  templmap.add("details", details);
  diagram.nodeTemplateMap = templmap;

  diagram.layout = $(go.ForceDirectedLayout,{ maxIterations: 200, defaultSpringLength: 20, defaultElectricalCharge: 80 });

diagram.model.nodeDataArray = [ ];
diagram.model.linkDataArray = [ ];
</script>
<script>goCode("changingCategory", 100, 600)</script>


</div>
<div>
<table id="hosts" style="width:100%">
 <thead>
  <tr>
    <th>Status</th>
    <th>First Scanned</th>
    <th>Last Scanned</th>
    <th>Times<br>Scanned</th>
    <th>Network</th>
    <th>Host name</th>
    <th>IP Address</th> 
    <th>MAC Address</th> 
    <th>MAC Vendor</th> 
    <th>Netmask</th>
    <th>Gateway</th>
    <th>Device type</th>
    <th>OS type</th>
    <th>Running</th>
    <th>Hops</th>
    <th>OS CP</th>
    <th>OS Details</th>
    <th>Ports</th>
  </tr>
 </thead>
 <tbody>
INSERTTABLEDATA
  </tbody>
</table>

<script src="tablefilter/tablefilter.js"></script>
<script data-config>
var tfConfig = {
    rows_counter_text: 'Number of hosts: ',
    btn_reset_text: "Clear",
    loader: true,
    no_results_message: true,
    base_path: './tablefilter/',
    col_0: 'select',
    col_4: 'select',
    col_8: 'select',
    col_9: 'select',
    col_10: 'select',
    col_11: 'select',
    col_12: 'select',
    col_14:'select',
    mark_active_columns: true,
    rows_counter: true,
    btn_reset: true,
    status_bar: true,
    col_widths: ["","100px","100px","","120px","120px","120px","180px","120px","120px","150px","150px","100px","10%","30px","10%","10%","10%"],
    col_types: [
       'string',
       'string',
       'string',
       'number',
       'string',
       'string',
       'ipaddress',
       'string',
       'string',
       'ipaddress',
       'ipaddress',
       'string',
       'string',
       'string',
       'number',
       'string',
       'string',
       'string'
       ],
    extensions: [{ name: 'sort' },
                 { name: 'colsVisibility',
                      at_start: [1,2,4,9,14,15,16,17],
                      text: 'Hide columns: ',
                      enable_tick_all: true}]
};
var tf = new TableFilter('hosts', tfConfig);
tf.init();
</script>

</div>
</body>
</html>



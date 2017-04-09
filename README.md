# nmap
scan &amp; visualize subnets

## Network diagram
[![nmap scan](https://raw.githubusercontent.com/tedsluis/nmap/master/nmapscan.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/nmapscan.jpg)
 
## Help
````
./nmapscan.pl -help
Help

Usage: 
       ./nmapscan.pl 
Optional:
       ./nmapscan.pl -subnet <cidr>[,<cidr>]                   Subnet(s) in CIDR notation.
       ./nmapscan.pl -debug                                    Display debug info.
       ./nmapscan.pl -help                                     This helptext.

Examples:
       ./nmapscan.pl -subnet 192.168.1.0/24,192.168.100.0/24

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
   - You may need to do sudo (to become root) to run nmap.

````



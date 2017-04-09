# nmap
Scans subnets using nmap and visualizes network topology in a browser.  
  
Table of Contents  
=================  

   * [nmap](#nmap)  
      * [Features](#features)
      * [Network diagram](#network-diagram)  
      * [Help](#help)  
      * [Display host properties](#display-host-properties)  
      * [Prerequisites](#prerequisites)  
      * [Installation instructions](#installation-instructions)
         * [Install Nmap](#install-nmap)
         * [Install Traceroute](#install-traceroute)
         * [Install Perl](#install-perl)
         * [Install Git](#install-git)
         * [Clone repo](#clone-repo)
  
## Features

* Performs OS detection and port scanning.
* Tracks subnet(s) gateways and route to internet.
* Shows network diagram of subnets with hosts.
* Use the mouse to drag the host objects around.
* Displays MAC address, vendor type, IP address, hostname, gateway, netmask, OS type, etc.
* Click on the icons in the corners of the host objects to display the host properties.

## Network diagram
[![nmap scan](https://raw.githubusercontent.com/tedsluis/nmap/master/img/nmapscan.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/nmapscan.jpg)
 
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

Example:
       ./nmapscan.pl -subnet 192.168.1.0/24,192.168.100.0/24

View result 'map.html' in a webbrowser.  

CIDR is <network>/<netbits>. 
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
   - You may need to do sudo (to become root) to run nmap: $ sudo ./nmapscan.pl -subnet 192.168.1.0/24
````
## Display host properties  
  
Click on the icons in the corners of the hosts to display the host properties. There are 3 different types: Basic, detailed and port properties.  
   
Top right corner: Basisc host info.  
[![nmap scan](https://raw.githubusercontent.com/tedsluis/nmap/master/img/basics_screenshot.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/basics_screenshot.jpg)
   
Bottom right corner: Host details:   
[![nmap scan](https://raw.githubusercontent.com/tedsluis/nmap/master/img/details_screenshot.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/details_screenshot.jpg)
    
Top left corner: Port host info:  
[![nmap scan](https://raw.githubusercontent.com/tedsluis/nmap/master/img/ports_screenshot.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/ports_screenshot.jpg)

## Prerequisites  

* nmap  
* traceroute  
* perl 
* root permissions  

note: If your system does not meet these requirements then follow the installation instructions.

## Installation instructions

### Install Nmap

### Install Traceroute

### Install Perl

### Install Git

### Clone repo




ted.sluis@gmail.com

  



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
         * [Install packages](#install-packages)
         * [Test packages](#test-packages)
         * [Clone repo](#clone-repo)
      * [Run nmapscan.pl](#run-nmapscanpl)
  
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
  
'nmapscan.pl' is a commandline script written in Perl. It creates 'map.html' which contains html, javascript and the network topology data.  
  
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
  
Click on the icons in the corners of the hosts object to display the host properties. There are 3 different types: Basic, detailed and port properties.  
   
Top right corner: Basisc host info.  
[![nmap scan basics](https://raw.githubusercontent.com/tedsluis/nmap/master/img/basics_screenshot.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/basics_screenshot.jpg)
   
Bottom right corner: Host details:   
[![nmap scan details](https://raw.githubusercontent.com/tedsluis/nmap/master/img/details_screenshot.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/details_screenshot.jpg)
    
Top left corner: Port host info:  
[![nmap scan ports](https://raw.githubusercontent.com/tedsluis/nmap/master/img/ports_screenshot.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/img/ports_screenshot.jpg)

## Prerequisites  

* nmap  
* traceroute  
* perl 
* root permissions  

note: If your system does not meet these requirements then follow the installation instructions.

## Installation instructions

### Install packages
  
Ubuntu/Debian/Raspbian  
````
$ sudo apt-get install nmap traceroute perl git  
````
   
Centos/RHEL  
````
$ yum install nmap traceroute perl git  
````
  
Fedora  
````
$ dnf install nmap traceroute perl git 
````
   
### Test packages  
  
To test nmap (specify our own subnet):  
````
$ nmap -O -n 192.168.1.0/24  
````
  
To test traceroute:  
````
$ traceroute 8.8.8.8   
````
   
### Clone repo  
  
Clone the repo to your locale host:
````
$ mkdir ~/git
$ cd ~/git
$ git clone https://github.com/tedsluis/nmap.git
$ cd ~/git/nmap
````
    
## Run nmapscan.pl
  
To run it (specify our own subnets):  
````
$ ./nmapscan.pl -subnet 192.168.1.0/24,192.168.11.0/24 

Interface=enp2s0 (ip=192.168.11.80)
Interface=virbr0 (ip=192.168.122.1)
Host gateway=192.168.11.1
  192.168.1.0/24   (subnetwork=192.168.1.0/24,   netbit=24, subnetmask=255.255.255.0, network=192.168.1.0,   broadcast=192.168.1.255),   number of IP's=254
  192.168.11.0/24  (subnetwork=192.168.11.0/24,  netbit=24, subnetmask=255.255.255.0, network=192.168.11.0,  broadcast=192.168.11.255),  number of IP's=254
  192.168.122.1/24 (subnetwork=192.168.122.0/24, netbit=24, subnetmask=255.255.255.0, network=192.168.122.0, broadcast=192.168.122.255), number of IP's=254
````
Depeding on your system and network this will take quite a while!    
Ones it is finshed you can view 'map.html' is a web browser.  
  
## Video  
  
<iframe width="560" height="315" src="https://www.youtube.com/embed/DMpabcP0r_U" frameborder="0" allowfullscreen></iframe> 
  
ted.sluis@gmail.com

  



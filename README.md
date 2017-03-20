# nmap
scan &amp; visualize subnets

## Network diagram
[![nmap scan](https://raw.githubusercontent.com/tedsluis/nmap/master/nmapscan.jpg)](https://raw.githubusercontent.com/tedsluis/nmap/master/nmapscan.jpg)
 
## Help
````
./nmapscan.pl -help
Help

usage: 
       ./nmapscan.pl 
optional:
       ./nmapscan.pl -ip <subnet>|<ip address>[,<subnet>|<ip address>]    Scan subnet(s) and/or ip address(es).
       ./nmapscan.pl -gw <ip address>,[<ip addres>]                       Specify default gateway(s).
       ./nmapscan.pl -debug                                               Display debug info.
       ./nmapscan.pl -help                                                This helptext.

examples:
       ./nmapscan.pl -ip 192.168.1.0/24,192.168.100.0/24
       ./nmapscan.pl -ip 192.168.1.254,192.168.1.1
       ./nmapscan.pl -ip 192.168.1.0/24 -gw 192.168.1.254

view result 'map.html' in a webbrowser.

note: - be sure you have installed nmap!
      - you need root (or sudo) to run ./nmapscan.pl
````

//Updated 3Feb2016
//@Slacker007 
/*							Hunt Team Field Manual 
**************************************************************************************************
1.) OS Stats
$ ifconfig eth0; ifconfig -a 
$ netstat -ni 
$ netstat -s
$ cat /proc/net/dev | columns -t 
$ awk '{ print $1,$5 }' /proc/net/dev
$ watch -n 1 cat /proc/interrupts 
$ watch -n 1 cat /proc/softirqs
$ vmstat -S m 1
$ ifpps --dev eth0
***************************************************************************************************
2.) Ethtool - NIC Configuration
Show            ;           Set 
$ ethtool -S eth0 // Statistics
$ ethtool -S eth0 | egrep '(rx_missed|no_buffer)'    // Drop Values  
$ ethtool -g eth0 ; ethtool -G eth0 rx 4096 tx 4096 // FIFO RX Descriptors
$ ethtool -k eth0 ; ethtool -K gro on gso on rx on // Offloading
$ ethtool -a eth0 ; ethtool -A rx off autoneg off // Pause Frames
$ ethtool -c eth0 ; ethtool -C eth0 rx-usecs 100 // Interrupt Coalescence 
***************************************************************************************************
3.) More OS Configurables
$ cat /proc/net/softnet_stats; printf "%d" 0xffff //Backlog Queue Stats
$ echo "1" > /proc/sys/net/core/bpf_jit_enable
$ sysctl net.core.netdev_max_backlog; sysctl -w net.core.netdev_max_backlog=3000
$ sysctl net.core.wmem_max; sysctl net.core.rmem_max 
$ sysctl net.core.wmem_default; sysctl net.core.rmem_default 
$ sysctl net.core.optmem_max
$ echo "net.core.netdev_max_backlog=1024" >>  /etc/sysctl.conf
****************************************************************************************************
4.) Example NIC Driver Configuration
$ /etc/modprobe.d# cat e1000.conf
options e1000 XsumRX=0,0,0,0,0 TxDescriptors=48,48,48,48,48  RxDescriptors=4096,4096,4096,4096,4096 FlowControl=0,0,0,0,0,1 InterruptThrottleRate=5000,5000,5000,5000,5000 debug=16
$ modinfo -p e1000
*/
TxDescriptors:Number of transmit descriptors (array of int)
RxDescriptors:Number of receive descriptors (array of int)
Speed:Speed setting (array of int)
Duplex:Duplex setting (array of int)
AutoNeg:Advertised auto-negotiation setting (array of int)
FlowControl:Flow Control setting (array of int)
XsumRX:Disable or enable Receive Checksum offload (array of int)
TxIntDelay:Transmit Interrupt Delay (array of int)
TxAbsIntDelay:Transmit Absolute Interrupt Delay (array of int)
RxIntDelay:Receive Interrupt Delay (array of int)
RxAbsIntDelay:Receive Absolute Interrupt Delay (array of int)
InterruptThrottleRate:Interrupt Throttling Rate (array of int)
SmartPowerDownEnable:Enable PHY smart power down (array of int)
copybreak:Maximum size of packet that is copied to a new buffer on receive (uint)
debug:Debug level (0=none,...,16=all) (int)
*/
*******************************************************************************
5.) Basic TCPdump Usage
// name resolution off (-n) 
$ tcpdump -c 10 -s0 -nni eth0 -w file.pcap
$ tcpdump -c 10 -eXXvnnr file.pcap
********************************************************************************
7.) PCAP Header, Redirection, & Reading Multiple Files
$ cat file.pcap | tcpdump -nnr -  
$ cat file1.pcap file2.pcap | tcpdump -nnr -  // doesn't work - bogus save file error
// pcap version 2.4 header is 24 bytes
$ dd if=file2.pcap of=new.pcap bs=1 skip=24; cat file1.pcap new.pcap | tcpdump -nnr - 
$ tail -c +25 file2.pcap > new-cut.pcap; cat file1.pcap file2.pcap | tcpdump -nnr - 
$ (cat file1.pcap ; ( tail -c +25 file1.pcap | cat )) | tcpdump -nnr -
$ (cat file1.pcap ; ( tail -c +25 ; cat ) <file2.pcap) | tcpdump -nnr -
$ (cat file1.pcap; (dd bs=24 count=0 skip=1; cat) <file2.pcap) | tcpdump -nnr -
$ (cat test.pcap; (dd bs=24 count=0 skip=1 2>/dev/null; cat) <test1.pcap;  \ 
(dd bs=24 count=0 skip=1 2>/dev/null; cat) <test.pcap ) | tcpdump -nnr - 
// Linux cooked PCAP - uses pseudo linux-layer header
$ tcpdump -nni any -c 10 -w cooked.pcap
$ file cooked.pcap
********************************************************************************
8.) Mergecap
$ mergecap file1.pcap file2.pcap file3.pcap -w combined.pcap
$ mergecap -F // shows formats
$ mergecap -F libpcap *.pcap -w combine_all.pcap
$ mergecap -v -F pcap /dir/with/pcaps/* -w /path/to/rolled/file.pcap
$ mergecap -a -F libpcap *.pcap -w - | tcpdump -nnr - // don't arrange TS
*********************************************************************************
9.) PCAP Statistical Data
capinfos file.pcap
tcpslice -r file.pcap
tcpdstat file.pcap
tcpprof -S lipn -P 30000 -r file.pcap
**********************************************************************************
9.) BPF (Berkely Packet Filters)
// see print out of  
// http://staff.washington.edu/dittrich/talks/core02/tools/tcpdump-filters.txt
// http://www.wains.be/pub/networking/tcpdump_advanced_filters.txt
// proper shell input with '' 
$ tcpdump -nni eth0 '((ip) and ((host 192.168.1.1 or 192.168.1.2) \
and not (host 192.168.1.254 and 192.168.1.253)) \
and (port 80 or 443 or 53))' 
// proper shell input with escapes "\"
$ tcpdump -nni eth0 \(\(ip\) and \(\(host 192.168.1.1 or 192.168.1.2\) \
and not \(host 192.168.1.254 and 192.168.1.253\)\) \
and \(port 80 or 443 or 53\)\)

**$ tcpdump -dd (ip and host 10.10.10.8 and port 8080) > C_Style.bpf // EASIEST WAY TO CREATE C_Style BPF!!!

*********************************************************************************
10.) Number System Conversions
$ printf "%d" 0x2d
$ printf "%x" 45
$ printf '\x47\x45\x54\x0a'
$ echo "GET" | hexdump -c 
$ echo "GET" | hexdump -C 
**********************************************************************************
11.) Session & Flow Data
iftop -i eth0.pcap // live only, replay for same effect
// use -i instead of -r for interface
$ tcpflow -c -e -r file.pcap 'tcp and port (80 or 443)'
$ tcpflow -r file.pcap tcp and port \(80 or 443\)
$ tcpick -r file.pcap -C -yP -h 'port (25 or 587)'
// [-wRu] write both flows; [-wRC] write client flows only ; [-wRS] write server flows only
$ tcpick -r file.pcap -wRu 
// Audit Record Generation And Utilization System
$ argus -r file.pcap -w file.argus
$ ra -nnr file.argus ; ra -Z b -nnr file.argus
$ ra -nnr file.argus - host 192.168.1.1 and port 80
$ racluster -M rmon -m saddr -r file.argus
$ ra -nnr file.argus -w - - port 22 | racluster -M rmon -m saddr -r - | rasort -m bytes -r -
$ racluster -M rmon -m proto -r file.argus -w - | rasort -m pkts -r - 
$ racluster -M rmon -m proto sport -r file.argus
$ ragraph bytes -M 30s -r file.argus -w bytes.png
$ ragraph pkts -M 30s -r file.argus -w pkts.png
$ ra -nnr file2.argus -s saddr,daddr,loss | sort -nr -k 3 | head -20
$ ragraph dbytes sbytes -M 30s -r file.argus - dst port 80 and dst port 443
$ ragraph dbytes sbytes dport sport -fill -M 30s -r file.argus
*********************************************************************************
12.) Network Forensics - File Extraction
$ tcpdump -nni eth0 -w image.pcap port 80 &
$ wget http://upload.wikimedia.org/wikipedia/en/5/55/Bsd_daemon.jpg
$ jobs
$ kill %1
$ tcpflow -r image.pcap
$ foremost -v 192.168.001.002.36130-208.080.152.211.00080 \
208.080.152.211.00080-192.168.001.006.36130
$ cd output/jpg; ls *.jpg; gqview *.jpg
$ tcpxtract -f file.pcap -o xtract/
*********************************************************************************
13.) Visualizations and Statistical Data
// Statistics w/ RRDtool graphs
$ ntop -f file.pcap -w 80 -W 443
$ ntop -u <user> -X <max TCP Sessions #increase for larger packets default 32768> \

$ /usr/sbin/ntop -w 80 -W 443 -4 -d -u ntop \
-t 0 -X --use-syslog=local7 -b -C \
--output-packet-path=/var/log/ntop --create-other-packets \
--create-suspicious-packets --local-subnets \
192.168.1.0/24,192.168.2.0/24 \
-o -p /etc/ntop/protocol.list -f file.pcap
**********************************************************************************
13.) Replay
tcpreplay -M10 -i eth0 file.pcap
netsniff-ng --in file.pcap --out eth0
netsniff-ng --in eth0.pcap --out eth1.pcap
trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0
**********************************************************************************
14.) IDS - Offline Analysis
snort -r file.pcap --pcap-filter='ip and tcp' -c /etc/snort/snort.conf -l .
u2spewfoo snort.unified2.* > alert.txt
bro -r file.pcap -f ip
bro-cut service proto id.resp_p id.resp_h < conn.log | head   // print out fields
bro-cut service < conn.log | sort | uniq -c | sort -n        // most used service
bro-cut user_agent < http.log | sort -u                     // list unique of user agent strings
bro-cut mime_type < http.log | sort -u                     // list unique MIME types
bro-cut service id.resp_p id.resp_h < conn.log \
	| awk '$1 == "http" && ! ($2 == 80 || $2 == 8080) { print $3 }' \
	| sort -u // find web traffic not on port 80 or 8080


bro-cut id.resp_p id.resp_h id.orig_p < dns.log \		//use to find all DNS servers
	| awk ’$1 == 53 { print $2, $3 }’ \  # Basic DNS only
	| sort | uniq -d \  # Duplicate source ports
	| awk ’{ print $1 }’ | uniq \  # Extract unique hosts


bro-cut id.resp_p id.orig_h id.orig_p < dns.log \              // use to find uniq hosts communicating to DNS from within
	| awk ’$1 == 53 { print $2, $3 }’ \  # Basic DNS only
	| sort | uniq -d \  # Duplicate source ports
	| awk ’{ print $1 }’ | uniq \  # Extract unique hosts




************************************************************************************
15.) Editing PCAPs
# change MAC's 
tcprewrite --enet-dmac=00:44:66:FC:29:AF,00:55:22:AF:C6:37
--enet-smac=00:66:AA:D1:32:C2,00:22:55:AC:DE:AC --infile=in.pcap
--outfile=out.pcap
# randomize IP's
tcprewrite --seed=423 --infile=in.pcap --outfile=out.pcap
# randomize IP's in argus files
ranonymize -r in.argus -w out.argus

************************************************************************************
16.) Windows CL Kung-Fu 
for %i in (*.txt) do type %i  /// For loop to display contents of all txt files in current dir to stdout
for %i in (*.txt) do type %i | findstr admin /// loop through all txt files searching for string (admin)


************************************************************************************
17.) File Hashing / Known Malware Detection 

md5deep -r / > hashlist.txt													// create a 2 column file containing hashes for each file with the absolute path

touch mainlist; touch hitlist; cat hashlist.txt | while read hashes; do whois -h hash.cymru.com $hashes >> mainlist; done & 	// Create file:mainlist to ingest results cat list of file hashes, piping output to \
																read command line by line & running search of each hash against cymru online database\
																and appending results to mainlist and ultimately backgrounding the process.
watch "cat mainlist | grep -v NO_DATA > hitlist | cat hitlist"									// watch the previous commands results at the default (2 second) interval







******************************************************
COMMON TTL'S (CAN BE MODIFIED/MANIPULATED)
******************************************************
+--------------------+-------+---------+---------+
| OS Version	     |"safe" | tcp_ttl | udp_ttl |
+--------------------+-------+---------+---------+
  AIX			  n	 60	   30
  DEC Pathworks V5	  n	 30	   30
  FreeBSD 2.1R		  y	 64	   64
  HP/UX	 9.0x		  n	 30	   30
  HP/UX	10.01		  y	 64	   64
  Irix 5.3		  y	 60	   60
  Irix 6.x		  y	 60	   60
  Linux		 	  y	 64	   64
  MacOS/MacTCP 2.0.x	  y	 60	   60
  OS/2 TCP/IP 3.0	  y	 64	   64
  OSF/1 V3.2A		  n	 60	   30
  Solaris 2.x		  y	255	  255
  Cisco IOS               y     255       255
  SunOS 4.1.3/4.1.4	  y	 60	   60
  Ultrix V4.1/V4.2A	  n	 60	   30
  VMS/Multinet		  y	 64	   64
  VMS/TCPware		  y	 60	   64
  VMS/Wollongong 1.1.1.1  n	128	   30
  VMS/UCX (latest rel.)	  y	128	  128
  MS WfW		  n	 32	   32
  MS Windows 95		  n	 32	   32
  MS Windows NT 3.51      n	 32	   32
  MS Windows NT 4.0       y	128	  128

*******************************************************
DEFAULT PORT SERVICE LISTING TCP/UDP
*******************************************************

TEC 236
Default TCP Ports

TCP  0  Reserved
TCP  1  Port Service Multiplexer
TCP  2  Management Utility
TCP  3  Compression Process
TCP  4  Unassigned
TCP  5  Remote Job Entry
TCP  6  Unassigned
TCP  7  Echo
TCP  8  Unassigned
TCP  9  Discard
TCP  10  Unassigned
TCP  11  Active Users
TCP  12  Unassigned
TCP  13  Daytime (RFC 867)
TCP  14  Unassigned
TCP  15  Unassigned [was netstat]
TCP  16  Unassigned
TCP  17  Quote of the Day
TCP  18  Message Send Protocol
TCP  19  Character Generator
TCP  20  File Transfer [Default Data]
TCP  21  File Transfer Protocol [Control]
TCP  22  SSH Remote Login Protocol
TCP  23  Telnet
TCP  24  any private mail system
TCP  25  Simple Mail Transfer
TCP  26  Unassigned
TCP  27  NSW User System FE
TCP  28  Unassigned
TCP  29  MSG ICP
TCP  30  Unassigned
TCP  31  MSG Authentication
TCP  32  Unassigned
TCP  33  Display Support Protocol
TCP  34  Unassigned
TCP  35  any private printer server
TCP  36  Unassigned
TCP  37  Time / W32.Sober.I virus
TCP  38  Route Access Protocol
TCP  39  Resource Location Protocol
TCP  40  Unassigned
TCP  41  Graphics
TCP  42  Host Name Server
TCP  43  WhoIs
TCP  44  MPM FLAGS Protocol
TCP  45  Message Processing Module [recv]
TCP  46  MPM [default send]
TCP  47  NI FTP
TCP  48  Digital Audit Daemon
TCP  49  Login Host Protocol (TACACS)
TCP  50  Remote Mail Checking Protocol
TCP  51  IMP Logical Address Maintenance
TCP  52  XNS Time Protocol
TCP  53  Domain Name Server
TCP  54  XNS Clearinghouse
TCP  55  ISI Graphics Language
TCP  56  XNS Authentication
TCP  57  any private terminal access
TCP  58  XNS Mail
TCP  59  any private file service
TCP  60  Unassigned
TCP  61  NI MAIL
TCP  62  ACA Services
TCP  63  whois++
TCP  64  Communications Integrator (CI)
TCP  65  TACACS-Database Service
TCP  66  Oracle SQL*NET
TCP  67  Bootstrap Protocol Server
TCP  68  Bootstrap Protocol Client
TCP  69  Trivial File Transfer
TCP  70  Gopher
TCP  71  Remote Job Service
TCP  72  Remote Job Service
TCP  73  Remote Job Service
TCP  74  Remote Job Service
TCP  75  any private dial out service
TCP  76  Distributed External Object Store
TCP  77  any private RJE service
TCP  78  vettcp
TCP  79  Finger
TCP  80  World Wide Web HTTP
TCP  81  HOSTS2 Name Server / Bagle-AZ worm / Win32.Rbot worm
TCP  82  XFER Utility
TCP  83  MIT ML Device
TCP  84  Common Trace Facility
TCP  85  MIT ML Device
TCP  86  Micro Focus Cobol
TCP  87  any private terminal link
TCP  88  Kerberos
TCP  89  SU/MIT Telnet Gateway
TCP  90  DNSIX Securit Attribute Token Map
TCP  91  MIT Dover Spooler
TCP  92  Network Printing Protocol
TCP  93  Device Control Protocol
TCP  94  Tivoli Object Dispatcher
TCP  95  SUPDUP
TCP  96  DIXIE Protocol Specification
TCP  97  Swift Remote Virtural File Protocol
TCP  98  Linuxconf / TAC News
TCP  99  Metagram Relay
TCP  100  [unauthorized use]
TCP  101  NIC Host Name Server
TCP  102  MSExchangeMTA X.400 / ISO-TSAP Class 0
TCP  103  Genesis Point-to-Point Trans Net
TCP  104  ACR-NEMA Digital Imag. & Comm. 300
TCP  105  Mailbox Name Nameserver
TCP  106  3COM-TSMUX
TCP  107  Remote Telnet Service
TCP  108  SNA Gateway Access Server
TCP  109  Post Office Protocol - Version 2
TCP  110  Post Office Protocol - Version 3
TCP  111  SUN Remote Procedure Call
TCP  112  McIDAS Data Transmission Protocol
TCP  113  Authentication Service
TCP  114  Audio News Multicast
TCP  115  Simple File Transfer Protocol
TCP  116  ANSA REX Notify
TCP  117  UUCP Path Service
TCP  118  SQL Services
TCP  119  Network News Transfer Protocol
TCP  120  CFDPTKT
TCP  121  Encore Expedited Remote Pro.Call
TCP  122  SMAKYNET
TCP  123  Network Time Protocol
TCP  124  ANSA REX Trader
TCP  125  Locus PC-Interface Net Map Ser
TCP  126  Unisys Unitary Login
TCP  127  Locus PC-Interface Conn Server
TCP  128  GSS X License Verification
TCP  129  Password Generator Protocol
TCP  130  cisco FNATIVE
TCP  131  cisco TNATIVE
TCP  132  cisco SYSMAINT
TCP  133  Statistics Service
TCP  134  INGRES-NET Service
TCP  135  DCE endpoint resolution
TCP  136  PROFILE Naming System
TCP  137  NETBIOS Name Service
TCP  138  NETBIOS Datagram Service
TCP  139  NETBIOS Session Service
TCP  140  EMFIS Data Service
TCP  141  EMFIS Control Service
TCP  142  Britton-Lee IDM
TCP  143  Internet Message Access Protocol
TCP  144  Universal Management Architecture
TCP  145  UAAC Protocol
TCP  146  ISO-IP0
TCP  147  ISO-IP
TCP  148  Jargon
TCP  149  AED 512 Emulation Service
TCP  150  SQL-NET
TCP  151  HEMS
TCP  152  Background File Transfer Program
TCP  153  SGMP
TCP  154  NETSC
TCP  155  NETSC
TCP  156  SQL Service
TCP  157  KNET/VM Command/Message Protocol
TCP  158  PCMail Server
TCP  159  NSS-Routing
TCP  160  SGMP-TRAPS
TCP  161  SNMP
TCP  162  SNMPTRAP
TCP  163  CMIP/TCP Manager
TCP  164  CMIP/TCP Agent
TCP  165  Xerox
TCP  166  Sirius Systems
TCP  167  NAMP
TCP  168  RSVD
TCP  169  SEND
TCP  170  Network PostScript
TCP  171  Network Innovations Multiplex
TCP  172  Network Innovations CL/1
TCP  173  Xyplex
TCP  174  MAILQ
TCP  175  VMNET
TCP  176  GENRAD-MUX
TCP  177  X Display Manager Control Protocol
TCP  178  NextStep Window Server
TCP  179  Border Gateway Protocol
TCP  180  Intergraph
TCP  181  Unify
TCP  182  Unisys Audit SITP
TCP  183  OCBinder
TCP  184  OCServer
TCP  185  Remote-KIS
TCP  186  KIS Protocol
TCP  187  Application Communication Interface
TCP  188  Plus Five's MUMPS
TCP  189  Queued File Transport
TCP  190  Gateway Access Control Protocol
TCP  191  Prospero Directory Service
TCP  192  OSU Network Monitoring System
TCP  193  Spider Remote Monitoring Protocol
TCP  194  Internet Relay Chat Protocol
TCP  195  DNSIX Network Level Module Audit
TCP  196  DNSIX Session Mgt Module Audit Redir
TCP  197  Directory Location Service
TCP  198  Directory Location Service Monitor
TCP  199  SMUX
TCP  200  IBM System Resource Controller
TCP  201  AppleTalk Routing Maintenance
TCP  202  AppleTalk Name Binding
TCP  203  AppleTalk Unused
TCP  204  AppleTalk Echo
TCP  205  AppleTalk Unused
TCP  206  AppleTalk Zone Information
TCP  207  AppleTalk Unused
TCP  208  AppleTalk Unused
TCP  209  The Quick Mail Transfer Protocol
TCP  210  ANSI Z39.50
TCP  211  Texas Instruments 914C/G Terminal
TCP  212  ATEXSSTR
TCP  213  IPX
TCP  214  VM PWSCS
TCP  215  Insignia Solutions
TCP  216  Computer Associates Int'l License Server
TCP  217  dBASE Unix
TCP  218  Netix Message Posting Protocol
TCP  219  Unisys ARPs
TCP  220  Interactive Mail Access Protocol v3
TCP  221  Berkeley rlogind with SPX auth
TCP  222  Berkeley rshd with SPX auth
TCP  223  Certificate Distribution Center
TCP  224  masqdialer
TCP  242  Direct
TCP  243  Survey Measurement
TCP  244  inbusiness
TCP  245  LINK
TCP  246  Display Systems Protocol
TCP  247  SUBNTBCST_TFTP
TCP  248  bhfhs
TCP  256  RAP/Checkpoint SNMP
TCP  257  Check Point / Secure Electronic Transaction
TCP  258  Check Point / Yak Winsock Personal Chat
TCP  259  Check Point Firewall-1 telnet auth / Efficient Short Remote Operations
TCP  260  Openport
TCP  261  IIOP Name Service over TLS/SSL
TCP  262  Arcisdms
TCP  263  HDAP
TCP  264  BGMP / Check Point
TCP  265  X-Bone CTL
TCP  266  SCSI on ST
TCP  267  Tobit David Service Layer
TCP  268  Tobit David Replica
TCP  280  HTTP-mgmt
TCP  281  Personal Link
TCP  282  Cable Port A/X
TCP  283  rescap
TCP  284  corerjd
TCP  286  FXP-1
TCP  287  K-BLOCK
TCP  308  Novastor Backup
TCP  309  EntrustTime
TCP  310  bhmds
TCP  311  AppleShare IP WebAdmin
TCP  312  VSLMP
TCP  313  Magenta Logic
TCP  314  Opalis Robot
TCP  315  DPSI
TCP  316  decAuth
TCP  317  Zannet
TCP  318  PKIX TimeStamp
TCP  319  PTP Event
TCP  320  PTP General
TCP  321  PIP
TCP  322  RTSPS
TCP  333  Texar Security Port
TCP  344  Prospero Data Access Protocol
TCP  345  Perf Analysis Workbench
TCP  346  Zebra server
TCP  347  Fatmen Server
TCP  348  Cabletron Management Protocol
TCP  349  mftp
TCP  350  MATIP Type A
TCP  351  bhoetty (added 5/21/97)
TCP  352  bhoedap4 (added 5/21/97)
TCP  353  NDSAUTH
TCP  354  bh611
TCP  355  DATEX-ASN
TCP  356  Cloanto Net 1
TCP  357  bhevent
TCP  358  Shrinkwrap
TCP  359  Tenebris Network Trace Service
TCP  360  scoi2odialog
TCP  361  Semantix
TCP  362  SRS Send
TCP  363  RSVP Tunnel
TCP  364  Aurora CMGR
TCP  365  DTK
TCP  366  ODMR
TCP  367  MortgageWare
TCP  368  QbikGDP
TCP  369  rpc2portmap
TCP  370  codaauth2
TCP  371  Clearcase
TCP  372  ListProcessor
TCP  373  Legent Corporation
TCP  374  Legent Corporation
TCP  375  Hassle
TCP  376  Amiga Envoy Network Inquiry Proto
TCP  377  NEC Corporation
TCP  378  NEC Corporation
TCP  379  TIA/EIA/IS-99 modem client
TCP  380  TIA/EIA/IS-99 modem server
TCP  381  hp performance data collector
TCP  382  hp performance data managed node
TCP  383  hp performance data alarm manager
TCP  384  A Remote Network Server System
TCP  385  IBM Application
TCP  386  ASA Message Router Object Def.
TCP  387  Appletalk Update-Based Routing Pro.
TCP  388  Unidata LDM
TCP  389  Lightweight Directory Access Protocol / Internet Locator Service (ILS)
TCP  390  UIS
TCP  391  SynOptics SNMP Relay Port
TCP  392  SynOptics Port Broker Port
TCP  393  Data Interpretation System
TCP  394  EMBL Nucleic Data Transfer
TCP  395  NETscout Control Protocol
TCP  396  Novell Netware over IP
TCP  397  Multi Protocol Trans. Net.
TCP  398  Kryptolan
TCP  399  ISO Transport Class 2 Non-Control over TCP
TCP  400  Workstation Solutions
TCP  401  Uninterruptible Power Supply
TCP  402  Genie Protocol
TCP  403  decap
TCP  404  nced
TCP  405  ncld
TCP  406  Interactive Mail Support Protocol
TCP  407  Timbuktu
TCP  408  Prospero Resource Manager Sys. Man.
TCP  409  Prospero Resource Manager Node Man.
TCP  410  DECLadebug Remote Debug Protocol
TCP  411  Remote MT Protocol
TCP  412  NeoModus Direct Connect (Windows file sharing program) / Trap Convention Port
TCP  413  SMSP
TCP  414  InfoSeek
TCP  415  BNet
TCP  416  Silverplatter
TCP  417  Onmux
TCP  418  Hyper-G
TCP  419  Ariel
TCP  420  SMPTE
TCP  421  Ariel
TCP  422  Ariel
TCP  423  IBM Operations Planning and Control Start
TCP  424  IBM Operations Planning and Control Track
TCP  425  ICAD
TCP  426  smartsdp
TCP  427  Server Location
TCP  428  OCS_CMU
TCP  429  OCS_AMU
TCP  430  UTMPSD
TCP  431  UTMPCD
TCP  432  IASD
TCP  433  NNSP
TCP  434  MobileIP-Agent
TCP  435  MobilIP-MN
TCP  436  DNA-CML
TCP  437  comscm
TCP  438  dsfgw
TCP  439  dasp
TCP  440  sgcp
TCP  441  decvms-sysmgt
TCP  442  cvc_hostd
TCP  443  HTTP protocol over TLS/SSL
TCP  444  Simple Network Paging Protocol
TCP  445  Microsoft-DS
TCP  446  DDM-RDB
TCP  447  DDM-RFM
TCP  448  DDM-SSL
TCP  449  AS Server Mapper
TCP  450  TServer
TCP  451  Cray Network Semaphore server
TCP  452  Cray SFS config server
TCP  453  CreativeServer
TCP  454  ContentServer
TCP  455  CreativePartnr
TCP  456  macon-tcp
TCP  457  scohelp
TCP  458  apple quick time
TCP  459  ampr-rcmd
TCP  460  skronk
TCP  461  DataRampSrv
TCP  462  DataRampSrvSec
TCP  463  alpes
TCP  464  kpasswd
TCP  465  SMTPS
TCP  466  digital-vrc
TCP  467  mylex-mapd
TCP  468  proturis
TCP  469  Radio Control Protocol
TCP  470  scx-proxy
TCP  471  Mondex
TCP  472  ljk-login
TCP  473  hybrid-pop
TCP  474  tn-tl-w1
TCP  475  tcpnethaspsrv
TCP  476  tn-tl-fd1
TCP  477  ss7ns
TCP  478  spsc
TCP  479  iafserver
TCP  480  iafdbase
TCP  481  Ph service
TCP  482  bgs-nsi
TCP  483  ulpnet
TCP  484  Integra Software Management Environment
TCP  485  Air Soft Power Burst
TCP  486  avian
TCP  487  saft Simple Asynchronous File Transfer
TCP  488  gss-HTTP
TCP  489  nest-protocol
TCP  490  micom-pfs
TCP  491  go-login
TCP  492  Transport Independent Convergence for FNA
TCP  493  Transport Independent Convergence for FNA
TCP  494  POV-Ray
TCP  495  intecourier
TCP  496  PIM-RP-DISC
TCP  497  dantz
TCP  498  siam
TCP  499  ISO ILL Protocol
TCP  500  ISAKMP
TCP  501  STMF
TCP  502  asa-appl-proto
TCP  503  Intrinsa
TCP  504  citadel
TCP  505  mailbox-lm
TCP  506  ohimsrv
TCP  507  crs
TCP  508  xvttp
TCP  509  snare
TCP  510  FirstClass Protocol
TCP  511  PassGo
TCP  512  Remote process execution
TCP  513  Remote Login
TCP  514  Remote Shell
TCP  515  spooler
TCP  516  videotex
TCP  517  like tenex link but across
TCP  518  talkd
TCP  519  unixtime
TCP  520  extended file name server
TCP  521  ripng
TCP  522  User Location Service / ULP
TCP  523  IBM-DB2
TCP  524  NCP
TCP  525  timeserver
TCP  526  newdate
TCP  527  Stock IXChange
TCP  528  Customer IXChange
TCP  529  IRC-SERV
TCP  530  rpc
TCP  531  chat
TCP  532  readnews
TCP  533  for emergency broadcasts
TCP  534  MegaMedia Admin
TCP  535  iiop
TCP  536  opalis-rdv
TCP  537  Networked Media Streaming Protocol
TCP  538  gdomap
TCP  539  Apertus Technologies Load Determination
TCP  540  uucpd
TCP  541  uucp-rlogin
TCP  542  commerce
TCP  543  kerberos (v4/v5)
TCP  544  krcmd
TCP  545  appleqtcsrvr
TCP  546  DHCPv6 Client
TCP  547  DHCPv6 Server
TCP  548  AppleShare AFP over TCP
TCP  549  IDFP
TCP  550  new-who
TCP  551  cybercash
TCP  552  deviceshare
TCP  553  pirp
TCP  554  Real Time Stream Control Protocol
TCP  555  phAse Zero backdoor (Win 9x, NT) / dsf
TCP  556  rfs server
TCP  557  openvms-sysipc
TCP  558  SDNSKMP
TCP  559  TEEDTAP / Backdoor.Domwis Win32 trojan
TCP  560  rmonitord
TCP  561  monitor
TCP  562  chcmd
TCP  563  AOL IM / NNTP protocol over TLS/SSL
TCP  564  plan 9 file service
TCP  565  whoami
TCP  566  streettalk
TCP  567  banyan-rpc
TCP  568  microsoft shuttle
TCP  569  microsoft rome
TCP  570  demon
TCP  571  udemon
TCP  572  sonar
TCP  573  banyan-vip
TCP  574  FTP Software Agent System
TCP  575  VEMMI
TCP  576  ipcd
TCP  577  vnas
TCP  578  ipdd
TCP  579  decbsrv
TCP  580  SNTP HEARTBEAT
TCP  581  Bundle Discovery Protocol
TCP  582  SCC Security
TCP  583  Philips Video-Conferencing
TCP  584  Key Server
TCP  585  IMAP4+SSL
TCP  586  Password Change
TCP  587  Message Submission (Sendmail)
TCP  588  CAL
TCP  589  EyeLink
TCP  590  TNS CML
TCP  591  FileMaker Inc. - HTTP Alternate
TCP  592  Eudora Set
TCP  593  HTTP RPC Ep Map
TCP  594  TPIP
TCP  595  CAB Protocol
TCP  596  SMSD
TCP  597  PTC Name Service
TCP  598  SCO Web Server Manager 3
TCP  599  Aeolon Core Protocol
TCP  600  Sun IPC server
TCP  606  Cray Unified Resource Manager
TCP  607  nqs
TCP  608  Sender-Initiated/Unsolicited File Transfer
TCP  609  npmp-trap
TCP  610  Apple Admin Service / npmp-local
TCP  611  npmp-gui
TCP  612  HMMP Indication
TCP  613  HMMP Operation
TCP  614  SSLshell
TCP  615  Internet Configuration Manager
TCP  616  SCO System Administration Server
TCP  617  SCO Desktop Administration Server
TCP  618  DEI-ICDA
TCP  619  Digital EVM
TCP  620  SCO WebServer Manager
TCP  621  ESCP
TCP  622  Collaborator
TCP  623  Aux Bus Shunt
TCP  624  Crypto Admin
TCP  625  DEC DLM
TCP  626  ASIA
TCP  627  PassGo Tivoli
TCP  628  QMQP
TCP  629  3Com AMP3
TCP  630  RDA
TCP  631  IPP (Internet Printing Protocol)
TCP  632  bmpp
TCP  633  Service Status update (Sterling Software)
TCP  634  ginad
TCP  635  RLZ DBase
TCP  636  LDAP protocol over TLS/SSL
TCP  637  lanserver
TCP  638  mcns-sec
TCP  639  MSDP
TCP  640  entrust-sps
TCP  641  repcmd
TCP  642  ESRO-EMSDP V1.3
TCP  643  SANity
TCP  644  dwr
TCP  645  PSSC
TCP  646  LDP
TCP  647  DHCP Failover
TCP  648  Registry Registrar Protocol (RRP)
TCP  649  Aminet
TCP  650  OBEX
TCP  651  IEEE MMS
TCP  652  UDLR_DTCP
TCP  653  RepCmd
TCP  654  AODV
TCP  655  TINC
TCP  656  SPMP
TCP  657  RMC
TCP  658  TenFold
TCP  659  URL Rendezvous
TCP  660  MacOS Server Admin
TCP  661  HAP
TCP  662  PFTP
TCP  663  PureNoise
TCP  664  Secure Aux Bus
TCP  665  Sun DR
TCP  666  doom Id Software
TCP  667  campaign contribution disclosures - SDR Technologies
TCP  668  MeComm
TCP  669  MeRegister
TCP  670  VACDSM-SWS
TCP  671  VACDSM-APP
TCP  672  VPPS-QUA
TCP  673  CIMPLEX
TCP  674  ACAP
TCP  675  DCTP
TCP  676  VPPS Via
TCP  677  Virtual Presence Protocol
TCP  678  GNU Gereration Foundation NCP
TCP  679  MRM
TCP  680  entrust-aaas
TCP  681  entrust-aams
TCP  682  XFR
TCP  683  CORBA IIOP
TCP  684  CORBA IIOP SSL
TCP  685  MDC Port Mapper
TCP  686  Hardware Control Protocol Wismar
TCP  687  asipregistry
TCP  688  REALM-RUSD
TCP  689  NMAP
TCP  690  VATP
TCP  691  MS Exchange Routing
TCP  692  Hyperwave-ISP
TCP  693  connendp
TCP  694  ha-cluster
TCP  695  IEEE-MMS-SSL
TCP  696  RUSHD
TCP  697  UUIDGEN
TCP  698  OLSR
TCP  704  errlog copy/server daemon
TCP  705  AgentX
TCP  706  SILC
TCP  707  W32.Nachi Worm / Borland DSJ
TCP  709  Entrust Key Management Service Handler
TCP  710  Entrust Administration Service Handler
TCP  711  Cisco TDP
TCP  729  IBM NetView DM/6000 Server/Client
TCP  730  IBM NetView DM/6000 send/tcp
TCP  731  IBM NetView DM/6000 receive/tcp
TCP  740  (old) NETscout Control Protocol (old)
TCP  741  netGW
TCP  742  Network based Rev. Cont. Sys.
TCP  744  Flexible License Manager
TCP  747  Fujitsu Device Control
TCP  748  Russell Info Sci Calendar Manager
TCP  749  kerberos administration
TCP  750  rfile
TCP  751  pump
TCP  752  Kerberos password server
TCP  753  Kerberos userreg server
TCP  754  send
TCP  758  nlogin
TCP  759  con
TCP  760  kreg, kerberos/4 registration
TCP  761  kpwd, Kerberos/4 password
TCP  762  quotad
TCP  763  cycleserv
TCP  764  omserv
TCP  765  webster
TCP  767  phone
TCP  769  vid
TCP  770  cadlock
TCP  771  rtip
TCP  772  cycleserv2
TCP  773  submit
TCP  774  rpasswd
TCP  775  entomb
TCP  776  wpages
TCP  777  Multiling HTTP
TCP  780  wpgs
TCP  781  HP performance data collector
TCP  782  node HP performance data managed node
TCP  783  HP performance data alarm manager
TCP  786  Concert
TCP  787  QSC
TCP  799  ControlIT / Remotely Possible
TCP  800  mdbs_daemon / Remotely Possible
TCP  801  device
TCP  808  CCProxy
TCP  810  FCP
TCP  828  itm-mcell-s
TCP  829  PKIX-3 CA/RA
TCP  871  SUP server
TCP  873  rsync
TCP  886  ICL coNETion locate server
TCP  887  ICL coNETion server info
TCP  888  CD Database Protocol
TCP  900  Check Point Firewall-1 HTTP administration / OMG Initial Refs
TCP  901  Samba Web Administration Tool / Realsecure / SMPNAMERES/ NetDevil trojan
TCP  902  VMware Authentication Daemon / IDEAFARM-CHAT
TCP  903  IDEAFARM-CATCH / NetDevil trojan
TCP  911  xact-backup
TCP  912  VMware Authentication Daemon
TCP  989  FTP protocol data over TLS/SSL
TCP  990  FTP protocol control over TLS/SSL
TCP  991  Netnews Administration System
TCP  992  Telnet protocol over TLS/SSL
TCP  993  IMAP4 protocol over TLS/SSL
TCP  994  IRC protocol over TLS/SSL
TCP  995  POP3 protocol over TLS/SSL
TCP  996  vsinet
TCP  997  maitrd
TCP  998  busboy
TCP  999  puprouter
TCP  1000  cadlock
TCP  1002  Microsoft Site Server Internet Locator Service (Netmeeting/ICF)
TCP  1008  UFS-aware server
TCP  1010  surf
TCP  1011  Doly (Windows Trojan)
TCP  1015  Doly (Windows Trojan)
TCP  1023  Reserved
TCP  1024  Reserved
TCP  1025  MSTASK / network blackjack
TCP  1026  MSTASK / Remote Login Network Terminal
TCP  1030  BBN IAD
TCP  1031  InetInfo / BBN IAD
TCP  1032  BBN IAD
TCP  1042  W32.Mydoom.L virus
TCP  1047  Sun's NEO Object Request Broker
TCP  1048  Sun's NEO Object Request Broker
TCP  1049  Tobit David Postman VPMN
TCP  1050  CORBA Management Agent
TCP  1051  Optima VNET
TCP  1052  Dynamic DNS Tools
TCP  1053  Remote Assistant (RA)
TCP  1054  BRVREAD
TCP  1055  ANSYS - License Manager
TCP  1056  VFO
TCP  1057  STARTRON
TCP  1058  nim
TCP  1059  nimreg
TCP  1060  POLESTAR
TCP  1061  KIOSK
TCP  1062  Veracity
TCP  1063  KyoceraNetDev
TCP  1064  JSTEL
TCP  1065  SYSCOMLAN
TCP  1066  FPO-FNS
TCP  1067  Installation Bootstrap Proto. Serv.
TCP  1068  Installation Bootstrap Proto. Cli.
TCP  1069  COGNEX-INSIGHT
TCP  1070  GMRUpdateSERV
TCP  1071  BSQUARE-VOIP
TCP  1072  CARDAX
TCP  1073  BridgeControl
TCP  1074  FASTechnologies License Manager
TCP  1075  RDRMSHC
TCP  1076  DAB STI-C
TCP  1077  IMGames
TCP  1078  eManageCstp
TCP  1079  ASPROVATalk
TCP  1080  Socks / W32.Beagle.AB trojan
TCP  1081  PVUNIWIEN
TCP  1082  AMT-ESD-PROT
TCP  1083  Anasoft License Manager
TCP  1084  Anasoft License Manager
TCP  1085  Web Objects
TCP  1086  CPL Scrambler Logging
TCP  1087  CPL Scrambler Internal
TCP  1088  CPL Scrambler Alarm Log
TCP  1089  FF Annunciation
TCP  1090  FF Fieldbus Message Specification
TCP  1091  FF System Management
TCP  1092  OBRPD
TCP  1093  PROOFD
TCP  1094  ROOTD
TCP  1095  NICELink
TCP  1096  Common Name Resolution Protocol
TCP  1097  Sun Cluster Manager
TCP  1098  RMI Activation
TCP  1099  RMI Registry
TCP  1100  MCTP
TCP  1101  PT2-DISCOVER
TCP  1102  ADOBE SERVER 1
TCP  1103  ADOBE SERVER 2
TCP  1104  XRL
TCP  1105  FTRANHC
TCP  1106  ISOIPSIGPORT-1
TCP  1107  ISOIPSIGPORT-2
TCP  1108  ratio-adp
TCP  1109  Pop with Kerberos
TCP  1110  Cluster status info
TCP  1111  LM Social Server
TCP  1112  Intelligent Communication Protocol
TCP  1114  Mini SQL
TCP  1115  ARDUS Transfer
TCP  1116  ARDUS Control
TCP  1117  ARDUS Multicast Transfer
TCP  1123  Murray
TCP  1127  SUP debugging
TCP  1155  Network File Access
TCP  1161  Health Polling
TCP  1162  Health Trap
TCP  1169  TRIPWIRE
TCP  1178  SKK (kanji input)
TCP  1180  Millicent Client Proxy
TCP  1188  HP Web Admin
TCP  1200  SCOL
TCP  1201  Nucleus Sand
TCP  1202  caiccipc
TCP  1203  License Validation
TCP  1204  Log Request Listener
TCP  1205  Accord-MGC
TCP  1206  Anthony Data
TCP  1207  MetaSage
TCP  1208  SEAGULL AIS
TCP  1209  IPCD3
TCP  1210  EOSS
TCP  1211  Groove DPP
TCP  1212  lupa
TCP  1213  MPC LIFENET
TCP  1214  KAZAA (Morpheus)
TCP  1215  scanSTAT 1.0
TCP  1216  ETEBAC 5
TCP  1217  HPSS-NDAPI
TCP  1218  AeroFlight-ADs
TCP  1219  AeroFlight-Ret
TCP  1220  QT SERVER ADMIN
TCP  1221  SweetWARE Apps
TCP  1222  SNI R&D network
TCP  1223  TGP
TCP  1224  VPNz
TCP  1225  SLINKYSEARCH
TCP  1226  STGXFWS
TCP  1227  DNS2Go
TCP  1228  FLORENCE
TCP  1229  Novell ZFS
TCP  1234  W32.Beagle.Y trojan / Infoseek Search Agent
TCP  1239  NMSD
TCP  1241  Nessus Daemon / remote message service
TCP  1243  SubSeven (Windows Trojan)
TCP  1245  Subseven backdoor remote access tool
TCP  1248  hermes
TCP  1270  Microsoft Operations Manager MOM-Encrypted
TCP  1300  H323 Host Call Secure
TCP  1310  Husky
TCP  1311  RxMon
TCP  1312  STI Envision
TCP  1313  BMC_PATROLDB
TCP  1314  Photoscript Distributed Printing System
TCP  1319  Panja-ICSP
TCP  1320  Panja-AXBNET
TCP  1321  PIP
TCP  1335  Digital Notary Protocol
TCP  1345  VPJP
TCP  1346  Alta Analytics License Manager
TCP  1347  multi media conferencing
TCP  1348  multi media conferencing
TCP  1349  Registration Network Protocol
TCP  1350  Registration Network Protocol
TCP  1351  Digital Tool Works (MIT)
TCP  1352  Lotus Notes
TCP  1353  Relief Consulting
TCP  1354  RightBrain Software
TCP  1355  Intuitive Edge
TCP  1356  CuillaMartin Company
TCP  1357  Electronic PegBoard
TCP  1358  CONNLCLI
TCP  1359  FTSRV
TCP  1360  MIMER
TCP  1361  LinX
TCP  1362  TimeFlies
TCP  1363  Network DataMover Requester
TCP  1364  Network DataMover Server
TCP  1365  Network Software Associates
TCP  1366  Novell NetWare Comm Service Platform
TCP  1367  DCS
TCP  1368  ScreenCast
TCP  1369  GlobalView to Unix Shell
TCP  1370  Unix Shell to GlobalView
TCP  1371  Fujitsu Config Protocol
TCP  1372  Fujitsu Config Protocol
TCP  1373  Chromagrafx
TCP  1374  EPI Software Systems
TCP  1375  Bytex
TCP  1376  IBM Person to Person Software
TCP  1377  Cichlid License Manager
TCP  1378  Elan License Manager
TCP  1379  Integrity Solutions
TCP  1380  Telesis Network License Manager
TCP  1381  Apple Network License Manager
TCP  1382  udt_os
TCP  1383  GW Hannaway Network License Manager
TCP  1384  Objective Solutions License Manager
TCP  1385  Atex Publishing License Manager
TCP  1386  CheckSum License Manager
TCP  1387  Computer Aided Design Software Inc LM
TCP  1388  Objective Solutions DataBase Cache
TCP  1389  Document Manager
TCP  1390  Storage Controller
TCP  1391  Storage Access Server
TCP  1392  Print Manager
TCP  1393  Network Log Server
TCP  1394  Network Log Client
TCP  1395  PC Workstation Manager software
TCP  1396  DVL Active Mail
TCP  1397  Audio Active Mail
TCP  1398  Video Active Mail
TCP  1399  Cadkey License Manager
TCP  1400  Cadkey Tablet Daemon
TCP  1401  Goldleaf License Manager
TCP  1402  Prospero Resource Manager
TCP  1403  Prospero Resource Manager
TCP  1404  Infinite Graphics License Manager
TCP  1405  IBM Remote Execution Starter
TCP  1406  NetLabs License Manager
TCP  1407  DBSA License Manager
TCP  1408  Sophia License Manager
TCP  1409  Here License Manager
TCP  1410  HiQ License Manager
TCP  1411  AudioFile
TCP  1412  InnoSys
TCP  1413  Innosys-ACL
TCP  1414  IBM MQSeries
TCP  1415  DBStar
TCP  1416  Novell LU6.2
TCP  1417  Timbuktu Service 1 Port
TCP  1418  Timbuktu Service 2 Port
TCP  1419  Timbuktu Service 3 Port
TCP  1420  Timbuktu Service 4 Port
TCP  1421  Gandalf License Manager
TCP  1422  Autodesk License Manager
TCP  1423  Essbase Arbor Software
TCP  1424  Hybrid Encryption Protocol
TCP  1425  Zion Software License Manager
TCP  1426  Satellite-data Acquisition System 1
TCP  1427  mloadd monitoring tool
TCP  1428  Informatik License Manager
TCP  1429  Hypercom NMS
TCP  1430  Hypercom TPDU
TCP  1431  Reverse Gossip Transport
TCP  1432  Blueberry Software License Manager
TCP  1433  Microsoft-SQL-Server
TCP  1434  Microsoft-SQL-Monitor
TCP  1435  IBM CICS
TCP  1436  Satellite-data Acquisition System 2
TCP  1437  Tabula
TCP  1438  Eicon Security Agent/Server
TCP  1439  Eicon X25/SNA Gateway
TCP  1440  Eicon Service Location Protocol
TCP  1441  Cadis License Management
TCP  1442  Cadis License Management
TCP  1443  Integrated Engineering Software
TCP  1444  Marcam License Management
TCP  1445  Proxima License Manager
TCP  1446  Optical Research Associates License Manager
TCP  1447  Applied Parallel Research LM
TCP  1448  OpenConnect License Manager
TCP  1449  PEport
TCP  1450  Tandem Distributed Workbench Facility
TCP  1451  IBM Information Management
TCP  1452  GTE Government Systems License Man
TCP  1453  Genie License Manager
TCP  1454  interHDL License Manager
TCP  1455  ESL License Manager
TCP  1456  DCA
TCP  1457  Valisys License Manager
TCP  1458  Nichols Research Corp.
TCP  1459  Proshare Notebook Application
TCP  1460  Proshare Notebook Application
TCP  1461  IBM Wireless LAN
TCP  1462  World License Manager
TCP  1463  Nucleus
TCP  1464  MSL License Manager
TCP  1465  Pipes Platform
TCP  1466  Ocean Software License Manager
TCP  1467  CSDMBASE
TCP  1468  CSDM
TCP  1469  Active Analysis Limited License Manager
TCP  1470  Universal Analytics
TCP  1471  csdmbase
TCP  1472  csdm
TCP  1473  OpenMath
TCP  1474  Telefinder
TCP  1475  Taligent License Manager
TCP  1476  clvm-cfg
TCP  1477  ms-sna-server
TCP  1478  ms-sna-base
TCP  1479  dberegister
TCP  1480  PacerForum
TCP  1481  AIRS
TCP  1482  Miteksys License Manager
TCP  1483  AFS License Manager
TCP  1484  Confluent License Manager
TCP  1485  LANSource
TCP  1486  nms_topo_serv
TCP  1487  LocalInfoSrvr
TCP  1488  DocStor
TCP  1489  dmdocbroker
TCP  1490  insitu-conf
TCP  1491  anynetgateway
TCP  1492  stone-design-1
TCP  1493  netmap_lm
TCP  1494  Citrix/ica
TCP  1495  cvc
TCP  1496  liberty-lm
TCP  1497  rfx-lm
TCP  1498  Sybase SQL Any
TCP  1499  Federico Heinz Consultora
TCP  1500  VLSI License Manager
TCP  1501  Satellite-data Acquisition System 3
TCP  1502  Shiva
TCP  1503  MS Netmeeting / T.120 / Databeam
TCP  1504  EVB Software Engineering License Manager
TCP  1505  Funk Software Inc.
TCP  1506  Universal Time daemon (utcd)
TCP  1507  symplex
TCP  1508  diagmond
TCP  1509  Robcad Ltd. License Manager
TCP  1510  Midland Valley Exploration Ltd. Lic. Man.
TCP  1511  3l-l1
TCP  1512  Microsoft's Windows Internet Name Service
TCP  1513  Fujitsu Systems Business of America Inc
TCP  1514  Fujitsu Systems Business of America Inc
TCP  1515  ifor-protocol
TCP  1516  Virtual Places Audio data
TCP  1517  Virtual Places Audio control
TCP  1518  Virtual Places Video data
TCP  1519  Virtual Places Video control
TCP  1520  atm zip office
TCP  1521  Oracle8i Listener / nCube License Manager
TCP  1522  Ricardo North America License Manager
TCP  1523  cichild
TCP  1524  dtspcd / ingres
TCP  1525  Oracle / Prospero Directory Service non-priv
TCP  1526  Prospero Data Access Prot non-priv
TCP  1527  oracle
TCP  1528  micautoreg
TCP  1529  oracle
TCP  1530  Oracle ExtProc (PLSExtProc) / rap-service
TCP  1531  rap-listen
TCP  1532  miroconnect
TCP  1533  Virtual Places Software
TCP  1534  micromuse-lm
TCP  1535  ampr-info
TCP  1536  ampr-inter
TCP  1537  isi-lm
TCP  1538  3ds-lm
TCP  1539  Intellistor License Manager
TCP  1540  rds
TCP  1541  rds2
TCP  1542  gridgen-elmd
TCP  1543  simba-cs
TCP  1544  aspeclmd
TCP  1545  vistium-share
TCP  1546  abbaccuray
TCP  1547  laplink
TCP  1548  Axon License Manager
TCP  1549  Shiva Hose
TCP  1550  Image Storage license manager 3M Company
TCP  1551  HECMTL-DB
TCP  1552  pciarray
TCP  1553  sna-cs
TCP  1554  CACI Products Company License Manager
TCP  1555  livelan
TCP  1556  AshWin CI Tecnologies
TCP  1557  ArborText License Manager
TCP  1558  xingmpeg
TCP  1559  web2host
TCP  1560  asci-val
TCP  1561  facilityview
TCP  1562  pconnectmgr
TCP  1563  Cadabra License Manager
TCP  1564  Pay-Per-View
TCP  1565  WinDD
TCP  1566  CORELVIDEO
TCP  1567  jlicelmd
TCP  1568  tsspmap
TCP  1569  ets
TCP  1570  orbixd
TCP  1571  Oracle Remote Data Base
TCP  1572  Chipcom License Manager
TCP  1573  itscomm-ns
TCP  1574  mvel-lm
TCP  1575  oraclenames
TCP  1576  moldflow-lm
TCP  1577  hypercube-lm
TCP  1578  Jacobus License Manager
TCP  1579  ioc-sea-lm
TCP  1580  tn-tl-r1
TCP  1581  MIL-2045-47001
TCP  1582  MSIMS
TCP  1583  simbaexpress
TCP  1584  tn-tl-fd2
TCP  1585  intv
TCP  1586  ibm-abtact
TCP  1587  pra_elmd
TCP  1588  triquest-lm
TCP  1589  VQP
TCP  1590  gemini-lm
TCP  1591  ncpm-pm
TCP  1592  commonspace
TCP  1593  mainsoft-lm
TCP  1594  sixtrak
TCP  1595  radio
TCP  1596  radio-sm
TCP  1597  orbplus-iiop
TCP  1598  picknfs
TCP  1599  simbaservices
TCP  1600  Bofra-A worm / issd
TCP  1601  aas
TCP  1602  inspect
TCP  1603  pickodbc
TCP  1604  icabrowser
TCP  1605  Salutation Manager (Salutation Protocol)
TCP  1606  Salutation Manager (SLM-API)
TCP  1607  stt
TCP  1608  Smart Corp. License Manager
TCP  1609  isysg-lm
TCP  1610  taurus-wh
TCP  1611  Inter Library Loan
TCP  1612  NetBill Transaction Server
TCP  1613  NetBill Key Repository
TCP  1614  NetBill Credential Server
TCP  1615  NetBill Authorization Server
TCP  1616  NetBill Product Server
TCP  1617  Nimrod Inter-Agent Communication
TCP  1618  skytelnet
TCP  1619  xs-openstorage
TCP  1620  faxportwinport
TCP  1621  softdataphone
TCP  1622  ontime
TCP  1623  jaleosnd
TCP  1624  udp-sr-port
TCP  1625  svs-omagent
TCP  1626  Shockwave
TCP  1627  T.128 Gateway
TCP  1628  LonTalk normal
TCP  1629  LonTalk urgent
TCP  1630  Oracle Net8 Cman
TCP  1631  Visit view
TCP  1632  PAMMRATC
TCP  1633  PAMMRPC
TCP  1634  Log On America Probe
TCP  1635  EDB Server 1
TCP  1636  CableNet Control Protocol
TCP  1637  CableNet Admin Protocol
TCP  1638  Bofra-A worm / CableNet Info Protocol
TCP  1639  cert-initiator
TCP  1640  cert-responder
TCP  1641  InVision
TCP  1642  isis-am
TCP  1643  isis-ambc
TCP  1644  Satellite-data Acquisition System 4
TCP  1645  datametrics
TCP  1646  sa-msg-port
TCP  1647  rsap
TCP  1648  concurrent-lm
TCP  1649  kermit
TCP  1650  nkd
TCP  1651  shiva_confsrvr
TCP  1652  xnmp
TCP  1653  alphatech-lm
TCP  1654  stargatealerts
TCP  1655  dec-mbadmin
TCP  1656  dec-mbadmin-h
TCP  1657  fujitsu-mmpdc
TCP  1658  sixnetudr
TCP  1659  Silicon Grail License Manager
TCP  1660  skip-mc-gikreq
TCP  1661  netview-aix-1
TCP  1662  netview-aix-2
TCP  1663  netview-aix-3
TCP  1664  netview-aix-4
TCP  1665  netview-aix-5
TCP  1666  netview-aix-6
TCP  1667  netview-aix-7
TCP  1668  netview-aix-8
TCP  1669  netview-aix-9
TCP  1670  netview-aix-10
TCP  1671  netview-aix-11
TCP  1672  netview-aix-12
TCP  1673  Intel Proshare Multicast
TCP  1674  Intel Proshare Multicast
TCP  1675  Pacific Data Products
TCP  1676  netcomm1
TCP  1677  groupwise
TCP  1678  prolink
TCP  1679  darcorp-lm
TCP  1680  microcom-sbp
TCP  1681  sd-elmd
TCP  1682  lanyon-lantern
TCP  1683  ncpm-hip
TCP  1684  SnareSecure
TCP  1685  n2nremote
TCP  1686  cvmon
TCP  1687  nsjtp-ctrl
TCP  1688  nsjtp-data
TCP  1689  firefox
TCP  1690  ng-umds
TCP  1691  empire-empuma
TCP  1692  sstsys-lm
TCP  1693  rrirtr
TCP  1694  rrimwm
TCP  1695  rrilwm
TCP  1696  rrifmm
TCP  1697  rrisat
TCP  1698  RSVP-ENCAPSULATION-1
TCP  1699  RSVP-ENCAPSULATION-2
TCP  1700  mps-raft
TCP  1701  l2tp / AOL
TCP  1702  deskshare
TCP  1703  hb-engine
TCP  1704  bcs-broker
TCP  1705  slingshot
TCP  1706  jetform
TCP  1707  vdmplay
TCP  1708  gat-lmd
TCP  1709  centra
TCP  1710  impera
TCP  1711  pptconference
TCP  1712  resource monitoring service
TCP  1713  ConferenceTalk
TCP  1714  sesi-lm
TCP  1715  houdini-lm
TCP  1716  xmsg
TCP  1717  fj-hdnet
TCP  1718  h323gatedisc
TCP  1719  h323gatestat
TCP  1720  h323hostcall
TCP  1721  caicci
TCP  1722  HKS License Manager
TCP  1723  pptp
TCP  1724  csbphonemaster
TCP  1725  iden-ralp
TCP  1726  IBERIAGAMES
TCP  1727  winddx
TCP  1728  TELINDUS
TCP  1729  CityNL License Management
TCP  1730  roketz
TCP  1731  MS Netmeeting / Audio call control / MSICCP
TCP  1732  proxim
TCP  1733  SIMS - SIIPAT Protocol for Alarm Transmission
TCP  1734  Camber Corporation License Management
TCP  1735  PrivateChat
TCP  1736  street-stream
TCP  1737  ultimad
TCP  1738  GameGen1
TCP  1739  webaccess
TCP  1740  encore
TCP  1741  cisco-net-mgmt
TCP  1742  3Com-nsd
TCP  1743  Cinema Graphics License Manager
TCP  1744  ncpm-ft
TCP  1745  ISA Server proxy autoconfig / Remote Winsock
TCP  1746  ftrapid-1
TCP  1747  ftrapid-2
TCP  1748  oracle-em1
TCP  1749  aspen-services
TCP  1750  Simple Socket Library's PortMaster
TCP  1751  SwiftNet
TCP  1752  Leap of Faith Research License Manager
TCP  1753  Translogic License Manager
TCP  1754  oracle-em2
TCP  1755  Microsoft Streaming Server
TCP  1756  capfast-lmd
TCP  1757  cnhrp
TCP  1758  tftp-mcast
TCP  1759  SPSS License Manager
TCP  1760  www-ldap-gw
TCP  1761  cft-0
TCP  1762  cft-1
TCP  1763  cft-2
TCP  1764  cft-3
TCP  1765  cft-4
TCP  1766  cft-5
TCP  1767  cft-6
TCP  1768  cft-7
TCP  1769  bmc-net-adm
TCP  1770  bmc-net-svc
TCP  1771  vaultbase
TCP  1772  EssWeb Gateway
TCP  1773  KMSControl
TCP  1774  global-dtserv
TCP  1776  Federal Emergency Management Information System
TCP  1777  powerguardian
TCP  1778  prodigy-internet
TCP  1779  pharmasoft
TCP  1780  dpkeyserv
TCP  1781  answersoft-lm
TCP  1782  HP JetSend
TCP  1783  Port 04/14/00 fujitsu.co.jp
TCP  1784  Finle License Manager
TCP  1785  Wind River Systems License Manager
TCP  1786  funk-logger
TCP  1787  funk-license
TCP  1788  psmond
TCP  1789  hello
TCP  1790  Narrative Media Streaming Protocol
TCP  1791  EA1
TCP  1792  ibm-dt-2
TCP  1793  rsc-robot
TCP  1794  cera-bcm
TCP  1795  dpi-proxy
TCP  1796  Vocaltec Server Administration
TCP  1797  UMA
TCP  1798  Event Transfer Protocol
TCP  1799  NETRISK
TCP  1800  ANSYS-License manager
TCP  1801  Microsoft Message Queuing
TCP  1802  ConComp1
TCP  1803  HP-HCIP-GWY
TCP  1804  ENL
TCP  1805  ENL-Name
TCP  1806  Musiconline
TCP  1807  Fujitsu Hot Standby Protocol
TCP  1808  Oracle-VP2
TCP  1809  Oracle-VP1
TCP  1810  Jerand License Manager
TCP  1811  Scientia-SDB
TCP  1812  RADIUS
TCP  1813  RADIUS Accounting / HackTool.SkSocket
TCP  1814  TDP Suite
TCP  1815  MMPFT
TCP  1816  HARP
TCP  1817  RKB-OSCS
TCP  1818  Enhanced Trivial File Transfer Protocol
TCP  1819  Plato License Manager
TCP  1820  mcagent
TCP  1821  donnyworld
TCP  1822  es-elmd
TCP  1823  Unisys Natural Language License Manager
TCP  1824  metrics-pas
TCP  1825  DirecPC Video
TCP  1826  ARDT
TCP  1827  ASI
TCP  1828  itm-mcell-u
TCP  1829  Optika eMedia
TCP  1830  Oracle Net8 CMan Admin
TCP  1831  Myrtle
TCP  1832  ThoughtTreasure
TCP  1833  udpradio
TCP  1834  ARDUS Unicast
TCP  1835  ARDUS Multicast
TCP  1836  ste-smsc
TCP  1837  csoft1
TCP  1838  TALNET
TCP  1839  netopia-vo1
TCP  1840  netopia-vo2
TCP  1841  netopia-vo3
TCP  1842  netopia-vo4
TCP  1843  netopia-vo5
TCP  1844  DirecPC-DLL
TCP  1850  GSI
TCP  1851  ctcd
TCP  1860  SunSCALAR Services
TCP  1861  LeCroy VICP
TCP  1862  techra-server
TCP  1863  MSN Messenger
TCP  1864  Paradym 31 Port
TCP  1865  ENTP
TCP  1870  SunSCALAR DNS Service
TCP  1871  Cano Central 0
TCP  1872  Cano Central 1
TCP  1873  Fjmpjps
TCP  1874  Fjswapsnp
TCP  1881  IBM MQSeries
TCP  1895  Vista 4GL
TCP  1899  MC2Studios
TCP  1900  SSDP
TCP  1901  Fujitsu ICL Terminal Emulator Program A
TCP  1902  Fujitsu ICL Terminal Emulator Program B
TCP  1903  Local Link Name Resolution
TCP  1904  Fujitsu ICL Terminal Emulator Program C
TCP  1905  Secure UP.Link Gateway Protocol
TCP  1906  TPortMapperReq
TCP  1907  IntraSTAR
TCP  1908  Dawn
TCP  1909  Global World Link
TCP  1910  ultrabac
TCP  1911  Starlight Networks Multimedia Transport Protocol
TCP  1912  rhp-iibp
TCP  1913  armadp
TCP  1914  Elm-Momentum
TCP  1915  FACELINK
TCP  1916  Persoft Persona
TCP  1917  nOAgent
TCP  1918  Candle Directory Service - NDS
TCP  1919  Candle Directory Service - DCH
TCP  1920  Candle Directory Service - FERRET
TCP  1921  NoAdmin
TCP  1922  Tapestry
TCP  1923  SPICE
TCP  1924  XIIP
TCP  1930  Drive AppServer
TCP  1931  AMD SCHED
TCP  1944  close-combat
TCP  1945  dialogic-elmd
TCP  1946  tekpls
TCP  1947  hlserver
TCP  1948  eye2eye
TCP  1949  ISMA Easdaq Live
TCP  1950  ISMA Easdaq Test
TCP  1951  bcs-lmserver
TCP  1952  mpnjsc
TCP  1953  Rapid Base
TCP  1961  BTS APPSERVER
TCP  1962  BIAP-MP
TCP  1963  WebMachine
TCP  1964  SOLID E ENGINE
TCP  1965  Tivoli NPM
TCP  1966  Slush
TCP  1967  SNS Quote
TCP  1972  Cache
TCP  1973  Data Link Switching Remote Access Protocol
TCP  1974  DRP
TCP  1975  TCO Flash Agent
TCP  1976  TCO Reg Agent
TCP  1977  TCO Address Book
TCP  1978  UniSQL
TCP  1979  UniSQL Java
TCP  1984  BB
TCP  1985  Hot Standby Router Protocol
TCP  1986  cisco license management
TCP  1987  cisco RSRB Priority 1 port
TCP  1988  cisco RSRB Priority 2 port
TCP  1989  MHSnet system
TCP  1990  cisco STUN Priority 1 port
TCP  1991  cisco STUN Priority 2 port
TCP  1992  IPsendmsg
TCP  1993  cisco SNMP TCP port
TCP  1994  cisco serial tunnel port
TCP  1995  cisco perf port
TCP  1996  cisco Remote SRB port
TCP  1997  cisco Gateway Discovery Protocol
TCP  1998  cisco X.25 service (XOT)
TCP  1999  cisco identification port / SubSeven (Windows Trojan) / Backdoor (Windows Trojan)
TCP  2000  Remotely Anywhere / VIA NET.WORKS PostOffice Plus
TCP  2001  Cisco mgmt / Remotely Anywhere
TCP  2002  globe
TCP  2003  GNU finger
TCP  2004  mailbox
TCP  2005  encrypted symmetric telnet/login
TCP  2006  invokator
TCP  2007  dectalk
TCP  2008  conf
TCP  2009  news
TCP  2010  search
TCP  2011  raid
TCP  2012  ttyinfo
TCP  2013  raid-am
TCP  2014  troff
TCP  2015  cypress
TCP  2016  bootserver
TCP  2017  cypress-stat
TCP  2018  terminaldb
TCP  2019  whosockami
TCP  2020  xinupageserver
TCP  2021  servexec
TCP  2022  down
TCP  2023  xinuexpansion3
TCP  2024  xinuexpansion4
TCP  2025  ellpack
TCP  2026  scrabble
TCP  2027  shadowserver
TCP  2028  submitserver
TCP  2030  device2
TCP  2032  blackboard
TCP  2033  glogger
TCP  2034  scoremgr
TCP  2035  imsldoc
TCP  2038  objectmanager
TCP  2040  lam
TCP  2041  W32.Korgo Worm / interbase
TCP  2042  isis
TCP  2043  isis-bcast
TCP  2044  rimsl
TCP  2045  cdfunc
TCP  2046  sdfunc
TCP  2047  dls
TCP  2048  dls-monitor
TCP  2049  Network File System - Sun Microsystems
TCP  2053  Kerberos de-multiplexer
TCP  2054  distrib-net
TCP  2065  Data Link Switch Read Port Number
TCP  2067  Data Link Switch Write Port Number
TCP  2080  Wingate
TCP  2090  Load Report Protocol
TCP  2091  PRP
TCP  2092  Descent 3
TCP  2093  NBX CC
TCP  2094  NBX AU
TCP  2095  NBX SER
TCP  2096  NBX DIR
TCP  2097  Jet Form Preview
TCP  2098  Dialog Port
TCP  2099  H.225.0 Annex G
TCP  2100  amiganetfs
TCP  2101  Microsoft Message Queuing / rtcm-sc104
TCP  2102  Zephyr server
TCP  2103  Microsoft Message Queuing RPC / Zephyr serv-hm connection
TCP  2104  Zephyr hostmanager
TCP  2105  Microsoft Message Queuing RPC / MiniPay
TCP  2106  MZAP
TCP  2107  Microsoft Message Queuing Management / BinTec Admin
TCP  2108  Comcam
TCP  2109  Ergolight
TCP  2110  UMSP
TCP  2111  DSATP
TCP  2112  Idonix MetaNet
TCP  2113  HSL StoRM
TCP  2114  NEWHEIGHTS
TCP  2115  KDM / Bugs (Windows Trojan)
TCP  2116  CCOWCMR
TCP  2117  MENTACLIENT
TCP  2118  MENTASERVER
TCP  2119  GSIGATEKEEPER
TCP  2120  Quick Eagle Networks CP
TCP  2121  CCProxy FTP / SCIENTIA-SSDB
TCP  2122  CauPC Remote Control
TCP  2123  GTP-Control Plane (3GPP)
TCP  2124  ELATELINK
TCP  2125  LOCKSTEP
TCP  2126  PktCable-COPS
TCP  2127  INDEX-PC-WB
TCP  2128  Net Steward Control
TCP  2129  cs-live.com
TCP  2130  SWC-XDS
TCP  2131  Avantageb2b
TCP  2132  AVAIL-EPMAP
TCP  2133  ZYMED-ZPP
TCP  2134  AVENUE
TCP  2135  Grid Resource Information Server
TCP  2136  APPWORXSRV
TCP  2137  CONNECT
TCP  2138  UNBIND-CLUSTER
TCP  2139  IAS-AUTH
TCP  2140  IAS-REG
TCP  2141  IAS-ADMIND
TCP  2142  TDM-OVER-IP
TCP  2143  Live Vault Job Control
TCP  2144  Live Vault Fast Object Transfer
TCP  2145  Live Vault Remote Diagnostic Console Support
TCP  2146  Live Vault Admin Event Notification
TCP  2147  Live Vault Authentication
TCP  2148  VERITAS UNIVERSAL COMMUNICATION LAYER
TCP  2149  ACPTSYS
TCP  2150  DYNAMIC3D
TCP  2151  DOCENT
TCP  2152  GTP-User Plane (3GPP)
TCP  2165  X-Bone API
TCP  2166  IWSERVER
TCP  2180  Millicent Vendor Gateway Server
TCP  2181  eforward
TCP  2190  TiVoConnect Beacon
TCP  2191  TvBus Messaging
TCP  2200  ICI
TCP  2201  Advanced Training System Program
TCP  2202  Int. Multimedia Teleconferencing Cosortium
TCP  2213  Kali
TCP  2220  Ganymede
TCP  2221  Rockwell CSP1
TCP  2222  Rockwell CSP2
TCP  2223  Rockwell CSP3
TCP  2232  IVS Video default
TCP  2233  INFOCRYPT
TCP  2234  DirectPlay
TCP  2235  Sercomm-WLink
TCP  2236  Nani
TCP  2237  Optech Port1 License Manager
TCP  2238  AVIVA SNA SERVER
TCP  2239  Image Query
TCP  2240  RECIPe
TCP  2241  IVS Daemon
TCP  2242  Folio Remote Server
TCP  2243  Magicom Protocol
TCP  2244  NMS Server
TCP  2245  HaO
TCP  2279  xmquery
TCP  2280  LNVPOLLER
TCP  2281  LNVCONSOLE
TCP  2282  LNVALARM
TCP  2283  Dumaru.Y (Windows trojan) / LNVSTATUS
TCP  2284  LNVMAPS
TCP  2285  LNVMAILMON
TCP  2286  NAS-Metering
TCP  2287  DNA
TCP  2288  NETML
TCP  2294  Konshus License Manager (FLEX)
TCP  2295  Advant License Manager
TCP  2296  Theta License Manager (Rainbow)
TCP  2297  D2K DataMover 1
TCP  2298  D2K DataMover 2
TCP  2299  PC Telecommute
TCP  2300  CVMMON
TCP  2301  Compaq HTTP
TCP  2302  Bindery Support
TCP  2303  Proxy Gateway
TCP  2304  Attachmate UTS
TCP  2305  MT ScaleServer
TCP  2306  TAPPI BoxNet
TCP  2307  pehelp
TCP  2308  sdhelp
TCP  2309  SD Server
TCP  2310  SD Client
TCP  2311  Message Service
TCP  2313  IAPP (Inter Access Point Protocol)
TCP  2314  CR WebSystems
TCP  2315  Precise Sft.
TCP  2316  SENT License Manager
TCP  2317  Attachmate G32
TCP  2318  Cadence Control
TCP  2319  InfoLibria
TCP  2320  Siebel NS
TCP  2321  RDLAP over UDP
TCP  2322  ofsd
TCP  2323  3d-nfsd
TCP  2324  Cosmocall
TCP  2325  Design Space License Management
TCP  2326  IDCP
TCP  2327  xingcsm
TCP  2328  Netrix SFTM
TCP  2329  NVD
TCP  2330  TSCCHAT
TCP  2331  AGENTVIEW
TCP  2332  RCC Host
TCP  2333  SNAPP
TCP  2334  ACE Client Auth
TCP  2335  ACE Proxy
TCP  2336  Apple UG Control
TCP  2337  ideesrv
TCP  2338  Norton Lambert
TCP  2339  3Com WebView
TCP  2340  WRS Registry
TCP  2341  XIO Status
TCP  2342  Seagate Manage Exec
TCP  2343  nati logos
TCP  2344  fcmsys
TCP  2345  dbm
TCP  2346  Game Connection Port
TCP  2347  Game Announcement and Location
TCP  2348  Information to query for game status
TCP  2349  Diagnostics Port
TCP  2350  psbserver
TCP  2351  psrserver
TCP  2352  pslserver
TCP  2353  pspserver
TCP  2354  psprserver
TCP  2355  psdbserver
TCP  2356  GXT License Managemant
TCP  2357  UniHub Server
TCP  2358  Futrix
TCP  2359  FlukeServer
TCP  2360  NexstorIndLtd
TCP  2361  TL1
TCP  2362  digiman
TCP  2363  Media Central NFSD
TCP  2364  OI-2000
TCP  2365  dbref
TCP  2366  qip-login
TCP  2367  Service Control
TCP  2368  OpenTable
TCP  2369  ACS2000 DSP
TCP  2370  L3-HBMon
TCP  2381  Compaq HTTPS
TCP  2382  Microsoft OLAP
TCP  2383  Microsoft OLAP
TCP  2384  SD-REQUEST
TCP  2389  OpenView Session Mgr
TCP  2390  RSMTP
TCP  2391  3COM Net Management
TCP  2392  Tactical Auth
TCP  2393  MS OLAP 1
TCP  2394  MS OLAP 2
TCP  2395  LAN900 Remote
TCP  2396  Wusage
TCP  2397  NCL
TCP  2398  Orbiter
TCP  2399  FileMaker Inc. - Data Access Layer
TCP  2400  OpEquus Server
TCP  2401  cvspserver
TCP  2402  TaskMaster 2000 Server
TCP  2403  TaskMaster 2000 Web
TCP  2404  IEC870-5-104
TCP  2405  TRC Netpoll
TCP  2406  JediServer
TCP  2407  Orion
TCP  2408  OptimaNet
TCP  2409  SNS Protocol
TCP  2410  VRTS Registry
TCP  2411  Netwave AP Management
TCP  2412  CDN
TCP  2413  orion-rmi-reg
TCP  2414  Interlingua
TCP  2415  COMTEST
TCP  2416  RMT Server
TCP  2417  Composit Server
TCP  2418  cas
TCP  2419  Attachmate S2S
TCP  2420  DSL Remote Management
TCP  2421  G-Talk
TCP  2422  CRMSBITS
TCP  2423  RNRP
TCP  2424  KOFAX-SVR
TCP  2425  Fujitsu App Manager
TCP  2426  Appliant TCP
TCP  2427  Media Gateway Control Protocol Gateway
TCP  2428  One Way Trip Time
TCP  2429  FT-ROLE
TCP  2430  venus
TCP  2431  venus-se
TCP  2432  codasrv
TCP  2433  codasrv-se
TCP  2434  pxc-epmap
TCP  2435  OptiLogic
TCP  2436  TOP/X
TCP  2437  UniControl
TCP  2438  MSP
TCP  2439  SybaseDBSynch
TCP  2440  Spearway Lockers
TCP  2441  pvsw-inet
TCP  2442  Netangel
TCP  2443  PowerClient Central Storage Facility
TCP  2444  BT PP2 Sectrans
TCP  2445  DTN1
TCP  2446  bues_service
TCP  2447  OpenView NNM daemon
TCP  2448  hpppsvr
TCP  2449  RATL
TCP  2450  netadmin
TCP  2451  netchat
TCP  2452  SnifferClient
TCP  2453  madge-om
TCP  2454  IndX-DDS
TCP  2455  WAGO-IO-SYSTEM
TCP  2456  altav-remmgt
TCP  2457  Rapido_IP
TCP  2458  griffin
TCP  2459  Community
TCP  2460  ms-theater
TCP  2461  qadmifoper
TCP  2462  qadmifevent
TCP  2463  Symbios Raid
TCP  2464  DirecPC SI
TCP  2465  Load Balance Management
TCP  2466  Load Balance Forwarding
TCP  2467  High Criteria
TCP  2468  qip_msgd
TCP  2469  MTI-TCS-COMM
TCP  2470  taskman port
TCP  2471  SeaODBC
TCP  2472  C3
TCP  2473  Aker-cdp
TCP  2474  Vital Analysis
TCP  2475  ACE Server
TCP  2476  ACE Server Propagation
TCP  2477  SecurSight Certificate Valifation Service
TCP  2478  SecurSight Authentication Server (SLL)
TCP  2479  SecurSight Event Logging Server (SSL)
TCP  2480  Lingwood's Detail
TCP  2481  Oracle GIOP
TCP  2482  Oracle GIOP SSL
TCP  2483  Oracle TTC
TCP  2484  Oracle TTC SSL
TCP  2485  Net Objects1
TCP  2486  Net Objects2
TCP  2487  Policy Notice Service
TCP  2488  Moy Corporation
TCP  2489  TSILB
TCP  2490  qip_qdhcp
TCP  2491  Conclave CPP
TCP  2492  GROOVE
TCP  2493  Talarian MQS
TCP  2494  BMC AR
TCP  2495  Fast Remote Services
TCP  2496  DIRGIS
TCP  2497  Quad DB
TCP  2498  ODN-CasTraq
TCP  2499  UniControl
TCP  2500  Resource Tracking system server
TCP  2501  Resource Tracking system client
TCP  2502  Kentrox Protocol
TCP  2503  NMS-DPNSS
TCP  2504  WLBS
TCP  2505  torque-traffic
TCP  2506  jbroker
TCP  2507  spock
TCP  2508  JDataStore
TCP  2509  fjmpss
TCP  2510  fjappmgrbulk
TCP  2511  Metastorm
TCP  2512  Citrix IMA
TCP  2513  Citrix ADMIN
TCP  2514  Facsys NTP
TCP  2515  Facsys Router
TCP  2516  Main Control
TCP  2517  H.323 Annex E call signaling transport
TCP  2518  Willy
TCP  2519  globmsgsvc
TCP  2520  pvsw
TCP  2521  Adaptec Manager
TCP  2522  WinDb
TCP  2523  Qke LLC V.3
TCP  2524  Optiwave License Management
TCP  2525  MS V-Worlds
TCP  2526  EMA License Manager
TCP  2527  IQ Server
TCP  2528  NCR CCL
TCP  2529  UTS FTP
TCP  2530  VR Commerce
TCP  2531  ITO-E GUI
TCP  2532  OVTOPMD
TCP  2533  SnifferServer
TCP  2534  Combox Web Access
TCP  2535  W32.Beagle trojan / MADCAP
TCP  2536  btpp2audctr1
TCP  2537  Upgrade Protocol
TCP  2538  vnwk-prapi
TCP  2539  VSI Admin
TCP  2540  LonWorks
TCP  2541  LonWorks2
TCP  2542  daVinci
TCP  2543  REFTEK
TCP  2544  Novell ZEN
TCP  2545  sis-emt
TCP  2546  vytalvaultbrtp
TCP  2547  vytalvaultvsmp
TCP  2548  vytalvaultpipe
TCP  2549  IPASS
TCP  2550  ADS
TCP  2551  ISG UDA Server
TCP  2552  Call Logging
TCP  2553  efidiningport
TCP  2554  VCnet-Link v10
TCP  2555  Compaq WCP
TCP  2556  W32.Beagle.N trojan / MADCAP / nicetec-nmsvc
TCP  2557  nicetec-mgmt
TCP  2558  PCLE Multi Media
TCP  2559  LSTP
TCP  2560  labrat
TCP  2561  MosaixCC
TCP  2562  Delibo
TCP  2563  CTI Redwood
TCP  2564  HP 3000 NS/VT block mode telnet
TCP  2565  Coordinator Server
TCP  2566  pcs-pcw
TCP  2567  Cisco Line Protocol
TCP  2568  SPAM TRAP
TCP  2569  Sonus Call Signal
TCP  2570  HS Port
TCP  2571  CECSVC
TCP  2572  IBP
TCP  2573  Trust Establish
TCP  2574  Blockade BPSP
TCP  2575  HL7
TCP  2576  TCL Pro Debugger
TCP  2577  Scriptics Lsrvr
TCP  2578  RVS ISDN DCP
TCP  2579  mpfoncl
TCP  2580  Tributary
TCP  2581  ARGIS TE
TCP  2582  ARGIS DS
TCP  2583  MON / Wincrash2
TCP  2584  cyaserv
TCP  2585  NETX Server
TCP  2586  NETX Agent
TCP  2587  MASC
TCP  2588  Privilege
TCP  2589  quartus tcl
TCP  2590  idotdist
TCP  2591  Maytag Shuffle
TCP  2592  netrek
TCP  2593  MNS Mail Notice Service
TCP  2594  Data Base Server
TCP  2595  World Fusion 1
TCP  2596  World Fusion 2
TCP  2597  Homestead Glory
TCP  2598  Citrix MA Client
TCP  2599  Meridian Data
TCP  2600  HPSTGMGR
TCP  2601  discp client
TCP  2602  discp server
TCP  2603  Service Meter
TCP  2604  NSC CCS
TCP  2605  NSC POSA
TCP  2606  Dell Netmon
TCP  2607  Dell Connection
TCP  2608  Wag Service
TCP  2609  System Monitor
TCP  2610  VersaTek
TCP  2611  LIONHEAD
TCP  2612  Qpasa Agent
TCP  2613  SMNTUBootstrap
TCP  2614  Never Offline
TCP  2615  firepower
TCP  2616  appswitch-emp
TCP  2617  Clinical Context Managers
TCP  2618  Priority E-Com
TCP  2619  bruce
TCP  2620  LPSRecommender
TCP  2621  Miles Apart Jukebox Server
TCP  2622  MetricaDBC
TCP  2623  LMDP
TCP  2624  Aria
TCP  2625  Blwnkl Port
TCP  2626  gbjd816
TCP  2627  Moshe Beeri
TCP  2628  DICT
TCP  2629  Sitara Server
TCP  2630  Sitara Management
TCP  2631  Sitara Dir
TCP  2632  IRdg Post
TCP  2633  InterIntelli
TCP  2634  PK Electronics
TCP  2635  Back Burner
TCP  2636  Solve
TCP  2637  Import Document Service
TCP  2638  Sybase Anywhere
TCP  2639  AMInet
TCP  2640  Sabbagh Associates Licence Manager
TCP  2641  HDL Server
TCP  2642  Tragic
TCP  2643  GTE-SAMP
TCP  2644  Travsoft IPX Tunnel
TCP  2645  Novell IPX CMD
TCP  2646  AND Licence Manager
TCP  2647  SyncServer
TCP  2648  Upsnotifyprot
TCP  2649  VPSIPPORT
TCP  2650  eristwoguns
TCP  2651  EBInSite
TCP  2652  InterPathPanel
TCP  2653  Sonus
TCP  2654  Corel VNC Admin
TCP  2655  UNIX Nt Glue
TCP  2656  Kana
TCP  2657  SNS Dispatcher
TCP  2658  SNS Admin
TCP  2659  SNS Query
TCP  2660  GC Monitor
TCP  2661  OLHOST
TCP  2662  BinTec-CAPI
TCP  2663  BinTec-TAPI
TCP  2664  Command MQ GM
TCP  2665  Command MQ PM
TCP  2666  extensis
TCP  2667  Alarm Clock Server
TCP  2668  Alarm Clock Client
TCP  2669  TOAD
TCP  2670  TVE Announce
TCP  2671  newlixreg
TCP  2672  nhserver
TCP  2673  First Call 42
TCP  2674  ewnn
TCP  2675  TTC ETAP
TCP  2676  SIMSLink
TCP  2677  Gadget Gate 1 Way
TCP  2678  Gadget Gate 2 Way
TCP  2679  Sync Server SSL
TCP  2680  pxc-sapxom
TCP  2681  mpnjsomb
TCP  2682  SRSP
TCP  2683  NCDLoadBalance
TCP  2684  mpnjsosv
TCP  2685  mpnjsocl
TCP  2686  mpnjsomg
TCP  2687  pq-lic-mgmt
TCP  2688  md-cf-HTTP
TCP  2689  FastLynx
TCP  2690  HP NNM Embedded Database
TCP  2691  IT Internet
TCP  2692  Admins LMS
TCP  2693  belarc-HTTP
TCP  2694  pwrsevent
TCP  2695  VSPREAD
TCP  2696  Unify Admin
TCP  2697  Oce SNMP Trap Port
TCP  2698  MCK-IVPIP
TCP  2699  Csoft Plus Client
TCP  2700  tqdata
TCP  2701  SMS Remote Control (control)
TCP  2702  SMS Remote Control (data)
TCP  2703  SMS Remote Control (chat)
TCP  2704  SMS Remote File Transfer
TCP  2705  SDS Admin
TCP  2706  NCD Mirroring
TCP  2707  EMCSYMAPIPORT
TCP  2708  Banyan-Net
TCP  2709  Supermon
TCP  2710  SSO Service
TCP  2711  SSO Control
TCP  2712  Axapta Object Communication Protocol
TCP  2713  Raven1
TCP  2714  Raven2
TCP  2715  HPSTGMGR2
TCP  2716  Inova IP Disco
TCP  2717  PN REQUESTER
TCP  2718  PN REQUESTER 2
TCP  2719  Scan & Change
TCP  2720  wkars
TCP  2721  Smart Diagnose
TCP  2722  Proactive Server
TCP  2723  WatchDog NT
TCP  2724  qotps
TCP  2725  SQL Analysis Services / MSOLAP PTP2
TCP  2726  TAMS
TCP  2727  Media Gateway Control Protocol Call Agent
TCP  2728  SQDR
TCP  2729  TCIM Control
TCP  2730  NEC RaidPlus
TCP  2731  NetDragon Messanger
TCP  2732  G5M
TCP  2733  Signet CTF
TCP  2734  CCS Software
TCP  2735  Monitor Console
TCP  2736  RADWIZ NMS SRV
TCP  2737  SRP Feedback
TCP  2738  NDL TCP-OSI Gateway
TCP  2739  TN Timing
TCP  2740  Alarm
TCP  2741  TSB
TCP  2742  TSB2
TCP  2743  murx
TCP  2744  honyaku
TCP  2745  W32.Beagle.C trojan) / URBISNET
TCP  2746  CPUDPENCAP
TCP  2747  yk.fujitsu.co.jp
TCP  2748  yk.fujitsu.co.jp
TCP  2749  yk.fujitsu.co.jp
TCP  2750  yk.fujitsu.co.jp
TCP  2751  yk.fujitsu.co.jp
TCP  2752  RSISYS ACCESS
TCP  2753  de-spot
TCP  2754  APOLLO CC
TCP  2755  Express Pay
TCP  2756  simplement-tie
TCP  2757  CNRP
TCP  2758  APOLLO Status
TCP  2759  APOLLO GMS
TCP  2760  Saba MS
TCP  2761  DICOM ISCL
TCP  2762  DICOM TLS
TCP  2763  Desktop DNA
TCP  2764  Data Insurance
TCP  2765  qip-audup
TCP  2766  Compaq SCP
TCP  2767  UADTC
TCP  2768  UACS
TCP  2769  Single Point MVS
TCP  2770  Veronica
TCP  2771  Vergence CM
TCP  2772  auris
TCP  2773  PC Backup
TCP  2774  PC Backup
TCP  2775  SMMP
TCP  2776  Ridgeway Systems & Software
TCP  2777  Ridgeway Systems & Software
TCP  2778  Gwen-Sonya
TCP  2779  LBC Sync
TCP  2780  LBC Control
TCP  2781  whosells
TCP  2782  everydayrc
TCP  2783  AISES
TCP  2784  world wide web - development
TCP  2785  aic-np
TCP  2786  aic-oncrpc - Destiny MCD database
TCP  2787  piccolo - Cornerstone Software
TCP  2788  NetWare Loadable Module - Seagate Software
TCP  2789  Media Agent
TCP  2790  PLG Proxy
TCP  2791  MT Port Registrator
TCP  2792  f5-globalsite
TCP  2793  initlsmsad
TCP  2794  aaftp
TCP  2795  LiveStats
TCP  2796  ac-tech
TCP  2797  esp-encap
TCP  2798  TMESIS-UPShot
TCP  2799  ICON Discover
TCP  2800  ACC RAID
TCP  2801  IGCP
TCP  2802  Veritas TCP1
TCP  2803  btprjctrl
TCP  2804  Telexis VTU
TCP  2805  WTA WSP-S
TCP  2806  cspuni
TCP  2807  cspmulti
TCP  2808  J-LAN-P
TCP  2809  CORBA LOC
TCP  2810  Active Net Steward
TCP  2811  GSI FTP
TCP  2812  atmtcp
TCP  2813  llm-pass
TCP  2814  llm-csv
TCP  2815  LBC Measurement
TCP  2816  LBC Watchdog
TCP  2817  NMSig Port
TCP  2818  rmlnk
TCP  2819  FC Fault Notification
TCP  2820  UniVision
TCP  2821  vml_dms
TCP  2822  ka0wuc
TCP  2823  CQG Net/LAN
TCP  2826  slc systemlog
TCP  2827  slc ctrlrloops
TCP  2828  ITM License Manager
TCP  2829  silkp1
TCP  2830  silkp2
TCP  2831  silkp3
TCP  2832  silkp4
TCP  2833  glishd
TCP  2834  EVTP
TCP  2835  EVTP-DATA
TCP  2836  catalyst
TCP  2837  Repliweb
TCP  2838  Starbot
TCP  2839  NMSigPort
TCP  2840  l3-exprt
TCP  2841  l3-ranger
TCP  2842  l3-hawk
TCP  2843  PDnet
TCP  2844  BPCP POLL
TCP  2845  BPCP TRAP
TCP  2846  AIMPP Hello
TCP  2847  AIMPP Port Req
TCP  2848  AMT-BLC-PORT
TCP  2849  FXP
TCP  2850  MetaConsole
TCP  2851  webemshttp
TCP  2852  bears-01
TCP  2853  ISPipes
TCP  2854  InfoMover
TCP  2856  cesdinv
TCP  2857  SimCtIP
TCP  2858  ECNP
TCP  2859  Active Memory
TCP  2860  Dialpad Voice 1
TCP  2861  Dialpad Voice 2
TCP  2862  TTG Protocol
TCP  2863  Sonar Data
TCP  2864  main 5001 cmd
TCP  2865  pit-vpn
TCP  2866  lwlistener
TCP  2867  esps-portal
TCP  2868  NPEP Messaging
TCP  2869  SSDP event notification / ICSLAP
TCP  2870  daishi
TCP  2871  MSI Select Play
TCP  2872  CONTRACT
TCP  2873  PASPAR2 ZoomIn
TCP  2874  dxmessagebase1
TCP  2875  dxmessagebase2
TCP  2876  SPS Tunnel
TCP  2877  BLUELANCE
TCP  2878  AAP
TCP  2879  ucentric-ds
TCP  2880  synapse
TCP  2881  NDSP
TCP  2882  NDTP
TCP  2883  NDNP
TCP  2884  Flash Msg
TCP  2885  TopFlow
TCP  2886  RESPONSELOGIC
TCP  2887  aironet
TCP  2888  SPCSDLOBBY
TCP  2889  RSOM
TCP  2890  CSPCLMULTI
TCP  2891  CINEGRFX-ELMD License Manager
TCP  2892  SNIFFERDATA
TCP  2893  VSECONNECTOR
TCP  2894  ABACUS-REMOTE
TCP  2895  NATUS LINK
TCP  2896  ECOVISIONG6-1
TCP  2897  Citrix RTMP
TCP  2898  APPLIANCE-CFG
TCP  2899  case.nm.fujitsu.co.jp
TCP  2900  magisoft.com
TCP  2901  ALLSTORCNS
TCP  2902  NET ASPI
TCP  2903  SUITCASE
TCP  2904  M2UA
TCP  2905  M3UA
TCP  2906  CALLER9
TCP  2907  WEBMETHODS B2B
TCP  2908  mao
TCP  2909  Funk Dialout
TCP  2910  TDAccess
TCP  2911  Blockade
TCP  2912  Epicon
TCP  2913  Booster Ware
TCP  2914  Game Lobby
TCP  2915  TK Socket
TCP  2916  Elvin Server
TCP  2917  Elvin Client
TCP  2918  Kasten Chase Pad
TCP  2919  ROBOER
TCP  2920  ROBOEDA
TCP  2921  CESD Contents Delivery Management
TCP  2922  CESD Contents Delivery Data Transfer
TCP  2923  WTA-WSP-WTP-S
TCP  2924  PRECISE-VIP
TCP  2925  Firewall Redundancy Protocol
TCP  2926  MOBILE-FILE-DL
TCP  2927  UNIMOBILECTRL
TCP  2928  REDSTONE-CPSS
TCP  2929  PANJA-WEBADMIN
TCP  2930  PANJA-WEBLINX
TCP  2931  Circle-X
TCP  2932  INCP
TCP  2933  4-TIER OPM GW
TCP  2934  4-TIER OPM CLI
TCP  2935  QTP
TCP  2936  OTPatch
TCP  2937  PNACONSULT-LM
TCP  2938  SM-PAS-1
TCP  2939  SM-PAS-2
TCP  2940  SM-PAS-3
TCP  2941  SM-PAS-4
TCP  2942  SM-PAS-5
TCP  2943  TTNRepository
TCP  2944  Megaco H-248
TCP  2945  H248 Binary
TCP  2946  FJSVmpor
TCP  2947  GPSD
TCP  2948  WAP PUSH
TCP  2949  WAP PUSH SECURE
TCP  2950  ESIP
TCP  2951  OTTP
TCP  2952  MPFWSAS
TCP  2953  OVALARMSRV
TCP  2954  OVALARMSRV-CMD
TCP  2955  CSNOTIFY
TCP  2956  OVRIMOSDBMAN
TCP  2957  JAMCT5
TCP  2958  JAMCT6
TCP  2959  RMOPAGT
TCP  2960  DFOXSERVER
TCP  2961  BOLDSOFT-LM
TCP  2962  IPH-POLICY-CLI
TCP  2963  IPH-POLICY-ADM
TCP  2964  BULLANT SRAP
TCP  2965  BULLANT RAP
TCP  2966  IDP-INFOTRIEVE
TCP  2967  SSC-AGENT
TCP  2968  ENPP
TCP  2969  UPnP / ESSP
TCP  2970  INDEX-NET
TCP  2971  Net Clip
TCP  2972  PMSM Webrctl
TCP  2973  SV Networks
TCP  2974  Signal
TCP  2975  Fujitsu Configuration Management Service
TCP  2976  CNS Server Port
TCP  2977  TTCs Enterprise Test Access Protocol - NS
TCP  2978  TTCs Enterprise Test Access Protocol - DS
TCP  2979  H.263 Video Streaming
TCP  2980  Instant Messaging Service
TCP  2981  MYLXAMPORT
TCP  2982  IWB-WHITEBOARD
TCP  2983  NETPLAN
TCP  2984  HPIDSADMIN
TCP  2985  HPIDSAGENT
TCP  2986  STONEFALLS
TCP  2987  IDENTIFY
TCP  2988  CLASSIFY
TCP  2989  ZARKOV
TCP  2990  BOSCAP
TCP  2991  WKSTN-MON
TCP  2992  ITB301
TCP  2993  VERITAS VIS1
TCP  2994  VERITAS VIS2
TCP  2995  IDRS
TCP  2996  vsixml
TCP  2997  REBOL
TCP  2998  Real Secure
TCP  2999  RemoteWare Unassigned
TCP  3000  RemoteWare Client
TCP  3001  Phatbot Worm / Redwood Broker
TCP  3002  RemoteWare Server
TCP  3003  CGMS
TCP  3004  Csoft Agent
TCP  3005  Genius License Manager
TCP  3006  Instant Internet Admin
TCP  3007  Lotus Mail Tracking Agent Protocol
TCP  3008  Midnight Technologies
TCP  3009  PXC-NTFY
TCP  3010  Telerate Workstation
TCP  3011  Trusted Web
TCP  3012  Trusted Web Client
TCP  3013  Gilat Sky Surfer
TCP  3014  Broker Service
TCP  3015  NATI DSTP
TCP  3016  Notify Server
TCP  3017  Event Listener
TCP  3018  Service Registry
TCP  3019  Resource Manager
TCP  3020  CIFS
TCP  3021  AGRI Server
TCP  3022  CSREGAGENT
TCP  3023  magicnotes
TCP  3024  NDS_SSO
TCP  3025  Arepa Raft
TCP  3026  AGRI Gateway
TCP  3027  LiebDevMgmt_C
TCP  3028  LiebDevMgmt_DM
TCP  3029  LiebDevMgmt_A
TCP  3030  Arepa Cas
TCP  3031  AgentVU
TCP  3032  Redwood Chat
TCP  3033  PDB
TCP  3034  Osmosis AEEA
TCP  3035  FJSV gssagt
TCP  3036  Hagel DUMP
TCP  3037  HP SAN Mgmt
TCP  3038  Santak UPS
TCP  3039  Cogitate Inc.
TCP  3040  Tomato Springs
TCP  3041  di-traceware
TCP  3042  journee
TCP  3043  BRP
TCP  3045  ResponseNet
TCP  3046  di-ase
TCP  3047  Fast Security HL Server
TCP  3048  Sierra Net PC Trader
TCP  3049  NSWS
TCP  3050  gds_db
TCP  3051  Galaxy Server
TCP  3052  APCPCNS
TCP  3053  dsom-server
TCP  3054  AMT CNF PROT
TCP  3055  Policy Server
TCP  3056  CDL Server
TCP  3057  GoAhead FldUp
TCP  3058  videobeans
TCP  3059  qsoft
TCP  3060  interserver
TCP  3061  cautcpd
TCP  3062  ncacn-ip-tcp
TCP  3063  ncadg-ip-udp
TCP  3065  slinterbase
TCP  3066  NETATTACHSDMP
TCP  3067  W32.Korgo Worm / FJHPJP
TCP  3068  ls3 Broadcast
TCP  3069  ls3
TCP  3070  MGXSWITCH
TCP  3075  Orbix 2000 Locator
TCP  3076  Orbix 2000 Config
TCP  3077  Orbix 2000 Locator SSL
TCP  3078  Orbix 2000 Locator SSL
TCP  3079  LV Front Panel
TCP  3080  stm_pproc
TCP  3081  TL1-LV
TCP  3082  TL1-RAW
TCP  3083  TL1-TELNET
TCP  3084  ITM-MCCS
TCP  3085  PCIHReq
TCP  3086  JDL-DBKitchen
TCP  3105  Cardbox
TCP  3106  Cardbox HTTP
TCP  3127  W32.Mydoom.A virus
TCP  3128  Squid HTTP Proxy / W32.Mydoom.B virus
TCP  3129  Master's Paradise (Windows Trojan)
TCP  3130  ICPv2
TCP  3131  Net Book Mark
TCP  3141  VMODEM
TCP  3142  RDC WH EOS
TCP  3143  Sea View
TCP  3144  Tarantella
TCP  3145  CSI-LFAP
TCP  3147  RFIO
TCP  3148  NetMike Game Administrator
TCP  3149  NetMike Game Server
TCP  3150  NetMike Assessor Administrator
TCP  3151  NetMike Assessor
TCP  3180  Millicent Broker Server
TCP  3181  BMC Patrol Agent
TCP  3182  BMC Patrol Rendezvous
TCP  3262  NECP
TCP  3264  cc:mail/lotus
TCP  3265  Altav Tunnel
TCP  3266  NS CFG Server
TCP  3267  IBM Dial Out
TCP  3268  Microsoft Global Catalog
TCP  3269  Microsoft Global Catalog with LDAP/SSL
TCP  3270  Verismart
TCP  3271  CSoft Prev Port
TCP  3272  Fujitsu User Manager
TCP  3273  Simple Extensible Multiplexed Protocol
TCP  3274  Ordinox Server
TCP  3275  SAMD
TCP  3276  Maxim ASICs
TCP  3277  AWG Proxy
TCP  3278  LKCM Server
TCP  3279  admind
TCP  3280  VS Server
TCP  3281  SYSOPT
TCP  3282  Datusorb
TCP  3283  Net Assistant
TCP  3284  4Talk
TCP  3285  Plato
TCP  3286  E-Net
TCP  3287  DIRECTVDATA
TCP  3288  COPS
TCP  3289  ENPC
TCP  3290  CAPS LOGISTICS TOOLKIT - LM
TCP  3291  S A Holditch & Associates - LM
TCP  3292  Cart O Rama
TCP  3293  fg-fps
TCP  3294  fg-gip
TCP  3295  Dynamic IP Lookup
TCP  3296  Rib License Manager
TCP  3297  Cytel License Manager
TCP  3298  Transview
TCP  3299  pdrncs
TCP  3300  bmc-patrol-agent
TCP  3301  Unathorised use by SAP R/3
TCP  3302  MCS Fastmail
TCP  3303  OP Session Client
TCP  3304  OP Session Server
TCP  3305  ODETTE-FTP
TCP  3306  MySQL
TCP  3307  OP Session Proxy
TCP  3308  TNS Server
TCP  3309  TNS ADV
TCP  3310  Dyna Access
TCP  3311  MCNS Tel Ret
TCP  3312  Application Management Server
TCP  3313  Unify Object Broker
TCP  3314  Unify Object Host
TCP  3315  CDID
TCP  3316  AICC/CMI
TCP  3317  VSAI PORT
TCP  3318  Swith to Swith Routing Information Protocol
TCP  3319  SDT License Manager
TCP  3320  Office Link 2000
TCP  3321  VNSSTR
TCP  3325  isi.edu
TCP  3326  SFTU
TCP  3327  BBARS
TCP  3328  Eaglepoint License Manager
TCP  3329  HP Device Disc
TCP  3330  MCS Calypso ICF
TCP  3331  MCS Messaging
TCP  3332  MCS Mail Server
TCP  3333  DEC Notes
TCP  3334  Direct TV Webcasting
TCP  3335  Direct TV Software Updates
TCP  3336  Direct TV Tickers
TCP  3337  Direct TV Data Catalog
TCP  3338  OMF data b
TCP  3339  OMF data l
TCP  3340  OMF data m
TCP  3341  OMF data h
TCP  3342  WebTIE
TCP  3343  MS Cluster Net
TCP  3344  BNT Manager
TCP  3345  Influence
TCP  3346  Trnsprnt Proxy
TCP  3347  Phoenix RPC
TCP  3348  Pangolin Laser
TCP  3349  Chevin Services
TCP  3350  FINDVIATV
TCP  3351  BTRIEVE
TCP  3352  SSQL
TCP  3353  FATPIPE
TCP  3354  SUITJD
TCP  3355  Hogle (proxy backdoor) / Ordinox Dbase
TCP  3356  UPNOTIFYPS
TCP  3357  Adtech Test IP
TCP  3358  Mp Sys Rmsvr
TCP  3359  WG NetForce
TCP  3360  KV Server
TCP  3361  KV Agent
TCP  3362  DJ ILM
TCP  3363  NATI Vi Server
TCP  3364  Creative Server
TCP  3365  Content Server
TCP  3366  Creative Partner
TCP  3371  ccm.jf.intel.com
TCP  3372  Microsoft Distributed Transaction Coordinator (MSDTC) / TIP 2
TCP  3373  Lavenir License Manager
TCP  3374  Cluster Disc
TCP  3375  VSNM Agent
TCP  3376  CD Broker
TCP  3377  Cogsys Network License Manager
TCP  3378  WSICOPY
TCP  3379  SOCORFS
TCP  3380  SNS Channels
TCP  3381  Geneous
TCP  3382  Fujitsu Network Enhanced Antitheft function
TCP  3383  Enterprise Software Products License Manager
TCP  3384  Cluster Management Services
TCP  3385  qnxnetman
TCP  3386  GPRS Data
TCP  3387  Back Room Net
TCP  3388  CB Server
TCP  3389  MS Terminal Server
TCP  3390  Distributed Service Coordinator
TCP  3391  SAVANT
TCP  3392  EFI License Management
TCP  3393  D2K Tapestry Client to Server
TCP  3394  D2K Tapestry Server to Server
TCP  3395  Dyna License Manager (Elam)
TCP  3396  Printer Agent
TCP  3397  Cloanto License Manager
TCP  3398  Mercantile
TCP  3399  CSMS
TCP  3400  CSMS2
TCP  3401  filecast
TCP  3410  Backdoor.OptixPro.13
TCP  3421  Bull Apprise portmapper
TCP  3454  Apple Remote Access Protocol
TCP  3455  RSVP Port
TCP  3456  VAT default data
TCP  3457  VAT default control
TCP  3458  D3WinOsfi
TCP  3459  TIP Integral
TCP  3460  EDM Manger
TCP  3461  EDM Stager
TCP  3462  EDM STD Notify
TCP  3463  EDM ADM Notify
TCP  3464  EDM MGR Sync
TCP  3465  EDM MGR Cntrl
TCP  3466  WORKFLOW
TCP  3467  RCST
TCP  3468  TTCM Remote Controll
TCP  3469  Pluribus
TCP  3470  jt400
TCP  3471  jt400-ssl
TCP  3535  MS-LA
TCP  3563  Watcom Debug
TCP  3572  harlequin.co.uk
TCP  3672  harlequinorb
TCP  3689  Apple Digital Audio Access Protocol
TCP  3802  VHD
TCP  3845  V-ONE Single Port Proxy
TCP  3862  GIGA-POCKET
TCP  3875  PNBSCADA
TCP  3900  Unidata UDT OS
TCP  3984  MAPPER network node manager
TCP  3985  MAPPER TCP/IP server
TCP  3986  MAPPER workstation server
TCP  3987  Centerline
TCP  4000  Terabase
TCP  4001  Cisco mgmt / NewOak
TCP  4002  pxc-spvr-ft
TCP  4003  pxc-splr-ft
TCP  4004  pxc-roid
TCP  4005  pxc-pin
TCP  4006  pxc-spvr
TCP  4007  pxc-splr
TCP  4008  NetCheque accounting
TCP  4009  Chimera HWM
TCP  4010  Samsung Unidex
TCP  4011  Alternate Service Boot
TCP  4012  PDA Gate
TCP  4013  ACL Manager
TCP  4014  TAICLOCK
TCP  4015  Talarian Mcast
TCP  4016  Talarian Mcast
TCP  4017  Talarian Mcast
TCP  4018  Talarian Mcast
TCP  4019  Talarian Mcast
TCP  4045  nfs-lockd
TCP  4096  BRE (Bridge Relay Element)
TCP  4097  Patrol View
TCP  4098  drmsfsd
TCP  4099  DPCP
TCP  4132  NUTS Daemon
TCP  4133  NUTS Bootp Server
TCP  4134  NIFTY-Serve HMI protocol
TCP  4141  Workflow Server
TCP  4142  Document Server
TCP  4143  Document Replication
TCP  4144  Compuserve pc windows
TCP  4160  Jini Discovery
TCP  4199  EIMS ADMIN
TCP  4299  earth.path.net
TCP  4300  Corel CCam
TCP  4321  Remote Who Is
TCP  4333  mini-sql server
TCP  4343  UNICALL
TCP  4344  VinaInstall
TCP  4345  Macro 4 Network AS
TCP  4346  ELAN LM
TCP  4347  LAN Surveyor
TCP  4348  ITOSE
TCP  4349  File System Port Map
TCP  4350  Net Device
TCP  4351  PLCY Net Services
TCP  4353  F5 iQuery
TCP  4397  Phatbot Worm
TCP  4442  Saris
TCP  4443  Pharos
TCP  4444  AdSubtract / NV Video default
TCP  4445  UPNOTIFYP
TCP  4446  N1-FWP
TCP  4447  N1-RMGMT
TCP  4448  ASC Licence Manager
TCP  4449  PrivateWire
TCP  4450  Camp
TCP  4451  CTI System Msg
TCP  4452  CTI Program Load
TCP  4453  NSS Alert Manager
TCP  4454  NSS Agent Manager
TCP  4455  PR Chat User
TCP  4456  PR Chat Server
TCP  4457  PR Register
TCP  4500  sae-urn
TCP  4501  urn-x-cdchoice
TCP  4545  WorldScores
TCP  4546  SF License Manager (Sentinel)
TCP  4547  Lanner License Manager
TCP  4557  FAX transmission service
TCP  4559  HylaFAX client-service protocol
TCP  4567  TRAM
TCP  4568  BMC Reporting
TCP  4600  Piranha1
TCP  4601  Piranha2
TCP  4661  eDonkey2k
TCP  4662  eDonkey2k
TCP  4663  eDonkey
TCP  4665  eDonkey2k
TCP  4672  remote file access server
TCP  4675  eMule
TCP  4711  eMule
TCP  4751  W32.Beagle.V trojan
TCP  4772  eMule
TCP  4800  Icona Instant Messenging System
TCP  4801  Icona Web Embedded Chat
TCP  4802  Icona License System Server
TCP  4820  Backdoor.Tuxter
TCP  4827  HTCP
TCP  4837  Varadero-0
TCP  4838  Varadero-1
TCP  4868  Photon Relay
TCP  4869  Photon Relay Debug
TCP  4885  ABBS
TCP  4899  RAdmin Win32 remote control
TCP  4983  AT&T Intercom
TCP  5000  UPnP / filmaker.com / Socket de Troie (Windows Trojan)
TCP  5001  filmaker.com / Socket de Troie (Windows Trojan)
TCP  5002  radio free ethernet
TCP  5003  FileMaker Inc. - Proprietary transport
TCP  5004  avt-profile-1
TCP  5005  avt-profile-2
TCP  5006  wsm server
TCP  5007  wsm server ssl
TCP  5010  TelepathStart
TCP  5011  TelepathAttack
TCP  5020  zenginkyo-1
TCP  5021  zenginkyo-2
TCP  5042  asnaacceler8db
TCP  5050  Yahoo Messenger / multimedia conference control tool
TCP  5051  ITA Agent
TCP  5052  ITA Manager
TCP  5055  UNOT
TCP  5060  SIP
TCP  5069  I/Net 2000-NPR
TCP  5071  PowerSchool
TCP  5093  Sentinel LM
TCP  5099  SentLM Srv2Srv
TCP  5101  Yahoo! Messenger
TCP  5145  RMONITOR SECURE
TCP  5150  Ascend Tunnel Management Protocol
TCP  5151  ESRI SDE Instance
TCP  5152  ESRI SDE Instance Discovery
TCP  5165  ife_1corp
TCP  5190  America-Online
TCP  5191  AmericaOnline1
TCP  5192  AmericaOnline2
TCP  5193  AmericaOnline3
TCP  5200  Targus AIB 1
TCP  5201  Targus AIB 2
TCP  5202  Targus TNTS 1
TCP  5203  Targus TNTS 2
TCP  5222  Jabber Server
TCP  5232  SGI Distribution Graphics
TCP  5236  padl2sim
TCP  5272  PK
TCP  5300  HA cluster heartbeat
TCP  5301  HA cluster general services
TCP  5302  HA cluster configuration
TCP  5303  HA cluster probing
TCP  5304  HA Cluster Commands
TCP  5305  HA Cluster Test
TCP  5306  Sun MC Group
TCP  5307  SCO AIP
TCP  5308  CFengine
TCP  5309  J Printer
TCP  5310  Outlaws
TCP  5311  TM Login
TCP  5373  W32.Gluber.B@mm
TCP  5400  Excerpt Search / Blade Runner (Windows Trojan)
TCP  5401  Excerpt Search Secure / Blade Runner (Windows Trojan)
TCP  5402  MFTP / Blade Runner (Windows Trojan)
TCP  5403  HPOMS-CI-LSTN
TCP  5404  HPOMS-DPS-LSTN
TCP  5405  NetSupport
TCP  5406  Systemics Sox
TCP  5407  Foresyte-Clear
TCP  5408  Foresyte-Sec
TCP  5409  Salient Data Server
TCP  5410  Salient User Manager
TCP  5411  ActNet
TCP  5412  Continuus
TCP  5413  WWIOTALK
TCP  5414  StatusD
TCP  5415  NS Server
TCP  5416  SNS Gateway
TCP  5417  SNS Agent
TCP  5418  MCNTP
TCP  5419  DJ-ICE
TCP  5420  Cylink-C
TCP  5421  Net Support 2
TCP  5422  Salient MUX
TCP  5423  VIRTUALUSER
TCP  5426  DEVBASIC
TCP  5427  SCO-PEER-TTA
TCP  5428  TELACONSOLE
TCP  5429  Billing and Accounting System Exchange
TCP  5430  RADEC CORP
TCP  5431  PARK AGENT
TCP  5432  postgres database server
TCP  5435  Data Tunneling Transceiver Linking (DTTL)
TCP  5454  apc-tcp-udp-4
TCP  5455  apc-tcp-udp-5
TCP  5456  apc-tcp-udp-6
TCP  5461  SILKMETER
TCP  5462  TTL Publisher
TCP  5465  NETOPS-BROKER
TCP  5490  Squid HTTP Proxy
TCP  5500  fcp-addr-srvr1
TCP  5501  fcp-addr-srvr2
TCP  5502  fcp-srvr-inst1
TCP  5503  fcp-srvr-inst2
TCP  5504  fcp-cics-gw1
TCP  5510  ACE/Server Services
TCP  5520  ACE/Server Services
TCP  5530  ACE/Server Services
TCP  5540  ACE/Server Services
TCP  5550  ACE/Server Services / Xtcp 2.0x
TCP  5554  Sasser Worm FTP backdoor / SGI ESP HTTP
TCP  5555  Personal Agent / W32.Mimail.P@mm
TCP  5556  Mtbd (mtb backup)
TCP  5559  Enterprise Security Remote Install axent.com
TCP  5599  Enterprise Security Remote Install
TCP  5600  Enterprise Security Manager
TCP  5601  Enterprise Security Agent
TCP  5602  A1-MSC
TCP  5603  A1-BS
TCP  5604  A3-SDUNode
TCP  5605  A4-SDUNode
TCP  5631  pcANYWHEREdata
TCP  5632  pcANYWHEREstat
TCP  5678  LinkSys EtherFast Router Remote Administration / Remote Replication Agent Connection
TCP  5679  Direct Cable Connect Manager
TCP  5680  Canna (Japanese Input)
TCP  5713  proshare conf audio
TCP  5714  proshare conf video
TCP  5715  proshare conf data
TCP  5716  proshare conf request
TCP  5717  proshare conf notify
TCP  5729  Openmail User Agent Layer
TCP  5741  IDA Discover Port 1
TCP  5742  IDA Discover Port 2 / Wincrash (Windows Trojan)
TCP  5745  fcopy-server
TCP  5746  fcopys-server
TCP  5755  OpenMail Desk Gateway server
TCP  5757  OpenMail X.500 Directory Server
TCP  5766  OpenMail NewMail Server
TCP  5767  OpenMail Suer Agent Layer (Secure)
TCP  5768  OpenMail CMTS Server
TCP  5771  NetAgent
TCP  5800  VNC Virtual Network Computing
TCP  5801  VNC Virtual Network Computing
TCP  5813  ICMPD
TCP  5859  WHEREHOO
TCP  5882  Y3k
TCP  5900  VNC Virtual Network Computing
TCP  5901  VNC Virtual Network Computing
TCP  5968  mppolicy-v5
TCP  5969  mppolicy-mgr
TCP  5977  NCD preferences TCP port
TCP  5978  NCD diagnostic TCP port
TCP  5979  NCD configuration TCP port
TCP  5980  VNC Virtual Network Computing
TCP  5981  VNC Virtual Network Computing
TCP  5987  Solaris Web Enterprise Management RMI
TCP  5997  NCD preferences telnet port
TCP  5998  NCD diagnostic telnet port
TCP  5999  CVSup
TCP  6000  X-Windows / W32.LoveGate.ak virus
TCP  6001  Cisco mgmt
TCP  6003  Half-Life WON server
TCP  6063  X Windows System mit.edu
TCP  6064  NDL-AHP-SVC
TCP  6065  WinPharaoh
TCP  6066  EWCTSP
TCP  6067  SRB
TCP  6068  GSMP
TCP  6069  TRIP
TCP  6070  Messageasap
TCP  6071  SSDTP
TCP  6072  DIAGNOSE-PROC
TCP  6073  DirectPlay8
TCP  6100  SynchroNet-db
TCP  6101  SynchroNet-rtc
TCP  6102  SynchroNet-upd
TCP  6103  RETS
TCP  6104  DBDB
TCP  6105  Prima Server
TCP  6106  MPS Server
TCP  6107  ETC Control
TCP  6108  Sercomm-SCAdmin
TCP  6109  GLOBECAST-ID
TCP  6110  HP SoftBench CM
TCP  6111  HP SoftBench Sub-Process Control
TCP  6112  dtspcd / Blizzard Battlenet
TCP  6123  Backup Express
TCP  6129  DameWare
TCP  6141  Meta Corporation License Manager
TCP  6142  Aspen Technology License Manager
TCP  6143  Watershed License Manager
TCP  6144  StatSci License Manager - 1
TCP  6145  StatSci License Manager - 2
TCP  6146  Lone Wolf Systems License Manager
TCP  6147  Montage License Manager
TCP  6148  Ricardo North America License Manager
TCP  6149  tal-pod
TCP  6253  CRIP
TCP  6321  Empress Software Connectivity Server 1
TCP  6322  Empress Software Connectivity Server 2
TCP  6346  Gnutella/Bearshare file sharing Application
TCP  6348  Limewire P2P
TCP  6389  clariion-evr01
TCP  6400  saegatesoftware.com
TCP  6401  saegatesoftware.com
TCP  6402  saegatesoftware.com
TCP  6403  saegatesoftware.com
TCP  6404  saegatesoftware.com
TCP  6405  saegatesoftware.com
TCP  6406  saegatesoftware.com
TCP  6407  saegatesoftware.com
TCP  6408  saegatesoftware.com
TCP  6409  saegatesoftware.com
TCP  6410  saegatesoftware.com
TCP  6455  SKIP Certificate Receive
TCP  6456  SKIP Certificate Send
TCP  6471  LVision License Manager
TCP  6500  BoKS Master
TCP  6501  BoKS Servc
TCP  6502  BoKS Servm
TCP  6503  BoKS Clntd
TCP  6505  BoKS Admin Private Port
TCP  6506  BoKS Admin Public Port
TCP  6507  BoKS Dir Server Private Port
TCP  6508  BoKS Dir Server Public Port
TCP  6547  apc-tcp-udp-1
TCP  6548  apc-tcp-udp-2
TCP  6549  apc-tcp-udp-3
TCP  6550  fg-sysupdate
TCP  6558  xdsxdm
TCP  6588  AnalogX Web Proxy
TCP  6665  Internet Relay Chat
TCP  6666  IRC / Windows Media Unicast Service
TCP  6667  IRC
TCP  6668  IRC
TCP  6669  IRC
TCP  6670  Vocaltec Global Online Directory / Deep Throat 2 (Windows Trojan)
TCP  6672  vision_server
TCP  6673  vision_elmd
TCP  6699  Napster
TCP  6700  Napster / Carracho (server)
TCP  6701  KTI/ICAD Nameserver
TCP  6701  Napster / Carracho (server)
TCP  6711  SubSeven (Windows Trojan)
TCP  6723  DDOS communication TCP
TCP  6767  BMC PERFORM AGENT
TCP  6768  BMC PERFORM MGRD
TCP  6776  SubSeven/BackDoor-G (Windows Trojan)
TCP  6777  W32.Beagle.A trojan
TCP  6789  IBM DB2
TCP  6790  HNMP / IBM DB2
TCP  6831  ambit-lm
TCP  6841  Netmo Default
TCP  6842  Netmo HTTP
TCP  6850  ICCRUSHMORE
TCP  6881  BitTorrent Network
TCP  6888  MUSE
TCP  6891  MS Messenger file transfer
TCP  6901  MS Messenger voice calls
TCP  6961  JMACT3
TCP  6962  jmevt2
TCP  6963  swismgr1
TCP  6964  swismgr2
TCP  6965  swistrap
TCP  6966  swispol
TCP  6969  acmsoda
TCP  6998  IATP-highPri
TCP  6999  IATP-normalPri
TCP  7000  IRC / file server itself
TCP  7001  WebLogic Server / Callbacks to cache managers
TCP  7002  WebLogic Server (SSL) / Half-Life Auth Server / Users & groups database
TCP  7003  volume location database
TCP  7004  AFS/Kerberos authentication service
TCP  7005  volume managment server
TCP  7006  error interpretation service
TCP  7007  Windows Media Services / basic overseer process
TCP  7008  server-to-server updater
TCP  7009  remote cache manager service
TCP  7010  onlinet uninterruptable power supplies
TCP  7011  Talon Discovery Port
TCP  7012  Talon Engine
TCP  7013  Microtalon Discovery
TCP  7014  Microtalon Communications
TCP  7015  Talon Webserver
TCP  7020  DP Serve
TCP  7021  DP Serve Admin
TCP  7070  ARCP
TCP  7099  lazy-ptop
TCP  7100  X Font Service
TCP  7121  Virtual Prototypes License Manager
TCP  7141  vnet.ibm.com
TCP  7161  Catalyst
TCP  7174  Clutild
TCP  7200  FODMS FLIP
TCP  7201  DLIP
TCP  7323  3.11 Remote Administration
TCP  7326  Internet Citizen's Band
TCP  7390  The Swiss Exchange swx.ch
TCP  7395  winqedit
TCP  7426  OpenView DM Postmaster Manager
TCP  7427  OpenView DM Event Agent Manager
TCP  7428  OpenView DM Log Agent Manager
TCP  7429  OpenView DM rqt communication
TCP  7430  OpenView DM xmpv7 api pipe
TCP  7431  OpenView DM ovc/xmpv3 api pipe
TCP  7437  Faximum
TCP  7491  telops-lmd
TCP  7511  pafec-lm
TCP  7544  FlowAnalyzer DisplayServer
TCP  7545  FlowAnalyzer UtilityServer
TCP  7566  VSI Omega
TCP  7570  Aries Kfinder
TCP  7588  Sun License Manager
TCP  7597  TROJAN WORM
TCP  7633  PMDF Management
TCP  7640  CUSeeMe
TCP  7777  Oracle App server / cbt
TCP  7778  Windows Media Services / Interwise
TCP  7781  accu-lmgr
TCP  7786  MINIVEND
TCP  7932  Tier 2 Data Resource Manager
TCP  7933  Tier 2 Business Rules Manager
TCP  7967  Supercell
TCP  7979  Micromuse-ncps
TCP  7980  Quest Vista
TCP  7999  iRDMI2
TCP  8000  HTTP/iRDMI
TCP  8001  HTTP/VCOM Tunnel
TCP  8002  HTTP/Teradata ORDBMS
TCP  8007  Apache JServ Protocol
TCP  8008  HTTP Alternate
TCP  8009  Apache JServ Protocol
TCP  8010  Wingate HTTP Proxy
TCP  8032  ProEd
TCP  8033  MindPrint
TCP  8080  HTTP / HTTP Proxy
TCP  8081  HTTP / HTTP Proxy
TCP  8082  BlackICE Capture
TCP  8129  Snapstream PVS Server
TCP  8130  INDIGO-VRMI
TCP  8131  INDIGO-VBCP
TCP  8160  Patrol
TCP  8161  Patrol SNMP
TCP  8181  IPSwitch IMail / Monitor
TCP  8200  TRIVNET
TCP  8201  TRIVNET
TCP  8204  LM Perfworks
TCP  8205  LM Instmgr
TCP  8206  LM Dta
TCP  8207  LM SServer
TCP  8208  LM Webwatcher
TCP  8351  Server Find
TCP  8376  Cruise ENUM
TCP  8377  Cruise SWROUTE
TCP  8378  Cruise CONFIG
TCP  8379  Cruise DIAGS
TCP  8380  Cruise UPDATE
TCP  8383  Web Email
TCP  8400  cvd
TCP  8401  sabarsd
TCP  8402  abarsd
TCP  8403  admind
TCP  8431  Micro PC-Cilin
TCP  8450  npmp
TCP  8473  Virtual Point to Point
TCP  8484  Ipswitch IMail
TCP  8554  RTSP Alternate (see port 554)
TCP  8733  iBus
TCP  8763  MC-APPSERVER
TCP  8764  OPENQUEUE
TCP  8765  Ultraseek HTTP
TCP  8804  truecm
TCP  8866  W32.Beagle.B trojan
TCP  8880  CDDBP
TCP  8888  NewsEDGE server TCP / AnswerBook2
TCP  8889  Desktop Data TCP 1
TCP  8890  Desktop Data TCP 2
TCP  8891  Desktop Data TCP 3: NESS application
TCP  8892  Desktop Data TCP 4: FARM product
TCP  8893  Desktop Data TCP 5: NewsEDGE/Web application
TCP  8894  Desktop Data TCP 6: COAL application
TCP  8900  JMB-CDS 1
TCP  8901  JMB-CDS 2
TCP  8967  Win32/Dabber (Windows worm)
TCP  8999  Firewall
TCP  9000  CSlistener
TCP  9001  cisco-xremote
TCP  9090  WebSM
TCP  9100  HP JetDirect
TCP  9160  NetLOCK1
TCP  9161  NetLOCK2
TCP  9162  NetLOCK3
TCP  9163  NetLOCK4
TCP  9164  NetLOCK5
TCP  9200  WAP connectionless session service
TCP  9201  WAP session service
TCP  9202  WAP secure connectionless session service
TCP  9203  WAP secure session service
TCP  9204  WAP vCard
TCP  9205  WAP vCal
TCP  9206  WAP vCard Secure
TCP  9207  WAP vCal Secure
TCP  9273  BackGate (Windows rootkit)
TCP  9274  BackGate (Windows rootkit)
TCP  9275  BackGate (Windows rootkit)
TCP  9276  BackGate (Windows rootkit)
TCP  9277  BackGate (Windows rootkit)
TCP  9278  BackGate (Windows rootkit)
TCP  9280  HP JetDirect Embedded Web Server
TCP  9290  HP JetDirect
TCP  9291  HP JetDirect
TCP  9292  HP JetDirect
TCP  9321  guibase
TCP  9343  MpIdcMgr
TCP  9344  Mphlpdmc
TCP  9374  fjdmimgr
TCP  9396  fjinvmgr
TCP  9397  MpIdcAgt
TCP  9400  InCommand
TCP  9500  ismserver
TCP  9535  Remote man server
TCP  9537  Remote man server, testing
TCP  9594  Message System
TCP  9595  Ping Discovery Service
TCP  9600  MICROMUSE-NCPW
TCP  9753  rasadv
TCP  9876  Session Director
TCP  9888  CYBORG Systems
TCP  9898  MonkeyCom / Win32/Dabber (Windows worm)
TCP  9899  SCTP TUNNELING
TCP  9900  IUA
TCP  9909  domaintime
TCP  9950  APCPCPLUSWIN1
TCP  9951  APCPCPLUSWIN2
TCP  9952  APCPCPLUSWIN3
TCP  9992  Palace
TCP  9993  Palace
TCP  9994  Palace
TCP  9995  Palace
TCP  9996  Sasser Worm shell / Palace
TCP  9997  Palace
TCP  9998  Distinct32
TCP  9999  distinct / Win32/Dabber (Windows worm)
TCP  10000  Webmin / Network Data Management Protocol/ Dumaru.Y (Windows trojan)
TCP  10001  queue
TCP  10002  poker
TCP  10003  gateway
TCP  10004  remp
TCP  10005  Secure telnet
TCP  10007  MVS Capacity
TCP  10012  qmaster
TCP  10080  Amanda / MyDoom.B (Windows trojan)
TCP  10082  Amanda Indexing
TCP  10083  Amanda Tape Indexing
TCP  10113  NetIQ Endpoint
TCP  10114  NetIQ Qcheck
TCP  10115  Ganymede Endpoint
TCP  10128  BMC-PERFORM-SERVICE DAEMON
TCP  10202  Computer Associate License Manager
TCP  10203  Computer Associate License Manager
TCP  10204  Computer Associate License Manager
TCP  10288  Blocks
TCP  10520  Acid Shivers (Windows Trojan)
TCP  11000  IRISA
TCP  11001  Metasys
TCP  11111  Viral Computing Environment (VCE)
TCP  11117  W32.Beagle.L trojan / URBISNET
TCP  11367  ATM UHAS
TCP  11523  AOL / AdSubtract AOL Proxy
TCP  11720  h323 Call Signal Alternate
TCP  11722  RK Test
TCP  12000  IBM Enterprise Extender SNA XID Exchange
TCP  12001  IBM Enterprise Extender SNA COS Network Priority
TCP  12002  IBM Enterprise Extender SNA COS High Priority
TCP  12003  IBM Enterprise Extender SNA COS Medium Priority
TCP  12004  IBM Enterprise Extender SNA COS Low Priority
TCP  12172  HiveP
TCP  12345  Netbus (Windows Trojan)
TCP  12346  NetBus (Windows Trojan)
TCP  12348  BioNet (Windows Trojan)
TCP  12349  BioNet (Windows Trojan)
TCP  12361  Whack-a-mole (Windows Trojan)
TCP  12362  Whack-a-mole (Windows Trojan)
TCP  12753  tsaf port
TCP  12754  DDOS communication TCP
TCP  13160  I-ZIPQD
TCP  13223  PowWow Client
TCP  13224  PowWow Server
TCP  13326  game
TCP  13720  BPRD Protocol (VERITAS NetBackup)
TCP  13721  BPBRM Protocol (VERITAS NetBackup)
TCP  13722  BP Java MSVC Protocol
TCP  13782  VERITAS NetBackup
TCP  13783  VOPIED Protnocol
TCP  13818  DSMCC Config
TCP  13819  DSMCC Session Messages
TCP  13820  DSMCC Pass-Thru Messages
TCP  13821  DSMCC Download Protocol
TCP  13822  DSMCC Channel Change Protocol
TCP  14001  ITU SCCP (SS7)
TCP  14237  Palm Network Hotsync
TCP  14247  Mitglieder.H trojan
TCP  15104  DDOS communication TCP
TCP  16360  netserialext1
TCP  16361  netserialext2
TCP  16367  netserialext3
TCP  16368  netserialext4
TCP  16660  Stacheldraht distributed attack tool client
TCP  16959  Subseven DEFCON8 2.1 backdoor remote access tool
TCP  16991  INTEL-RCI-MP
TCP  17007  isode-dua
TCP  17219  Chipper
TCP  17300  Kuang2 (Windows trojan)
TCP  17569  Infector
TCP  17990  Worldspan gateway
TCP  18000  Beckman Instruments Inc.
TCP  18181  OPSEC CVP
TCP  18182  OPSEC UFP
TCP  18183  OPSEC SAM
TCP  18184  OPSEC LEA
TCP  18185  OPSEC OMI
TCP  18187  OPSEC ELA
TCP  18463  AC Cluster
TCP  18753  Shaft distributed attack tool handler agent
TCP  18888  APCNECMP
TCP  19216  BackGate (Windows rootkit)
TCP  19283  Key Server for SASSAFRAS
TCP  19315  Key Shadow for SASSAFRAS
TCP  19410  hp-sco
TCP  19411  hp-sca
TCP  19412  HP-SESSMON
TCP  19541  JCP Client
TCP  20000  DNP
TCP  20005  xcept4 (German Telekom's CEPT videotext service)
TCP  20031  BakBone NetVault
TCP  20034  NetBus 2 Pro (Windows Trojan)
TCP  20432  Shaft distributed attack client
TCP  20670  Track
TCP  20742  Mitglieder.E trojan
TCP  20999  At Hand MMP
TCP  21554  Girlfriend (Windows Trojan)
TCP  21590  VoFR Gateway
TCP  21845  webphone
TCP  21846  NetSpeak Corp. Directory Services
TCP  21847  NetSpeak Corp. Connection Services
TCP  21848  NetSpeak Corp. Automatic Call Distribution
TCP  21849  NetSpeak Corp. Credit Processing System
TCP  22000  SNAPenetIO
TCP  22001  OptoControl
TCP  22156  Phatbot Worm
TCP  22273  wnn6
TCP  22289  Wnn6 (Chinese Input)
TCP  22305  Wnn6 (Korean Input)
TCP  22321  Wnn6 (Taiwanese Input)
TCP  22555  Vocaltec Web Conference
TCP  22800  Telerate Information Platform LAN
TCP  22951  Telerate Information Platform WAN
TCP  23005  W32.HLLW.Nettrash
TCP  23006  W32.HLLW.Nettrash
TCP  23432  Asylum
TCP  23476  Donald Dick
TCP  23477  Donald Dick
TCP  23485  Shareasa file sharing
TCP  24000  med-ltp
TCP  24001  med-fsp-rx
TCP  24002  med-fsp-tx
TCP  24003  med-supp
TCP  24004  med-ovw
TCP  24005  med-ci
TCP  24006  med-net-svc
TCP  24386  Intel RCI
TCP  24554  BINKP
TCP  25000  icl-twobase1
TCP  25001  icl-twobase2
TCP  25002  icl-twobase3
TCP  25003  icl-twobase4
TCP  25004  icl-twobase5
TCP  25005  icl-twobase6
TCP  25006  icl-twobase7
TCP  25007  icl-twobase8
TCP  25008  icl-twobase9
TCP  25009  icl-twobase10
TCP  25555  Mitglieder.D trojan
TCP  25793  Vocaltec Address Server
TCP  25867  WebCam32 Admin
TCP  26000  quake
TCP  26208  wnn6-ds
TCP  26274  Delta Source (Windows Trojan)
TCP  27347  SubSeven / Linux.Ramen.Worm (RedHat Linux)
TCP  27374  SubSeven / Linux.Ramen.Worm (RedHat Linux)
TCP  27665  Trinoo distributed attack tool Master server control port
TCP  27999  TW Authentication/Key Distribution and
TCP  30100  Netsphere (Windows Trojan)
TCP  30101  Netsphere (Windows Trojan)
TCP  30102  Netsphere (Windows Trojan)
TCP  30999  Kuang
TCP  31337  BO2K
TCP  31785  Hack-A-Tack (Windows Trojan)
TCP  31787  Hack-A-Tack (Windows Trojan)
TCP  31788  Hack-A-Tack (Windows Trojan)
TCP  31789  Hack-A-Tack (Windows Trojan)
TCP  31791  Hack-A-Tack (Windows Trojan)
TCP  32000  XtraMail v1.11
TCP  32768  Filenet TMS
TCP  32769  Filenet RPC
TCP  32770  Filenet NCH
TCP  32771  Solaris RPC
TCP  32772  Solaris RPC
TCP  32773  Solaris RPC
TCP  32774  Solaris RPC
TCP  32775  Solaris RPC
TCP  32776  Solaris RPC
TCP  32777  Solaris RPC
TCP  32780  RPC
TCP  33434  traceroute use
TCP  34324  Big Gluck (Windows Trojan)
TCP  36865  KastenX Pipe
TCP  40421  Master's Paradise (Windows Trojan)
TCP  40422  Master's Paradise (Windows Trojan)
TCP  40423  Master's Paradise (Windows Trojan)
TCP  40426  Master's Paradise (Windows Trojan)
TCP  40841  CSCP
TCP  42424  ASP.NET Session State
TCP  43118  Reachout
TCP  43188  Reachout
TCP  44333  Kerio WinRoute Firewall Administration
TCP  44334  Kerio Personal Firewall Administration
TCP  44337  Kerio MailServer Administration
TCP  44444  Prosiak
TCP  44818  Rockwell Encapsulation
TCP  45092  BackGate (Windows rootkit)
TCP  45678  EBA PRISE
TCP  45966  SSRServerMgr
TCP  47262  Delta Source (Windows Trojan)
TCP  47557  Databeam Corporation
TCP  47624  Direct Play Server
TCP  47806  ALC Protocol
TCP  47808  Building Automation and Control Networks
TCP  48000  Nimbus Controller
TCP  48001  Nimbus Spooler
TCP  48002  Nimbus Hub
TCP  48003  Nimbus Gateway
TCP  49400  Compaq Insight Manager
TCP  49401  Compaq Insight Manager
TCP  50300  O&O Defrag
TCP  51515  Microsoft Operations Manager MOM-Clear
TCP  52673  Stickies
TCP  54283  SubSeven
TCP  54320  Orifice 2000 (TCP)
TCP  54321  Orifice 2000 (TCP)
TCP  60000  DeepThroat
TCP  65000  distributed attack tool / Devil (Windows Trojan)
TCP  65301  pcAnywhere-def
TCP  65506  PhatBot, Agobot, Gaobot (Windows trojans)

Up to the TCP port list
UDP Ports

UDP  0  Reserved
UDP  1  Port Service Multiplexer
UDP  2  Management Utility
UDP  3  Compression Process
UDP  4  Unassigned
UDP  5  Remote Job Entry
UDP  6  Unassigned
UDP  7  Echo
UDP  8  Unassigned
UDP  9  Discard
UDP  10  Unassigned
UDP  11  Active Users
UDP  12  Unassigned
UDP  13  Daytime
UDP  14  Unassigned
UDP  15  Unassigned
UDP  16  Unassigned
UDP  17  Quote of the Day
UDP  18  Message Send Protocol
UDP  19  Character Generator
UDP  20  File Transfer [Default Data]
UDP  21  File Transfer [Control]
UDP  22  SSH Remote Login Protocol
UDP  23  Telnet
UDP  24  any private mail system
UDP  25  Simple Mail Transfer
UDP  26  Unassigned
UDP  27  NSW User System FE
UDP  28  Unassigned
UDP  29  MSG ICP
UDP  30  Unassigned
UDP  31  MSG Authentication
UDP  32  Unassigned
UDP  33  Display Support Protocol
UDP  34  Unassigned
UDP  35  any private printer server
UDP  36  Unassigned
UDP  37  Time
UDP  38  Route Access Protocol
UDP  39  Resource Location Protocol
UDP  40  Unassigned
UDP  41  Graphics
UDP  42  Host Name Server
UDP  43  Who Is
UDP  44  MPM FLAGS Protocol
UDP  45  Message Processing Module [recv]
UDP  46  MPM [default send]
UDP  47  NI FTP
UDP  48  Digital Audit Daemon
UDP  49  Login Host Protocol (TACACS)
UDP  50  Remote Mail Checking Protocol
UDP  51  IMP Logical Address Maintenance
UDP  52  XNS Time Protocol
UDP  53  Domain Name Server
UDP  54  XNS Clearinghouse
UDP  55  ISI Graphics Language
UDP  56  XNS Authentication
UDP  57  any private terminal access
UDP  58  XNS Mail
UDP  59  any private file service
UDP  60  Unassigned
UDP  61  NI MAIL
UDP  62  ACA Services
UDP  63  whois++
UDP  64  Communications Integrator (CI)
UDP  65  TACACS-Database Service
UDP  66  Oracle SQL*NET
UDP  67  Bootstrap Protocol Server
UDP  68  Bootstrap Protocol Client
UDP  69  Trivial File Transfer
UDP  70  Gopher
UDP  71  Remote Job Service
UDP  72  Remote Job Service
UDP  73  Remote Job Service
UDP  74  Remote Job Service
UDP  75  any private dial out service
UDP  76  Distributed External Object Store
UDP  77  any private RJE service
UDP  78  vettcp
UDP  79  Finger
UDP  80  World Wide Web HTTP
UDP  81  HOSTS2 Name Server
UDP  82  XFER Utility
UDP  83  MIT ML Device
UDP  84  Common Trace Facility
UDP  85  MIT ML Device
UDP  86  Micro Focus Cobol
UDP  87  any private terminal link
UDP  88  Kerberos
UDP  89  SU/MIT Telnet Gateway
UDP  90  DNSIX Securit Attribute Token Map
UDP  91  MIT Dover Spooler
UDP  92  Network Printing Protocol
UDP  93  Device Control Protocol
UDP  94  Tivoli Object Dispatcher
UDP  95  SUPDUP
UDP  96  DIXIE Protocol Specification
UDP  97  Swift Remote Virtural File Protocol
UDP  98  TAC News
UDP  99  Metagram Relay
UDP  101  NIC Host Name Server
UDP  102  ISO-TSAP Class 0
UDP  103  Genesis Point-to-Point Trans Net
UDP  104  ACR-NEMA Digital Imag. & Comm. 300
UDP  105  Mailbox Name Nameserver
UDP  106  3COM-TSMUX
UDP  107  Remote Telnet Service
UDP  108  SNA Gateway Access Server
UDP  109  Post Office Protocol - Version 2
UDP  110  Post Office Protocol - Version 3
UDP  111  SUN Remote Procedure Call
UDP  112  McIDAS Data Transmission Protocol
UDP  113  Authentication Service
UDP  114  Audio News Multicast
UDP  115  Simple File Transfer Protocol
UDP  116  ANSA REX Notify
UDP  117  UUCP Path Service
UDP  118  SQL Services
UDP  119  Network News Transfer Protocol
UDP  120  CFDPTKT
UDP  121  Encore Expedited Remote Pro.Call
UDP  122  SMAKYNET
UDP  123  Network Time Protocol
UDP  124  ANSA REX Trader
UDP  125  Locus PC-Interface Net Map Ser
UDP  126  Unisys Unitary Login
UDP  127  Locus PC-Interface Conn Server
UDP  128  GSS X License Verification
UDP  129  Password Generator Protocol
UDP  130  cisco FNATIVE
UDP  131  cisco TNATIVE
UDP  132  cisco SYSMAINT
UDP  133  Statistics Service
UDP  134  INGRES-NET Service
UDP  135  DCE endpoint resolution
UDP  136  PROFILE Naming System
UDP  137  NETBIOS Name Service
UDP  138  NETBIOS Datagram Service
UDP  139  NETBIOS Session Service
UDP  140  EMFIS Data Service
UDP  141  EMFIS Control Service
UDP  142  Britton-Lee IDM
UDP  143  Internet Message Access Protocol
UDP  144  Universal Management Architecture
UDP  145  UAAC Protocol
UDP  146  ISO-IP0
UDP  147  ISO-IP
UDP  148  Jargon
UDP  149  AED 512 Emulation Service
UDP  150  SQL-NET
UDP  151  HEMS
UDP  152  Background File Transfer Program
UDP  153  SGMP
UDP  154  NETSC
UDP  155  NETSC
UDP  156  SQL Service
UDP  157  KNET/VM Command/Message Protocol
UDP  158  PCMail Server
UDP  159  NSS-Routing
UDP  160  SGMP-TRAPS
UDP  161  SNMP
UDP  162  SNMPTRAP
UDP  163  CMIP/TCP Manager
UDP  164  CMIP/TCP Agent
UDP  165  Xerox
UDP  166  Sirius Systems
UDP  167  NAMP
UDP  168  RSVD
UDP  169  SEND
UDP  170  Network PostScript
UDP  171  Network Innovations Multiplex
UDP  172  Network Innovations CL/1
UDP  173  Xyplex
UDP  174  MAILQ
UDP  175  VMNET
UDP  176  GENRAD-MUX
UDP  177  X Display Manager Control Protocol
UDP  178  NextStep Window Server
UDP  179  Border Gateway Protocol
UDP  180  Intergraph
UDP  181  Unify
UDP  182  Unisys Audit SITP
UDP  183  OCBinder
UDP  184  OCServer
UDP  185  Remote-KIS
UDP  186  KIS Protocol
UDP  187  Application Communication Interface
UDP  188  Plus Five's MUMPS
UDP  189  Queued File Transport
UDP  190  Gateway Access Control Protocol
UDP  191  Prospero Directory Service
UDP  192  OSU Network Monitoring System
UDP  193  Spider Remote Monitoring Protocol
UDP  194  Internet Relay Chat Protocol
UDP  195  DNSIX Network Level Module Audit
UDP  196  DNSIX Session Mgt Module Audit Redir
UDP  197  Directory Location Service
UDP  198  Directory Location Service Monitor
UDP  199  SMUX
UDP  200  IBM System Resource Controller
UDP  201  AppleTalk Routing Maintenance
UDP  202  AppleTalk Name Binding
UDP  203  AppleTalk Unused
UDP  204  AppleTalk Echo
UDP  205  AppleTalk Unused
UDP  206  AppleTalk Zone Information
UDP  207  AppleTalk Unused
UDP  208  AppleTalk Unused
UDP  209  The Quick Mail Transfer Protocol
UDP  210  ANSI Z39.50
UDP  211  Texas Instruments 914C/G Terminal
UDP  212  ATEXSSTR
UDP  213  IPX
UDP  214  VM PWSCS
UDP  215  Insignia Solutions
UDP  216  Computer Associates Int'l License Server
UDP  217  dBASE Unix
UDP  218  Netix Message Posting Protocol
UDP  219  Unisys ARPs
UDP  220  Interactive Mail Access Protocol v3
UDP  221  Berkeley rlogind with SPX auth
UDP  222  Berkeley rshd with SPX auth
UDP  223  Certificate Distribution Center
UDP  224  masqdialer
UDP  242  Direct
UDP  243  Survey Measurement
UDP  244  inbusiness
UDP  245  LINK
UDP  246  Display Systems Protocol
UDP  247  SUBNTBCST_TFTP
UDP  248  bhfhs
UDP  256  RAP
UDP  257  Secure Electronic Transaction
UDP  258  Yak Winsock Personal Chat
UDP  259  Efficient Short Remote Operations
UDP  260  Openport
UDP  261  IIOP Name Service over TLS/SSL
UDP  262  Arcisdms
UDP  263  HDAP
UDP  264  BGMP
UDP  265  X-Bone CTL
UDP  266  SCSI on ST
UDP  267  Tobit David Service Layer
UDP  268  Tobit David Replica
UDP  280  HTTP-mgmt
UDP  281  Personal Link
UDP  282  Cable Port A/X
UDP  283  rescap
UDP  284  corerjd
UDP  286  FXP-1
UDP  287  K-BLOCK
UDP  308  Novastor Backup
UDP  309  EntrustTime
UDP  310  bhmds
UDP  311  AppleShare IP WebAdmin
UDP  312  VSLMP
UDP  313  Magenta Logic
UDP  314  Opalis Robot
UDP  315  DPSI
UDP  316  decAuth
UDP  317  Zannet
UDP  318  PKIX TimeStamp
UDP  319  PTP Event
UDP  320  PTP General
UDP  321  PIP
UDP  322  RTSPS
UDP  333  Texar Security Port
UDP  344  Prospero Data Access Protocol
UDP  345  Perf Analysis Workbench
UDP  346  Zebra server
UDP  347  Fatmen Server
UDP  348  Cabletron Management Protocol
UDP  349  mftp
UDP  350  MATIP Type A
UDP  351  bhoetty
UDP  352  bhoedap4
UDP  353  NDSAUTH
UDP  354  bh611
UDP  355  DATEX-ASN
UDP  356  Cloanto Net 1
UDP  357  bhevent
UDP  358  Shrinkwrap
UDP  359  Tenebris Network Trace Service
UDP  360  scoi2odialog
UDP  361  Semantix
UDP  362  SRS Send
UDP  363  RSVP Tunnel
UDP  364  Aurora CMGR
UDP  365  DTK
UDP  366  ODMR
UDP  367  MortgageWare
UDP  368  QbikGDP
UDP  369  rpc2portmap
UDP  370  codaauth2
UDP  371  Clearcase
UDP  372  ListProcessor
UDP  373  Legent Corporation
UDP  374  Legent Corporation
UDP  375  Hassle
UDP  376  Amiga Envoy Network Inquiry Proto
UDP  377  NEC Corporation
UDP  378  NEC Corporation
UDP  379  TIA/EIA/IS-99 modem client
UDP  380  TIA/EIA/IS-99 modem server
UDP  381  hp performance data collector
UDP  382  hp performance data managed node
UDP  383  hp performance data alarm manager
UDP  384  A Remote Network Server System
UDP  385  IBM Application
UDP  386  ASA Message Router Object Def.
UDP  387  Appletalk Update-Based Routing Pro.
UDP  388  Unidata LDM
UDP  389  Lightweight Directory Access Protocol
UDP  390  UIS
UDP  391  SynOptics SNMP Relay Port
UDP  392  SynOptics Port Broker Port
UDP  393  Data Interpretation System
UDP  394  EMBL Nucleic Data Transfer
UDP  395  NETscout Control Protocol
UDP  396  Novell Netware over IP
UDP  397  Multi Protocol Trans. Net.
UDP  398  Kryptolan
UDP  399  ISO Transport Class 2 Non-Control over TCP
UDP  400  Workstation Solutions
UDP  401  Uninterruptible Power Supply
UDP  402  Genie Protocol
UDP  403  decap
UDP  404  nced
UDP  405  ncld
UDP  406  Interactive Mail Support Protocol
UDP  407  Timbuktu
UDP  408  Prospero Resource Manager Sys. Man.
UDP  409  Prospero Resource Manager Node Man.
UDP  410  DECLadebug Remote Debug Protocol
UDP  411  Remote MT Protocol
UDP  412  Trap Convention Port
UDP  413  SMSP
UDP  414  InfoSeek
UDP  415  BNet
UDP  416  Silverplatter
UDP  417  Onmux
UDP  418  Hyper-G
UDP  419  Ariel
UDP  420  SMPTE
UDP  421  Ariel
UDP  422  Ariel
UDP  423  IBM Operations Planning and Control Start
UDP  424  IBM Operations Planning and Control Track
UDP  425  ICAD
UDP  426  smartsdp
UDP  427  Server Location
UDP  428  OCS_CMU
UDP  429  OCS_AMU
UDP  430  UTMPSD
UDP  431  UTMPCD
UDP  432  IASD
UDP  433  NNSP
UDP  434  MobileIP-Agent
UDP  435  MobilIP-MN
UDP  436  DNA-CML
UDP  437  comscm
UDP  438  dsfgw
UDP  439  dasp
UDP  440  sgcp
UDP  441  decvms-sysmgt
UDP  442  cvc_hostd
UDP  443  HTTP protocol over TLS/SSL
UDP  444  Simple Network Paging Protocol
UDP  445  Microsoft-DS
UDP  446  DDM-RDB
UDP  447  DDM-RFM
UDP  448  DDM-SSL
UDP  449  AS Server Mapper
UDP  450  TServer
UDP  451  Cray Network Semaphore server
UDP  452  Cray SFS config server
UDP  453  CreativeServer
UDP  454  ContentServer
UDP  455  CreativePartnr
UDP  456  macon-udp
UDP  457  scohelp
UDP  458  apple quick time
UDP  459  ampr-rcmd
UDP  460  skronk
UDP  461  DataRampSrv
UDP  462  DataRampSrvSec
UDP  463  alpes
UDP  464  kpasswd
UDP  465  SMTP protocol over TLS/SSL
UDP  466  digital-vrc
UDP  467  mylex-mapd
UDP  468  proturis
UDP  469  Radio Control Protocol
UDP  470  scx-proxy
UDP  471  Mondex
UDP  472  ljk-login
UDP  473  hybrid-pop
UDP  474  tn-tl-w2
UDP  475  tcpnethaspsrv
UDP  476  tn-tl-fd1
UDP  477  ss7ns
UDP  478  spsc
UDP  479  iafserver
UDP  480  iafdbase
UDP  481  Ph service
UDP  482  bgs-nsi
UDP  483  ulpnet
UDP  484  Integra Software Management Environment
UDP  485  Air Soft Power Burst
UDP  486  avian
UDP  487  saft Simple Asynchronous File Transfer
UDP  488  gss-HTTP
UDP  489  nest-protocol
UDP  490  micom-pfs
UDP  491  go-login
UDP  492  Transport Independent Convergence for FNA
UDP  493  Transport Independent Convergence for FNA
UDP  494  POV-Ray
UDP  495  intecourier
UDP  496  PIM-RP-DISC
UDP  497  dantz
UDP  498  siam
UDP  499  ISO ILL Protocol
UDP  500  ISAKMP
UDP  501  STMF
UDP  502  asa-appl-proto
UDP  503  Intrinsa
UDP  504  citadel
UDP  505  mailbox-lm
UDP  506  ohimsrv
UDP  507  crs
UDP  508  xvttp
UDP  509  snare
UDP  510  FirstClass Protocol
UDP  511  PassGo
UDP  512  used by mail system to notify users
UDP  513  maintains data bases showing who's
UDP  514  BSD syslogd
UDP  515  spooler
UDP  516  videotex
UDP  517  like tenex link but across
UDP  518  talkd
UDP  519  unixtime
UDP  520  Routing Information Protocol
UDP  521  ripng
UDP  522  ULP
UDP  523  IBM-DB2
UDP  524  NCP
UDP  525  timeserver
UDP  526  newdate
UDP  527  Stock IXChange
UDP  528  Customer IXChange
UDP  529  IRC-SERV
UDP  530  rpc
UDP  531  chat
UDP  532  readnews
UDP  533  for emergency broadcasts
UDP  534  MegaMedia Admin
UDP  535  iiop
UDP  536  opalis-rdv
UDP  537  Networked Media Streaming Protocol
UDP  538  gdomap
UDP  539  Apertus Technologies Load Determination
UDP  540  uucpd
UDP  541  uucp-rlogin
UDP  542  commerce
UDP  543  kerberos (v4/v5)
UDP  544  krcmd
UDP  545  appleqtcsrvr
UDP  546  DHCPv6 Client
UDP  547  DHCPv6 Server
UDP  548  AFP over TCP
UDP  549  IDFP
UDP  550  new-who
UDP  551  cybercash
UDP  552  deviceshare
UDP  553  pirp
UDP  554  Real Time Stream Control Protocol
UDP  555  phAse Zero backdoor (Windows) / dsf
UDP  556  rfs server
UDP  557  openvms-sysipc
UDP  558  SDNSKMP
UDP  559  TEEDTAP
UDP  560  rmonitord
UDP  561  monitor
UDP  562  chcmd
UDP  563  NNTP protocol over TLS/SSL
UDP  564  plan 9 file service
UDP  565  whoami
UDP  566  streettalk
UDP  567  banyan-rpc
UDP  568  microsoft shuttle
UDP  569  microsoft rome
UDP  570  demon
UDP  571  udemon
UDP  572  sonar
UDP  573  banyan-vip
UDP  574  FTP Software Agent System
UDP  575  VEMMI
UDP  576  ipcd
UDP  577  vnas
UDP  578  ipdd
UDP  579  decbsrv
UDP  580  SNTP HEARTBEAT
UDP  581  Bundle Discovery Protocol
UDP  582  SCC Security
UDP  583  Philips Video-Conferencing
UDP  584  Key Server
UDP  585  IMAP4+SSL
UDP  586  Password Change
UDP  587  Submission
UDP  588  CAL
UDP  589  EyeLink
UDP  590  TNS CML
UDP  591  FileMaker Inc. - HTTP Alternate
UDP  592  Eudora Set
UDP  593  HTTP RPC Ep Map
UDP  594  TPIP
UDP  595  CAB Protocol
UDP  596  SMSD
UDP  597  PTC Name Service
UDP  598  SCO Web Server Manager 3
UDP  599  Aeolon Core Protocol
UDP  600  Sun IPC server
UDP  606  Cray Unified Resource Manager
UDP  607  nqs
UDP  608  Sender-Initiated/Unsolicited File Transfer
UDP  609  npmp-trap
UDP  610  npmp-local
UDP  611  npmp-gui
UDP  612  HMMP Indication
UDP  613  HMMP Operation
UDP  614  SSLshell
UDP  615  Internet Configuration Manager
UDP  616  SCO System Administration Server
UDP  617  SCO Desktop Administration Server
UDP  618  DEI-ICDA
UDP  619  Digital EVM
UDP  620  SCO WebServer Manager
UDP  621  ESCP
UDP  622  Collaborator
UDP  623  Aux Bus Shunt
UDP  624  Crypto Admin
UDP  625  DEC DLM
UDP  626  ASIA
UDP  627  PassGo Tivoli
UDP  628  QMQP
UDP  629  3Com AMP3
UDP  630  RDA
UDP  631  IPP (Internet Printing Protocol)
UDP  632  bmpp
UDP  633  Service Status update (Sterling Software)
UDP  634  ginad
UDP  635  RLZ DBase
UDP  636  LDAP protocol over TLS/SSL
UDP  637  lanserver
UDP  638  mcns-sec
UDP  639  MSDP
UDP  640  entrust-sps
UDP  641  repcmd
UDP  642  ESRO-EMSDP V1.3
UDP  643  SANity
UDP  644  dwr
UDP  645  PSSC
UDP  646  LDP
UDP  647  DHCP Failover
UDP  648  Registry Registrar Protocol (RRP)
UDP  649  Aminet
UDP  650  OBEX
UDP  651  IEEE MMS
UDP  652  UDLR_DTCP
UDP  653  RepCmd
UDP  654  AODV
UDP  655  TINC
UDP  656  SPMP
UDP  657  RMC
UDP  658  TenFold
UDP  659  URL Rendezvous
UDP  660  MacOS Server Admin
UDP  661  HAP
UDP  662  PFTP
UDP  663  PureNoise
UDP  664  Secure Aux Bus
UDP  665  Sun DR
UDP  666  doom Id Software
UDP  667  campaign contribution disclosures - SDR Technologies
UDP  668  MeComm
UDP  669  MeRegister
UDP  670  VACDSM-SWS
UDP  671  VACDSM-APP
UDP  672  VPPS-QUA
UDP  673  CIMPLEX
UDP  674  ACAP
UDP  675  DCTP
UDP  676  VPPS Via
UDP  677  Virtual Presence Protocol
UDP  678  GNU Generation Foundation NCP
UDP  679  MRM
UDP  680  entrust-aaas
UDP  681  entrust-aams
UDP  682  XFR
UDP  683  CORBA IIOP
UDP  684  CORBA IIOP SSL
UDP  685  MDC Port Mapper
UDP  686  Hardware Control Protocol Wismar
UDP  687  asipregistry
UDP  688  REALM-RUSD
UDP  689  NMAP
UDP  690  VATP
UDP  691  MS Exchange Routing
UDP  692  Hyperwave-ISP
UDP  693  connendp
UDP  694  ha-cluster
UDP  695  IEEE-MMS-SSL
UDP  696  RUSHD
UDP  697  UUIDGEN
UDP  698  OLSR
UDP  704  errlog copy/server daemon
UDP  705  AgentX
UDP  706  SILC
UDP  707  Borland DSJ
UDP  709  Entrust Key Management Service Handler
UDP  710  Entrust Administration Service Handler
UDP  711  Cisco TDP
UDP  729  IBM NetView DM/6000 Server/Client
UDP  730  IBM NetView DM/6000 send/tcp
UDP  731  IBM NetView DM/6000 receive/tcp
UDP  740  (old) NETscout Control Protocol (old)
UDP  741  netGW
UDP  742  Network based Rev. Cont. Sys.
UDP  744  Flexible License Manager
UDP  747  Fujitsu Device Control
UDP  748  Russell Info Sci Calendar Manager
UDP  749  kerberos administration
UDP  750  kerberos version iv
UDP  751  pump
UDP  752  Kerberos password server
UDP  753  Kerberos userreg server
UDP  754  send
UDP  758  nlogin
UDP  759  con
UDP  760  ns
UDP  761  rxe
UDP  762  quotad
UDP  763  cycleserv
UDP  764  omserv
UDP  765  webster
UDP  767  phone
UDP  769  vid
UDP  770  cadlock
UDP  771  rtip
UDP  772  cycleserv2
UDP  773  notify
UDP  774  acmaint_dbd
UDP  775  acmaint_transd
UDP  776  wpages
UDP  777  Multiling HTTP
UDP  780  wpgs
UDP  781  HP performance data collector
UDP  782  node HP performance data managed node
UDP  783  HP performance data alarm manager
UDP  786  Concert
UDP  787  QSC
UDP  800  mdbs_daemon
UDP  801  device
UDP  810  FCP Datagram
UDP  828  itm-mcell-s
UDP  829  PKIX-3 CA/RA
UDP  873  rsync
UDP  886  ICL coNETion locate server
UDP  887  ICL coNETion server info
UDP  888  AccessBuilder
UDP  900  OMG Initial Refs
UDP  901  SMPNAMERES
UDP  902  IDEAFARM-CHAT
UDP  903  IDEAFARM-CATCH
UDP  911  xact-backup
UDP  989  FTP protocol data over TLS/SSL
UDP  990  FTP protocol control over TLS/SSL
UDP  991  Netnews Administration System
UDP  992  Telnet protocol over TLS/SSL
UDP  993  IMAP4 protocol over TLS/SSL
UDP  994  IRC protocol over TLS/SSL
UDP  995  POP3 protocol over TLS/SSL / W32/Sobig virus
UDP  996  vsinet / W32/Sobig virus
UDP  997  maitrd / W32/Sobig virus
UDP  998  puparp / W32/Sobig virus
UDP  999  Applix ac / W32/Sobig virus
UDP  1000  ock
UDP  1008  Solaris
UDP  1010  surf
UDP  1012  This is rstatd on a openBSD box
UDP  1023  Reserved
UDP  1024  Reserved
UDP  1025  network blackjack
UDP  1030  BBN IAD
UDP  1031  BBN IAD
UDP  1032  BBN IAD
UDP  1047  Sun's NEO Object Request Broker
UDP  1048  Sun's NEO Object Request Broker
UDP  1049  Tobit David Postman VPMN
UDP  1050  CORBA Management Agent
UDP  1051  Optima VNET
UDP  1052  Dynamic DNS Tools
UDP  1053  Remote Assistant (RA)
UDP  1054  BRVREAD
UDP  1055  ANSYS - License Manager
UDP  1056  VFO
UDP  1057  STARTRON
UDP  1058  nim
UDP  1059  nimreg
UDP  1060  POLESTAR
UDP  1061  KIOSK
UDP  1062  Veracity
UDP  1063  KyoceraNetDev
UDP  1064  JSTEL
UDP  1065  SYSCOMLAN
UDP  1066  FPO-FNS
UDP  1067  Installation Bootstrap Proto. Serv.
UDP  1068  Installation Bootstrap Proto. Cli.
UDP  1069  COGNEX-INSIGHT
UDP  1070  GMRUpdateSERV
UDP  1071  BSQUARE-VOIP
UDP  1072  CARDAX
UDP  1073  BridgeControl
UDP  1074  FASTechnologies License Manager
UDP  1075  RDRMSHC
UDP  1076  DAB STI-C
UDP  1077  IMGames
UDP  1078  eManageCstp
UDP  1079  ASPROVATalk
UDP  1080  Socks
UDP  1081  PVUNIWIEN
UDP  1082  AMT-ESD-PROT
UDP  1083  Anasoft License Manager
UDP  1084  Anasoft License Manager
UDP  1085  Web Objects
UDP  1086  CPL Scrambler Logging
UDP  1087  CPL Scrambler Internal
UDP  1088  CPL Scrambler Alarm Log
UDP  1089  FF Annunciation
UDP  1090  FF Fieldbus Message Specification
UDP  1091  FF System Management
UDP  1092  OBRPD
UDP  1093  PROOFD
UDP  1094  ROOTD
UDP  1095  NICELink
UDP  1096  Common Name Resolution Protocol
UDP  1097  Sun Cluster Manager
UDP  1098  RMI Activation
UDP  1099  RMI Registry
UDP  1100  MCTP
UDP  1101  PT2-DISCOVER
UDP  1102  ADOBE SERVER 1
UDP  1103  ADOBE SERVER 2
UDP  1104  XRL
UDP  1105  FTRANHC
UDP  1106  ISOIPSIGPORT-1
UDP  1107  ISOIPSIGPORT-2
UDP  1108  ratio-adp
UDP  1110  Client status info
UDP  1111  LM Social Server
UDP  1112  Intelligent Communication Protocol
UDP  1114  Mini SQL
UDP  1115  ARDUS Transfer
UDP  1116  ARDUS Control
UDP  1117  ARDUS Multicast Transfer
UDP  1123  Murray
UDP  1155  Network File Access
UDP  1161  Health Polling
UDP  1162  Health Trap
UDP  1167  conference calling
UDP  1169  TRIPWIRE
UDP  1180  Millicent Client Proxy
UDP  1188  HP Web Admin
UDP  1200  SCOL
UDP  1201  Nucleus Sand
UDP  1202  caiccipc
UDP  1203  License Validation
UDP  1204  Log Request Listener
UDP  1205  Accord-MGC
UDP  1206  Anthony Data
UDP  1207  MetaSage
UDP  1208  SEAGULL AIS
UDP  1209  IPCD3
UDP  1210  EOSS
UDP  1211  Groove DPP
UDP  1212  lupa
UDP  1213  MPC LIFENET
UDP  1214  KAZAA
UDP  1215  scanSTAT 1.0
UDP  1216  ETEBAC 5
UDP  1217  HPSS-NDAPI
UDP  1218  AeroFlight-ADs
UDP  1219  AeroFlight-Ret
UDP  1220  QT SERVER ADMIN
UDP  1221  SweetWARE Apps
UDP  1222  SNI R&D network
UDP  1223  TGP
UDP  1224  VPNz
UDP  1225  SLINKYSEARCH
UDP  1226  STGXFWS
UDP  1227  DNS2Go
UDP  1228  FLORENCE
UDP  1229  Novell ZFS
UDP  1234  Infoseek Search Agent
UDP  1239  NMSD
UDP  1248  hermes
UDP  1300  H323 Host Call Secure
UDP  1310  Husky
UDP  1311  RxMon
UDP  1312  STI Envision
UDP  1313  BMC_PATROLDB
UDP  1314  Photoscript Distributed Printing System
UDP  1319  Panja-ICSP
UDP  1320  Panja-AXBNET
UDP  1321  PIP
UDP  1335  Digital Notary Protocol
UDP  1345  VPJP
UDP  1346  Alta Analytics License Manager
UDP  1347  multi media conferencing
UDP  1348  multi media conferencing
UDP  1349  Registration Network Protocol
UDP  1350  Registration Network Protocol
UDP  1351  Digital Tool Works (MIT)
UDP  1352  Lotus Note
UDP  1353  Relief Consulting
UDP  1354  RightBrain Software
UDP  1355  Intuitive Edge
UDP  1356  CuillaMartin Company
UDP  1357  Electronic PegBoard
UDP  1358  CONNLCLI
UDP  1359  FTSRV
UDP  1360  MIMER
UDP  1361  LinX
UDP  1362  TimeFlies
UDP  1363  Network DataMover Requester
UDP  1364  Network DataMover Server
UDP  1365  Network Software Associates
UDP  1366  Novell NetWare Comm Service Platform
UDP  1367  DCS
UDP  1368  ScreenCast
UDP  1369  GlobalView to Unix Shell
UDP  1370  Unix Shell to GlobalView
UDP  1371  Fujitsu Config Protocol
UDP  1372  Fujitsu Config Protocol
UDP  1373  Chromagrafx
UDP  1374  EPI Software Systems
UDP  1375  Bytex
UDP  1376  IBM Person to Person Software
UDP  1377  Cichlid License Manager
UDP  1378  Elan License Manager
UDP  1379  Integrity Solutions
UDP  1380  Telesis Network License Manager
UDP  1381  Apple Network License Manager
UDP  1382  udt_os
UDP  1383  GW Hannaway Network License Manager
UDP  1384  Objective Solutions License Manager
UDP  1385  Atex Publishing License Manager
UDP  1386  CheckSum License Manager
UDP  1387  Computer Aided Design Software Inc LM
UDP  1388  Objective Solutions DataBase Cache
UDP  1389  Document Manager
UDP  1390  Storage Controller
UDP  1391  Storage Access Server
UDP  1392  Print Manager
UDP  1393  Network Log Server
UDP  1394  Network Log Client
UDP  1395  PC Workstation Manager software
UDP  1396  DVL Active Mail
UDP  1397  Audio Active Mail
UDP  1398  Video Active Mail
UDP  1399  Cadkey License Manager
UDP  1400  Cadkey Tablet Daemon
UDP  1401  Goldleaf License Manager
UDP  1402  Prospero Resource Manager
UDP  1403  Prospero Resource Manager
UDP  1404  Infinite Graphics License Manager
UDP  1405  IBM Remote Execution Starter
UDP  1406  NetLabs License Manager
UDP  1407  DBSA License Manager
UDP  1408  Sophia License Manager
UDP  1409  Here License Manager
UDP  1410  HiQ License Manager
UDP  1411  AudioFile
UDP  1412  InnoSys
UDP  1413  Innosys-ACL
UDP  1414  IBM MQSeries
UDP  1415  DBStar
UDP  1416  Novell LU6.2
UDP  1417  Timbuktu Service 1 Port
UDP  1418  Timbuktu Service 2 Port
UDP  1419  Timbuktu Service 3 Port
UDP  1420  Timbuktu Service 4 Port
UDP  1421  Gandalf License Manager
UDP  1422  Autodesk License Manager
UDP  1423  Essbase Arbor Software
UDP  1424  Hybrid Encryption Protocol
UDP  1425  Zion Software License Manager
UDP  1426  Satellite-data Acquisition System 1
UDP  1427  mloadd monitoring tool
UDP  1428  Informatik License Manager
UDP  1429  Hypercom NMS
UDP  1430  Hypercom TPDU
UDP  1431  Reverse Gossip Transport
UDP  1432  Blueberry Software License Manager
UDP  1433  Microsoft-SQL-Server
UDP  1434  Microsoft-SQL-Monitor
UDP  1435  IBM CICS
UDP  1436  Satellite-data Acquisition System 2
UDP  1437  Tabula
UDP  1438  Eicon Security Agent/Server
UDP  1439  Eicon X25/SNA Gateway
UDP  1440  Eicon Service Location Protocol
UDP  1441  Cadis License Management
UDP  1442  Cadis License Management
UDP  1443  Integrated Engineering Software
UDP  1444  Marcam License Management
UDP  1445  Proxima License Manager
UDP  1446  Optical Research Associates License Manager
UDP  1447  Applied Parallel Research LM
UDP  1448  OpenConnect License Manager
UDP  1449  PEport
UDP  1450  Tandem Distributed Workbench Facility
UDP  1451  IBM Information Management
UDP  1452  GTE Government Systems License Man
UDP  1453  Genie License Manager
UDP  1454  interHDL License Manager
UDP  1455  ESL License Manager
UDP  1456  DCA
UDP  1457  Valisys License Manager
UDP  1458  Nichols Research Corp.
UDP  1459  Proshare Notebook Application
UDP  1460  Proshare Notebook Application
UDP  1461  IBM Wireless LAN
UDP  1462  World License Manager
UDP  1463  Nucleus
UDP  1464  MSL License Manager
UDP  1465  Pipes Platform mfarlin@peerlogic.com
UDP  1466  Ocean Software License Manager
UDP  1467  CSDMBASE
UDP  1468  CSDM
UDP  1469  Active Analysis Limited License Manager
UDP  1470  Universal Analytics
UDP  1471  csdmbase
UDP  1472  csdm
UDP  1473  OpenMath
UDP  1474  Telefinder
UDP  1475  Taligent License Manager
UDP  1476  clvm-cfg
UDP  1477  ms-sna-server
UDP  1478  ms-sna-base
UDP  1479  dberegister
UDP  1480  PacerForum
UDP  1481  AIRS
UDP  1482  Miteksys License Manager
UDP  1483  AFS License Manager
UDP  1484  Confluent License Manager
UDP  1485  LANSource
UDP  1486  nms_topo_serv
UDP  1487  LocalInfoSrvr
UDP  1488  DocStor
UDP  1489  dmdocbroker
UDP  1490  insitu-conf
UDP  1491  anynetgateway
UDP  1492  stone-design-1
UDP  1493  netmap_lm
UDP  1494  ica
UDP  1495  cvc
UDP  1496  liberty-lm
UDP  1497  rfx-lm
UDP  1498  Sybase SQL Any
UDP  1499  Federico Heinz Consultora
UDP  1500  VLSI License Manager
UDP  1501  Satellite-data Acquisition System 3
UDP  1502  Shiva
UDP  1503  Databeam
UDP  1504  EVB Software Engineering License Manager
UDP  1505  Funk Software Inc.
UDP  1506  Universal Time daemon (utcd)
UDP  1507  symplex
UDP  1508  diagmond
UDP  1509  Robcad Ltd. License Manager
UDP  1510  Midland Valley Exploration Ltd. Lic. Man.
UDP  1511  3l-l1
UDP  1512  Microsoft's Windows Internet Name Service
UDP  1513  Fujitsu Systems Business of America Inc
UDP  1514  Fujitsu Systems Business of America Inc
UDP  1515  ifor-protocol
UDP  1516  Virtual Places Audio data
UDP  1517  Virtual Places Audio control
UDP  1518  Virtual Places Video data
UDP  1519  Virtual Places Video control
UDP  1520  atm zip office
UDP  1521  nCube License Manager
UDP  1522  Ricardo North America License Manager
UDP  1523  cichild
UDP  1524  ingres
UDP  1525  Prospero Directory Service non-priv
UDP  1526  Prospero Data Access Prot non-priv
UDP  1527  oracle
UDP  1528  micautoreg
UDP  1529  oracle
UDP  1530  rap-service
UDP  1531  rap-listen
UDP  1532  miroconnect
UDP  1533  Virtual Places Software
UDP  1534  micromuse-lm
UDP  1535  ampr-info
UDP  1536  ampr-inter
UDP  1537  isi-lm
UDP  1538  3ds-lm
UDP  1539  Intellistor License Manager
UDP  1540  rds
UDP  1541  rds2
UDP  1542  gridgen-elmd
UDP  1543  simba-cs
UDP  1544  aspeclmd
UDP  1545  vistium-share
UDP  1546  abbaccuray
UDP  1547  laplink
UDP  1548  Axon License Manager
UDP  1549  Shiva Sound
UDP  1550  Image Storage license manager 3M Company
UDP  1551  HECMTL-DB
UDP  1552  pciarray
UDP  1553  sna-cs
UDP  1554  CACI Products Company License Manager
UDP  1555  livelan
UDP  1556  AshWin CI Tecnologies
UDP  1557  ArborText License Manager
UDP  1558  xingmpeg
UDP  1559  web2host
UDP  1560  asci-val
UDP  1561  facilityview
UDP  1562  pconnectmgr
UDP  1563  Cadabra License Manager
UDP  1564  Pay-Per-View
UDP  1565  WinDD
UDP  1566  CORELVIDEO
UDP  1567  jlicelmd
UDP  1568  tsspmap
UDP  1569  ets
UDP  1570  orbixd
UDP  1571  Oracle Remote Data Base
UDP  1572  Chipcom License Manager
UDP  1573  itscomm-ns
UDP  1574  mvel-lm
UDP  1575  oraclenames
UDP  1576  moldflow-lm
UDP  1577  hypercube-lm
UDP  1578  Jacobus License Manager
UDP  1579  ioc-sea-lm
UDP  1580  tn-tl-r2
UDP  1581  MIL-2045-47001
UDP  1582  MSIMS
UDP  1583  simbaexpress
UDP  1584  tn-tl-fd2
UDP  1585  intv
UDP  1586  ibm-abtact
UDP  1587  pra_elmd
UDP  1588  triquest-lm
UDP  1589  VQP
UDP  1590  gemini-lm
UDP  1591  ncpm-pm
UDP  1592  commonspace
UDP  1593  mainsoft-lm
UDP  1594  sixtrak
UDP  1595  radio
UDP  1596  radio-bc
UDP  1597  orbplus-iiop
UDP  1598  picknfs
UDP  1599  simbaservices
UDP  1600  issd
UDP  1601  aas
UDP  1602  inspect
UDP  1603  pickodbc
UDP  1604  icabrowser
UDP  1605  Salutation Manager (Salutation Protocol)
UDP  1606  Salutation Manager (SLM-API)
UDP  1607  stt
UDP  1608  Smart Corp. License Manager
UDP  1609  isysg-lm
UDP  1610  taurus-wh
UDP  1611  Inter Library Loan
UDP  1612  NetBill Transaction Server
UDP  1613  NetBill Key Repository
UDP  1614  NetBill Credential Server
UDP  1615  NetBill Authorization Server
UDP  1616  NetBill Product Server
UDP  1617  Nimrod Inter-Agent Communication
UDP  1618  skytelnet
UDP  1619  xs-openstorage
UDP  1620  faxportwinport
UDP  1621  softdataphone
UDP  1622  ontime
UDP  1623  jaleosnd
UDP  1624  udp-sr-port
UDP  1625  svs-omagent
UDP  1626  Shockwave
UDP  1627  T.128 Gateway
UDP  1628  LonTalk normal
UDP  1629  LonTalk urgent
UDP  1630  Oracle Net8 Cman
UDP  1631  Visit view
UDP  1632  PAMMRATC
UDP  1633  PAMMRPC
UDP  1634  Log On America Probe
UDP  1635  EDB Server 1
UDP  1636  CableNet Control Protocol
UDP  1637  CableNet Admin Protocol
UDP  1638  CableNet Info Protocol
UDP  1639  cert-initiator
UDP  1640  cert-responder
UDP  1641  InVision
UDP  1642  isis-am
UDP  1643  isis-ambc
UDP  1644  Satellite-data Acquistion Systems 4
UDP  1645  Legacy RADIUS / datametrics
UDP  1646  Legacy RADIUS / sa-msg-port
UDP  1647  rsap
UDP  1648  concurrent-lm
UDP  1649  kermit
UDP  1650  nkd
UDP  1651  shiva_confsrvr
UDP  1652  xnmp
UDP  1653  alphatech-lm
UDP  1654  stargatealerts
UDP  1655  dec-mbadmin
UDP  1656  dec-mbadmin-h
UDP  1657  fujitsu-mmpdc
UDP  1658  sixnetudr
UDP  1659  Silicon Grail License Manager
UDP  1660  skip-mc-gikreq
UDP  1661  netview-aix-1
UDP  1662  netview-aix-2
UDP  1663  netview-aix-3
UDP  1664  netview-aix-4
UDP  1665  netview-aix-5
UDP  1666  netview-aix-6
UDP  1667  netview-aix-7
UDP  1668  netview-aix-8
UDP  1669  netview-aix-9
UDP  1670  netview-aix-10
UDP  1671  netview-aix-11
UDP  1672  netview-aix-12
UDP  1673  Intel Proshare Multicast
UDP  1674  Intel Proshare Multicast
UDP  1675  Pacific Data Products
UDP  1676  netcomm2
UDP  1677  groupwise
UDP  1678  prolink
UDP  1679  darcorp-lm
UDP  1680  microcom-sbp
UDP  1681  sd-elmd
UDP  1682  lanyon-lantern
UDP  1683  ncpm-hip
UDP  1684  SnareSecure
UDP  1685  n2nremote
UDP  1686  cvmon
UDP  1687  nsjtp-ctrl
UDP  1688  nsjtp-data
UDP  1689  firefox
UDP  1690  ng-umds
UDP  1691  empire-empuma
UDP  1692  sstsys-lm
UDP  1693  rrirtr
UDP  1694  rrimwm
UDP  1695  rrilwm
UDP  1696  rrifmm
UDP  1697  rrisat
UDP  1698  RSVP-ENCAPSULATION-1
UDP  1699  RSVP-ENCAPSULATION-2
UDP  1700  mps-raft
UDP  1701  l2tp
UDP  1702  deskshare
UDP  1703  hb-engine
UDP  1704  bcs-broker
UDP  1705  slingshot
UDP  1706  jetform
UDP  1707  vdmplay
UDP  1708  gat-lmd
UDP  1709  centra
UDP  1710  impera
UDP  1711  pptconference
UDP  1712  resource monitoring service
UDP  1713  ConferenceTalk
UDP  1714  sesi-lm
UDP  1715  houdini-lm
UDP  1716  xmsg
UDP  1717  fj-hdnet
UDP  1718  h323gatedisc
UDP  1719  h323gatestat
UDP  1720  h323hostcall
UDP  1721  caicci
UDP  1722  HKS License Manager
UDP  1723  pptp
UDP  1724  csbphonemaster
UDP  1725  iden-ralp
UDP  1726  IBERIAGAMES
UDP  1727  winddx
UDP  1728  TELINDUS
UDP  1729  CityNL License Management
UDP  1730  roketz
UDP  1731  MSICCP
UDP  1732  proxim
UDP  1733  SIMS - SIIPAT Protocol for Alarm Transmission
UDP  1734  Camber Corporation License Management
UDP  1735  PrivateChat
UDP  1736  street-stream
UDP  1737  ultimad
UDP  1738  GameGen1
UDP  1739  webaccess
UDP  1740  encore
UDP  1741  cisco-net-mgmt
UDP  1742  3Com-nsd
UDP  1743  Cinema Graphics License Manager
UDP  1744  ncpm-ft
UDP  1745  remote-winsock
UDP  1746  ftrapid-1
UDP  1747  ftrapid-2
UDP  1748  oracle-em1
UDP  1749  aspen-services
UDP  1750  Simple Socket Library's PortMaster
UDP  1751  SwiftNet
UDP  1752  Leap of Faith Research License Manager
UDP  1753  Translogic License Manager
UDP  1754  oracle-em2
UDP  1755  ms-streaming
UDP  1756  capfast-lmd
UDP  1757  cnhrp
UDP  1758  tftp-mcast
UDP  1759  SPSS License Manager
UDP  1760  www-ldap-gw
UDP  1761  LANDesk-RC / cft-0
UDP  1762  cft-1
UDP  1763  cft-2
UDP  1764  cft-3
UDP  1765  cft-4
UDP  1766  cft-5
UDP  1767  cft-6
UDP  1768  cft-7
UDP  1769  bmc-net-adm
UDP  1770  bmc-net-svc
UDP  1771  vaultbase
UDP  1772  EssWeb Gateway
UDP  1773  KMSControl
UDP  1774  global-dtserv
UDP  1776  Federal Emergency Management Information System
UDP  1777  powerguardian
UDP  1778  prodigy-internet
UDP  1779  pharmasoft
UDP  1780  dpkeyserv
UDP  1781  answersoft-lm
UDP  1782  hp-hcip
UDP  1783  Port 04/14/00 fujitsu.co.jp
UDP  1784  Finle License Manager
UDP  1785  Wind River Systems License Manager
UDP  1786  funk-logger
UDP  1787  funk-license
UDP  1788  psmond
UDP  1789  hello
UDP  1790  Narrative Media Streaming Protocol
UDP  1791  EA1
UDP  1792  ibm-dt-2
UDP  1793  rsc-robot
UDP  1794  cera-bcm
UDP  1795  dpi-proxy
UDP  1796  Vocaltec Server Administration
UDP  1797  UMA
UDP  1798  Event Transfer Protocol
UDP  1799  NETRISK
UDP  1800  ANSYS-License manager
UDP  1801  Microsoft Message Queuing
UDP  1802  ConComp1
UDP  1803  HP-HCIP-GWY
UDP  1804  ENL
UDP  1805  ENL-Name
UDP  1806  Musiconline
UDP  1807  Fujitsu Hot Standby Protocol
UDP  1808  Oracle-VP2
UDP  1809  Oracle-VP1
UDP  1810  Jerand License Manager
UDP  1811  Scientia-SDB
UDP  1812  RADIUS
UDP  1813  RADIUS Accounting
UDP  1814  TDP Suite
UDP  1815  MMPFT
UDP  1816  HARP
UDP  1817  RKB-OSCS
UDP  1818  Enhanced Trivial File Transfer Protocol
UDP  1819  Plato License Manager
UDP  1820  mcagent
UDP  1821  donnyworld
UDP  1822  es-elmd
UDP  1823  Unisys Natural Language License Manager
UDP  1824  metrics-pas
UDP  1825  DirecPC Video
UDP  1826  ARDT
UDP  1827  ASI
UDP  1828  itm-mcell-u
UDP  1829  Optika eMedia
UDP  1830  Oracle Net8 CMan Admin
UDP  1831  Myrtle
UDP  1832  ThoughtTreasure
UDP  1833  udpradio
UDP  1834  ARDUS Unicast
UDP  1835  ARDUS Multicast
UDP  1836  ste-smsc
UDP  1837  csoft1
UDP  1838  TALNET
UDP  1839  netopia-vo1
UDP  1840  netopia-vo2
UDP  1841  netopia-vo3
UDP  1842  netopia-vo4
UDP  1843  netopia-vo5
UDP  1844  DirecPC-DLL
UDP  1850  GSI
UDP  1851  ctcd
UDP  1860  SunSCALAR Services
UDP  1861  LeCroy VICP
UDP  1862  techra-server
UDP  1863  MSNP
UDP  1864  Paradym 31 Port
UDP  1865  ENTP
UDP  1870  SunSCALAR DNS Service
UDP  1871  Cano Central 0
UDP  1872  Cano Central 1
UDP  1873  Fjmpjps
UDP  1874  Fjswapsnp
UDP  1881  IBM MQSeries
UDP  1895  Vista 4GL
UDP  1899  MC2Studios
UDP  1900  UPnP SSDP
UDP  1901  Fujitsu ICL Terminal Emulator Program A
UDP  1902  Fujitsu ICL Terminal Emulator Program B
UDP  1903  Local Link Name Resolution
UDP  1904  Fujitsu ICL Terminal Emulator Program C
UDP  1905  Secure UP.Link Gateway Protocol
UDP  1906  TPortMapperReq
UDP  1907  IntraSTAR
UDP  1908  Dawn
UDP  1909  Global World Link
UDP  1910  ultrabac
UDP  1911  Starlight Networks Multimedia Transport Protocol
UDP  1912  rhp-iibp
UDP  1913  armadp
UDP  1914  Elm-Momentum
UDP  1915  FACELINK
UDP  1916  Persoft Persona
UDP  1917  nOAgent
UDP  1918  Candle Directory Service - NDS
UDP  1919  Candle Directory Service - DCH
UDP  1920  Candle Directory Service - FERRET
UDP  1921  NoAdmin
UDP  1922  Tapestry
UDP  1923  SPICE
UDP  1924  XIIP
UDP  1930  Drive AppServer
UDP  1931  AMD SCHED
UDP  1944  close-combat
UDP  1945  dialogic-elmd
UDP  1946  tekpls
UDP  1947  hlserver
UDP  1948  eye2eye
UDP  1949  ISMA Easdaq Live
UDP  1950  ISMA Easdaq Test
UDP  1951  bcs-lmserver
UDP  1952  mpnjsc
UDP  1953  Rapid Base
UDP  1961  BTS APPSERVER
UDP  1962  BIAP-MP
UDP  1963  WebMachine
UDP  1964  SOLID E ENGINE
UDP  1965  Tivoli NPM
UDP  1966  Slush
UDP  1967  SNS Quote
UDP  1972  Cache
UDP  1973  Data Link Switching Remote Access Protocol
UDP  1974  DRP
UDP  1975  TCO Flash Agent
UDP  1976  TCO Reg Agent
UDP  1977  TCO Address Book
UDP  1978  Slapper.B / UniSQL
UDP  1979  UniSQL Java
UDP  1984  BB
UDP  1985  Hot Standby Router Protocol
UDP  1986  cisco license management
UDP  1987  cisco RSRB Priority 1 port
UDP  1988  cisco RSRB Priority 2 port
UDP  1989  MHSnet system
UDP  1990  cisco STUN Priority 1 port
UDP  1991  cisco STUN Priority 2 port
UDP  1992  IPsendmsg
UDP  1993  cisco SNMP TCP port
UDP  1994  cisco serial tunnel port
UDP  1995  cisco perf port
UDP  1996  cisco Remote SRB port
UDP  1997  cisco Gateway Discovery Protocol
UDP  1998  cisco X.25 service (XOT)
UDP  1999  cisco identification port
UDP  2000  callbook
UDP  2001  curry
UDP  2002  Slapper.A / globe
UDP  2004  CCWS mm conf
UDP  2005  oracle
UDP  2006  raid
UDP  2007  raid-am
UDP  2008  terminaldb
UDP  2009  whosockami
UDP  2010  pipe-server
UDP  2011  servserv
UDP  2012  raid-ac
UDP  2013  raid-cd
UDP  2014  raid-sf
UDP  2015  raid-cs
UDP  2016  bootserver
UDP  2017  bootclient
UDP  2018  rellpack
UDP  2019  about
UDP  2020  xinupageserver
UDP  2021  xinuexpansion1
UDP  2022  xinuexpansion2
UDP  2023  xinuexpansion3
UDP  2024  xinuexpansion4
UDP  2025  xribs
UDP  2026  scrabble
UDP  2027  shadowserver
UDP  2028  submitserver
UDP  2030  device2
UDP  2032  blackboard
UDP  2033  glogger
UDP  2034  scoremgr
UDP  2035  imsldoc
UDP  2038  objectmanager
UDP  2040  lam
UDP  2041  interbase
UDP  2042  isis
UDP  2043  isis-bcast
UDP  2044  rimsl
UDP  2045  cdfunc
UDP  2046  sdfunc
UDP  2047  dls
UDP  2048  dls-monitor
UDP  2049  Network File System - Sun Microsystems
UDP  2065  Data Link Switch Read Port Number
UDP  2067  Data Link Switch Write Port Number
UDP  2090  Load Report Protocol
UDP  2091  PRP
UDP  2092  Descent 3
UDP  2093  NBX CC
UDP  2094  NBX AU
UDP  2095  NBX SER
UDP  2096  NBX DIR
UDP  2097  Jet Form Preview
UDP  2098  Dialog Port
UDP  2099  H.225.0 Annex G
UDP  2100  amiganetfs
UDP  2101  rtcm-sc104
UDP  2102  Zephyr server
UDP  2103  Zephyr serv-hm connection
UDP  2104  Zephyr hostmanager
UDP  2105  MiniPay
UDP  2106  MZAP
UDP  2107  BinTec Admin
UDP  2108  Comcam
UDP  2109  Ergolight
UDP  2110  UMSP
UDP  2111  DSATP
UDP  2112  Idonix MetaNet
UDP  2113  HSL StoRM
UDP  2114  NEWHEIGHTS
UDP  2115  KDM
UDP  2116  CCOWCMR
UDP  2117  MENTACLIENT
UDP  2118  MENTASERVER
UDP  2119  GSIGATEKEEPER
UDP  2120  Quick Eagle Networks CP
UDP  2121  SCIENTIA-SSDB
UDP  2122  CauPC Remote Control
UDP  2123  GTP-Control Plane (3GPP)
UDP  2124  ELATELINK
UDP  2125  LOCKSTEP
UDP  2126  PktCable-COPS
UDP  2127  INDEX-PC-WB
UDP  2128  Net Steward Control
UDP  2129  cs-live.com
UDP  2130  SWC-XDS
UDP  2131  Avantageb2b
UDP  2132  AVAIL-EPMAP
UDP  2133  ZYMED-ZPP
UDP  2134  AVENUE
UDP  2135  Grid Resource Information Server
UDP  2136  APPWORXSRV
UDP  2137  CONNECT
UDP  2138  UNBIND-CLUSTER
UDP  2139  IAS-AUTH
UDP  2140  IAS-REG / Deep Throat (Windows Trojan) / Deep Throat 2 (Windows Trojan)
UDP  2141  IAS-ADMIND
UDP  2142  TDM-OVER-IP
UDP  2143  Live Vault Job Control
UDP  2144  Live Vault Fast Object Transfer
UDP  2145  Live Vault Remote Diagnostic Console Support
UDP  2146  Live Vault Admin Event Notification
UDP  2147  Live Vault Authentication
UDP  2148  VERITAS UNIVERSAL COMMUNICATION LAYER
UDP  2149  ACPTSYS
UDP  2150  DYNAMIC3D
UDP  2151  DOCENT
UDP  2152  GTP-User Plane (3GPP)
UDP  2165  X-Bone API
UDP  2166  IWSERVER
UDP  2180  Millicent Vendor Gateway Server
UDP  2181  eforward
UDP  2190  TiVoConnect Beacon
UDP  2191  TvBus Messaging
UDP  2200  ICI
UDP  2201  Advanced Training System Program
UDP  2202  Int. Multimedia Teleconferencing Cosortium
UDP  2213  Kali
UDP  2220  Ganymede
UDP  2221  Rockwell CSP1
UDP  2222  Rockwell CSP2
UDP  2223  Rockwell CSP3
UDP  2232  IVS Video default
UDP  2233  INFOCRYPT
UDP  2234  DirectPlay
UDP  2235  Sercomm-WLink
UDP  2236  Nani
UDP  2237  Optech Port1 License Manager
UDP  2238  AVIVA SNA SERVER
UDP  2239  Image Query
UDP  2240  RECIPe
UDP  2241  IVS Daemon
UDP  2242  Folio Remote Server
UDP  2243  Magicom Protocol
UDP  2244  NMS Server
UDP  2245  HaO
UDP  2279  xmquery
UDP  2280  LNVPOLLER
UDP  2281  LNVCONSOLE
UDP  2282  LNVALARM
UDP  2283  LNVSTATUS
UDP  2284  LNVMAPS
UDP  2285  LNVMAILMON
UDP  2286  NAS-Metering
UDP  2287  DNA
UDP  2288  NETML
UDP  2294  Konshus License Manager (FLEX)
UDP  2295  Advant License Manager
UDP  2296  Theta License Manager (Rainbow)
UDP  2297  D2K DataMover 1
UDP  2298  D2K DataMover 2
UDP  2299  PC Telecommute
UDP  2300  CVMMON
UDP  2301  Compaq HTTP
UDP  2302  Bindery Support
UDP  2303  Proxy Gateway
UDP  2304  Attachmate UTS
UDP  2305  MT ScaleServer
UDP  2306  TAPPI BoxNet
UDP  2307  pehelp
UDP  2308  sdhelp
UDP  2309  SD Server
UDP  2310  SD Client
UDP  2311  Message Service
UDP  2313  IAPP (Inter Access Point Protocol)
UDP  2314  CR WebSystems
UDP  2315  Precise Sft.
UDP  2316  SENT License Manager
UDP  2317  Attachmate G32
UDP  2318  Cadence Control
UDP  2319  InfoLibria
UDP  2320  Siebel NS
UDP  2321  RDLAP
UDP  2322  ofsd
UDP  2323  3d-nfsd
UDP  2324  Cosmocall
UDP  2325  Design Space License Management
UDP  2326  IDCP
UDP  2327  xingcsm
UDP  2328  Netrix SFTM
UDP  2329  NVD
UDP  2330  TSCCHAT
UDP  2331  AGENTVIEW
UDP  2332  RCC Host
UDP  2333  SNAPP
UDP  2334  ACE Client Auth
UDP  2335  ACE Proxy
UDP  2336  Apple UG Control
UDP  2337  ideesrv
UDP  2338  Norton Lambert
UDP  2339  3Com WebView
UDP  2340  WRS Registry
UDP  2341  XIO Status
UDP  2342  Seagate Manage Exec
UDP  2343  nati logos
UDP  2344  fcmsys
UDP  2345  dbm
UDP  2346  Game Connection Port
UDP  2347  Game Announcement and Location
UDP  2348  Information to query for game status
UDP  2349  Disgnostics Port
UDP  2350  psbserver
UDP  2351  psrserver
UDP  2352  pslserver
UDP  2353  pspserver
UDP  2354  psprserver
UDP  2355  psdbserver
UDP  2356  GXT License Managemant
UDP  2357  UniHub Server
UDP  2358  Futrix
UDP  2359  FlukeServer
UDP  2360  NexstorIndLtd
UDP  2361  TL1
UDP  2362  digiman
UDP  2363  Media Central NFSD
UDP  2364  OI-2000
UDP  2365  dbref
UDP  2366  qip-login
UDP  2367  Service Control
UDP  2368  OpenTable
UDP  2369  ACS2000 DSP
UDP  2370  L3-HBMon
UDP  2381  Compaq HTTPS
UDP  2382  Microsoft OLAP
UDP  2383  Microsoft OLAP
UDP  2384  SD-REQUEST
UDP  2389  OpenView Session Mgr
UDP  2390  RSMTP
UDP  2391  3COM Net Management
UDP  2392  Tactical Auth
UDP  2393  MS OLAP 1
UDP  2394  MA OLAP 2
UDP  2395  LAN900 Remote
UDP  2396  Wusage
UDP  2397  NCL
UDP  2398  Orbiter
UDP  2399  FileMaker Inc. - Data Access Layer
UDP  2400  OpEquus Server
UDP  2401  cvspserver
UDP  2402  TaskMaster 2000 Server
UDP  2403  TaskMaster 2000 Web
UDP  2404  IEC870-5-104
UDP  2405  TRC Netpoll
UDP  2406  JediServer
UDP  2407  Orion
UDP  2408  OptimaNet
UDP  2409  SNS Protocol
UDP  2410  VRTS Registry
UDP  2411  Netwave AP Management
UDP  2412  CDN
UDP  2413  orion-rmi-reg
UDP  2414  Interlingua
UDP  2415  COMTEST
UDP  2416  RMT Server
UDP  2417  Composit Server
UDP  2418  cas
UDP  2419  Attachmate S2S
UDP  2420  DSL Remote Management
UDP  2421  G-Talk
UDP  2422  CRMSBITS
UDP  2423  RNRP
UDP  2424  KOFAX-SVR
UDP  2425  Fujitsu App Manager
UDP  2426  Appliant UDP
UDP  2427  Media Gateway Control Protocol Gateway
UDP  2428  One Way Trip Time
UDP  2429  FT-ROLE
UDP  2430  venus
UDP  2431  venus-se
UDP  2432  codasrv
UDP  2433  codasrv-se
UDP  2434  pxc-epmap
UDP  2435  OptiLogic
UDP  2436  TOP/X
UDP  2437  UniControl
UDP  2438  MSP
UDP  2439  SybaseDBSynch
UDP  2440  Spearway Lockser
UDP  2441  pvsw-inet
UDP  2442  Netangel
UDP  2443  PowerClient Central Storage Facility
UDP  2444  BT PP2 Sectrans
UDP  2445  DTN1
UDP  2446  bues_service
UDP  2447  OpenView NNM daemon
UDP  2448  hpppsvr
UDP  2449  RATL
UDP  2450  netadmin
UDP  2451  netchat
UDP  2452  SnifferClient
UDP  2453  madge-om
UDP  2454  IndX-DDS
UDP  2455  WAGO-IO-SYSTEM
UDP  2456  altav-remmgt
UDP  2457  Rapido_IP
UDP  2458  griffin
UDP  2459  Community
UDP  2460  ms-theater
UDP  2461  qadmifoper
UDP  2462  qadmifevent
UDP  2463  Symbios Raid
UDP  2464  DirecPC SI
UDP  2465  Load Balance Management
UDP  2466  Load Balance Forwarding
UDP  2467  High Criteria
UDP  2468  qip_msgd
UDP  2469  MTI-TCS-COMM
UDP  2470  taskman port
UDP  2471  SeaODBC
UDP  2472  C3
UDP  2473  Aker-cdp
UDP  2474  Vital Analysis
UDP  2475  ACE Server
UDP  2476  ACE Server Propagation
UDP  2477  SecurSight Certificate Valifation Service
UDP  2478  SecurSight Authentication Server (SSL)
UDP  2479  SecurSight Event Logging Server (SSL)
UDP  2480  Lingwood's Detail
UDP  2481  Oracle GIOP
UDP  2482  Oracle GIOP SSL
UDP  2483  Oracel TTC
UDP  2484  Oracle TTC SSL
UDP  2485  Net Objects1
UDP  2486  Net Objects2
UDP  2487  Policy Notice Service
UDP  2488  Moy Corporation
UDP  2489  TSILB
UDP  2490  qip_qdhcp
UDP  2491  Conclave CPP
UDP  2492  GROOVE
UDP  2493  Talarian MQS
UDP  2494  BMC AR
UDP  2495  Fast Remote Services
UDP  2496  DIRGIS
UDP  2497  Quad DB
UDP  2498  ODN-CasTraq
UDP  2499  UniControl
UDP  2500  Resource Tracking system server
UDP  2501  Resource Tracking system client
UDP  2502  Kentrox Protocol
UDP  2503  NMS-DPNSS
UDP  2504  WLBS
UDP  2505  torque-traffic
UDP  2506  jbroker
UDP  2507  spock
UDP  2508  JDataStore
UDP  2509  fjmpss
UDP  2510  fjappmgrbulk
UDP  2511  Metastorm
UDP  2512  Citrix IMA
UDP  2513  Citrix ADMIN
UDP  2514  Facsys NTP
UDP  2515  Facsys Router
UDP  2516  Main Control
UDP  2517  H.323 Annex E call signaling transport
UDP  2518  Willy
UDP  2519  globmsgsvc
UDP  2520  pvsw
UDP  2521  Adaptec Manager
UDP  2522  WinDb
UDP  2523  Qke LLC V.3
UDP  2524  Optiwave License Management
UDP  2525  MS V-Worlds
UDP  2526  EMA License Manager
UDP  2527  IQ Server
UDP  2528  NCR CCL
UDP  2529  UTS FTP
UDP  2530  VR Commerce
UDP  2531  ITO-E GUI
UDP  2532  OVTOPMD
UDP  2533  SnifferServer
UDP  2534  Combox Web Access
UDP  2535  MADCAP
UDP  2536  btpp2audctr1
UDP  2537  Upgrade Protocol
UDP  2538  vnwk-prapi
UDP  2539  VSI Admin
UDP  2540  LonWorks
UDP  2541  LonWorks2
UDP  2542  daVinci
UDP  2543  REFTEK
UDP  2544  Novell ZEN novell.com
UDP  2545  sis-emt
UDP  2546  vytalvaultbrtp
UDP  2547  vytalvaultvsmp
UDP  2548  vytalvaultpipe
UDP  2549  IPASS
UDP  2550  ADS
UDP  2551  ISG UDA Server
UDP  2552  Call Logging
UDP  2553  efidiningport
UDP  2554  VCnet-Link v10
UDP  2555  Compaq WCP
UDP  2556  nicetec-nmsvc
UDP  2557  nicetec-mgmt
UDP  2558  PCLE Multi Media
UDP  2559  LSTP
UDP  2560  labrat
UDP  2561  MosaixCC
UDP  2562  Delibo
UDP  2563  CTI Redwood
UDP  2565  Coordinator Server
UDP  2566  pcs-pcw
UDP  2567  Cisco Line Protocol
UDP  2568  SPAM TRAP
UDP  2569  Sonus Call Signal
UDP  2570  HS Port
UDP  2571  CECSVC
UDP  2572  IBP
UDP  2573  Trust Establish
UDP  2574  Blockade BPSP
UDP  2575  HL7
UDP  2576  TCL Pro Debugger
UDP  2577  Scriptics Lsrvr
UDP  2578  RVS ISDN DCP
UDP  2579  mpfoncl
UDP  2580  Tributary
UDP  2581  ARGIS TE
UDP  2582  ARGIS DS
UDP  2583  MON
UDP  2584  cyaserv
UDP  2585  NETX Server
UDP  2586  NETX Agent
UDP  2587  MASC
UDP  2588  Privilege
UDP  2589  quartus tcl
UDP  2590  idotdist
UDP  2591  Maytag Shuffle
UDP  2592  netrek
UDP  2593  MNS Mail Notice Service
UDP  2594  Data Base Server
UDP  2595  World Fusion 1
UDP  2596  World Fusion 2
UDP  2597  Homestead Glory
UDP  2598  Citrix MA Client
UDP  2599  Meridian Data
UDP  2600  HPSTGMGR
UDP  2601  discp client
UDP  2602  discp server
UDP  2603  Service Meter
UDP  2604  NSC CCS
UDP  2605  NSC POSA
UDP  2606  Dell Netmon
UDP  2607  Dell Connection
UDP  2608  Wag Service
UDP  2609  System Monitor
UDP  2610  VersaTek
UDP  2611  LIONHEAD
UDP  2612  Qpasa Agent
UDP  2613  SMNTUBootstrap
UDP  2614  Never Offline
UDP  2615  firepower
UDP  2616  appswitch-emp
UDP  2617  Clinical Context Managers
UDP  2618  Priority E-Com
UDP  2619  bruce
UDP  2620  LPSRecommender
UDP  2621  Miles Apart Jukebox Server
UDP  2622  MetricaDBC
UDP  2623  LMDP
UDP  2624  Aria
UDP  2625  Blwnkl Port
UDP  2626  gbjd816
UDP  2627  Moshe Beeri
UDP  2628  DICT
UDP  2629  Sitara Server
UDP  2630  Sitara Management
UDP  2631  Sitara Dir
UDP  2632  IRdg Post
UDP  2633  InterIntelli
UDP  2634  PK Electronics
UDP  2635  Back Burner
UDP  2636  Solve
UDP  2637  Import Document Service
UDP  2638  Sybase Anywhere
UDP  2639  AMInet
UDP  2640  Sabbagh Associates Licence Manager
UDP  2641  HDL Server
UDP  2642  Tragic
UDP  2643  GTE-SAMP
UDP  2644  Travsoft IPX Tunnel
UDP  2645  Novell IPX CMD
UDP  2646  AND License Manager
UDP  2647  SyncServer
UDP  2648  Upsnotifyprot
UDP  2649  VPSIPPORT
UDP  2650  eristwoguns
UDP  2651  EBInSite
UDP  2652  InterPathPanel
UDP  2653  Sonus
UDP  2654  Corel VNC Admin
UDP  2655  UNIX Nt Glue
UDP  2656  Kana
UDP  2657  SNS Dispatcher
UDP  2658  SNS Admin
UDP  2659  SNS Query
UDP  2660  GC Monitor
UDP  2661  OLHOST
UDP  2662  BinTec-CAPI
UDP  2663  BinTec-TAPI
UDP  2664  Command MQ GM
UDP  2665  Command MQ PM
UDP  2666  extensis
UDP  2667  Alarm Clock Server
UDP  2668  Alarm Clock Client
UDP  2669  TOAD
UDP  2670  TVE Announce
UDP  2671  newlixreg
UDP  2672  nhserver
UDP  2673  First Call 42
UDP  2674  ewnn
UDP  2675  TTC ETAP
UDP  2676  SIMSLink
UDP  2677  Gadget Gate 1 Way
UDP  2678  Gadget Gate 2 Way
UDP  2679  Sync Server SSL
UDP  2680  pxc-sapxom
UDP  2681  mpnjsomb
UDP  2682  SRSP
UDP  2683  NCDLoadBalance
UDP  2684  mpnjsosv
UDP  2685  mpnjsocl
UDP  2686  mpnjsomg
UDP  2687  pq-lic-mgmt
UDP  2688  md-cf-HTTP
UDP  2689  FastLynx
UDP  2690  HP NNM Embedded Database
UDP  2691  IT Internet
UDP  2692  Admins LMS
UDP  2693  belarc-HTTP
UDP  2694  pwrsevent
UDP  2695  VSPREAD
UDP  2696  Unify Admin
UDP  2697  Oce SNMP Trap Port
UDP  2698  MCK-IVPIP
UDP  2699  Csoft Plus Client
UDP  2700  tqdata
UDP  2701  SMS Remote Control (control)
UDP  2702  SMS Remote Control (data)
UDP  2703  SMS Remote Control (chat)
UDP  2704  SMS Remote File Transfer
UDP  2705  SDS Admin
UDP  2706  NCD Mirroring
UDP  2707  EMCSYMAPIPORT
UDP  2708  Banyan-Net
UDP  2709  Supermon
UDP  2710  SSO Service
UDP  2711  SSO Control
UDP  2712  Axapta Object Communication Protocol
UDP  2713  Raven1
UDP  2714  unified-technologies.com
UDP  2715  HPSTGMGR2
UDP  2716  Inova IP Disco
UDP  2717  PN REQUESTER
UDP  2718  PN REQUESTER 2
UDP  2719  Scan & Change
UDP  2720  wkars
UDP  2721  Smart Diagnose
UDP  2722  Proactive Server
UDP  2723  WatchDog NT
UDP  2724  qotps
UDP  2725  MSOLAP PTP2
UDP  2726  TAMS
UDP  2727  Media Gateway Control Protocol Call Agent
UDP  2728  SQDR
UDP  2729  TCIM Control
UDP  2730  NEC RaidPlus
UDP  2731  NetDragon Messanger
UDP  2732  G5M
UDP  2733  Signet CTF
UDP  2734  CCS Software
UDP  2735  Monitor Console
UDP  2736  RADWIZ NMS SRV
UDP  2737  SRP Feedback
UDP  2738  NDL TCP-OSI Gateway
UDP  2739  TN Timing
UDP  2740  Alarm
UDP  2741  TSB
UDP  2742  TSB2
UDP  2743  murx
UDP  2744  honyaku
UDP  2745  URBISNET
UDP  2746  CPUDPENCAP
UDP  2747  yk.fujitsu.co.jp
UDP  2748  yk.fujitsu.co.jp
UDP  2749  yk.fujitsu.co.jp
UDP  2750  yk.fujitsu.co.jp
UDP  2751  yk.fujitsu.co.jp
UDP  2752  RSISYS ACCESS
UDP  2753  de-spot
UDP  2754  APOLLO CC
UDP  2755  Express Pay
UDP  2756  simplement-tie
UDP  2757  CNRP
UDP  2758  APOLLO Status
UDP  2759  APOLLO GMS
UDP  2760  Saba MS
UDP  2761  DICOM ISCL
UDP  2762  DICOM TLS
UDP  2763  Desktop DNA
UDP  2764  Data Insurance
UDP  2765  qip-audup
UDP  2766  Compaq SCP
UDP  2767  UADTC
UDP  2768  UACS
UDP  2769  Single Point MVS
UDP  2770  Veronica
UDP  2771  Vergence CM
UDP  2772  auris
UDP  2773  PC Backup
UDP  2774  PC Backup
UDP  2775  SMMP
UDP  2776  Ridgeway Systems & Software
UDP  2777  Ridgeway Systems & Software
UDP  2778  Gwen-Sonya
UDP  2779  LBC Sync
UDP  2780  LBC Control
UDP  2781  whosells
UDP  2782  everydayrc
UDP  2783  AISES
UDP  2784  world wide web - development
UDP  2785  aic-np
UDP  2786  aic-oncrpc - Destiny MCD database
UDP  2787  piccolo - Cornerstone Software
UDP  2788  NetWare Loadable Module - Seagate Software
UDP  2789  Media Agent
UDP  2790  PLG Proxy
UDP  2791  MT Port Registrator
UDP  2792  f5-globalsite
UDP  2793  initlsmsad
UDP  2794  aaftp
UDP  2795  LiveStats
UDP  2796  ac-tech
UDP  2797  esp-encap
UDP  2798  TMESIS-UPShot
UDP  2799  ICON Discover
UDP  2800  ACC RAID
UDP  2801  IGCP
UDP  2802  Veritas UDP1
UDP  2803  btprjctrl
UDP  2804  Telexis VTU
UDP  2805  WTA WSP-S
UDP  2806  cspuni
UDP  2807  cspmulti
UDP  2808  J-LAN-P
UDP  2809  CORBA LOC
UDP  2810  Active Net Steward
UDP  2811  GSI FTP
UDP  2812  atmtcp
UDP  2813  llm-pass
UDP  2814  llm-csv
UDP  2815  LBC Measurement
UDP  2816  LBC Watchdog
UDP  2817  NMSig Port
UDP  2818  rmlnk
UDP  2819  FC Fault Notification
UDP  2820  UniVision
UDP  2821  vml_dms
UDP  2822  ka0wuc
UDP  2823  CQG Net/LAN
UDP  2826  slc systemlog
UDP  2827  slc ctrlrloops
UDP  2828  ITM License Manager
UDP  2829  silkp1
UDP  2830  silkp2
UDP  2831  silkp3
UDP  2832  silkp4
UDP  2833  glishd
UDP  2834  EVTP
UDP  2835  EVTP-DATA
UDP  2836  catalyst
UDP  2837  Repliweb
UDP  2838  Starbot
UDP  2839  NMSigPort
UDP  2840  l3-exprt
UDP  2841  l3-ranger
UDP  2842  l3-hawk
UDP  2843  PDnet
UDP  2844  BPCP POLL
UDP  2845  BPCP TRAP
UDP  2846  AIMPP Hello
UDP  2847  AIMPP Port Req
UDP  2848  AMT-BLC-PORT
UDP  2849  FXP
UDP  2850  MetaConsole
UDP  2851  webemshttp
UDP  2852  bears-01
UDP  2853  ISPipes
UDP  2854  InfoMover
UDP  2856  cesdinv
UDP  2857  SimCtIP
UDP  2858  ECNP
UDP  2859  Active Memory
UDP  2860  Dialpad Voice 1
UDP  2861  Dialpad Voice 2
UDP  2862  TTG Protocol
UDP  2863  Sonar Data
UDP  2864  main 5001 cmd
UDP  2865  pit-vpn
UDP  2866  lwlistener
UDP  2867  esps-portal
UDP  2868  NPEP Messaging
UDP  2869  ICSLAP
UDP  2870  daishi
UDP  2871  MSI Select Play
UDP  2872  CONTRACT
UDP  2873  PASPAR2 ZoomIn
UDP  2874  dxmessagebase1
UDP  2875  dxmessagebase2
UDP  2876  SPS Tunnel
UDP  2877  BLUELANCE
UDP  2878  AAP
UDP  2879  ucentric-ds
UDP  2880  synapse
UDP  2881  NDSP
UDP  2882  NDTP
UDP  2883  NDNP
UDP  2884  Flash Msg
UDP  2885  TopFlow
UDP  2886  RESPONSELOGIC
UDP  2887  aironet
UDP  2888  SPCSDLOBBY
UDP  2889  RSOM
UDP  2890  CSPCLMULTI
UDP  2891  CINEGRFX-ELMD License Manager
UDP  2892  SNIFFERDATA
UDP  2893  VSECONNECTOR
UDP  2894  ABACUS-REMOTE
UDP  2895  NATUS LINK
UDP  2896  ECOVISIONG6-1
UDP  2897  Citrix RTMP
UDP  2898  APPLIANCE-CFG
UDP  2899  POWERGEMPLUS
UDP  2900  QUICKSUITE
UDP  2901  ALLSTORCNS
UDP  2902  NET ASPI
UDP  2903  SUITCASE
UDP  2904  M2UA
UDP  2905  M3UA
UDP  2906  CALLER9
UDP  2907  WEBMETHODS B2B
UDP  2908  mao
UDP  2909  Funk Dialout
UDP  2910  TDAccess
UDP  2911  Blockade
UDP  2912  Epicon
UDP  2913  Booster Ware
UDP  2914  Game Lobby
UDP  2915  TK Socket
UDP  2916  Elvin Server
UDP  2917  Elvin Client
UDP  2918  Kasten Chase Pad
UDP  2919  ROBOER
UDP  2920  ROBOEDA
UDP  2921  CESD Contents Delivery Management
UDP  2922  CESD Contents Delivery Data Transfer
UDP  2923  WTA-WSP-WTP-S
UDP  2924  PRECISE-VIP
UDP  2925  Firewall Redundancy Protocol
UDP  2926  MOBILE-FILE-DL
UDP  2927  UNIMOBILECTRL
UDP  2928  REDSONTE-CPSS
UDP  2929  PANJA-WEBADMIN
UDP  2930  PANJA-WEBLINX
UDP  2931  Circle-X
UDP  2932  INCP
UDP  2933  4-TIER OPM GW
UDP  2934  4-TIER OPM CLI
UDP  2935  QTP
UDP  2936  OTPatch
UDP  2937  PNACONSULT-LM
UDP  2938  SM-PAS-1
UDP  2939  SM-PAS-2
UDP  2940  SM-PAS-3
UDP  2941  SM-PAS-4
UDP  2942  SM-PAS-5
UDP  2943  TTNRepository
UDP  2944  Megaco H-248
UDP  2945  H248 Binary
UDP  2946  FJSVmpor
UDP  2947  GPSD
UDP  2948  WAP PUSH
UDP  2949  WAP PUSH SECURE
UDP  2950  ESIP
UDP  2951  OTTP
UDP  2952  MPFWSAS
UDP  2953  OVALARMSRV
UDP  2954  OVALARMSRV-CMD
UDP  2955  CSNOTIFY
UDP  2956  OVRIMOSDBMAN
UDP  2957  JAMCT5
UDP  2958  JAMCT6
UDP  2959  RMOPAGT
UDP  2960  DFOXSERVER
UDP  2961  BOLDSOFT-LM
UDP  2962  IPH-POLICY-CLI
UDP  2963  IPH-POLICY-ADM
UDP  2964  BULLANT SRAP
UDP  2965  BULLANT RAP
UDP  2966  IDP-INFOTRIEVE
UDP  2967  SSC-AGENT / Norton Antivirus
UDP  2968  ENPP
UDP  2969  ESSP
UDP  2970  INDEX-NET
UDP  2971  Net Clip
UDP  2972  PMSM Webrctl
UDP  2973  SV Networks
UDP  2974  Signal
UDP  2975  Fujitsu Configuration Management Service
UDP  2976  CNS Server Port
UDP  2977  TTCs Enterprise Test Access Protocol - NS
UDP  2978  TTCs Enterprise Test Access Protocol - DS
UDP  2979  H.263 Video Streaming
UDP  2980  Instant Messaging Service
UDP  2981  MYLXAMPORT
UDP  2982  IWB-WHITEBOARD
UDP  2983  NETPLAN
UDP  2984  HPIDSADMIN
UDP  2985  HPIDSAGENT
UDP  2986  STONEFALLS
UDP  2987  IDENTIFY
UDP  2988  CLASSIFY
UDP  2989  ZARKOV
UDP  2990  BOSCAP
UDP  2991  WKSTN-MON
UDP  2992  ITB301
UDP  2993  VERITAS VIS1
UDP  2994  VERITAS VIS2
UDP  2995  IDRS
UDP  2996  vsixml
UDP  2997  REBOL
UDP  2998  Real Secure
UDP  2999  RemoteWare Unassigned
UDP  3000  RemoteWare Client
UDP  3001  Redwood Broker
UDP  3002  RemoteWare Server
UDP  3003  CGMS
UDP  3004  Csoft Agent
UDP  3005  Genius License Manager
UDP  3006  Instant Internet Admin
UDP  3007  Lotus Mail Tracking Agent Protocol
UDP  3008  Midnight Technologies
UDP  3009  PXC-NTFY
UDP  3010  Telerate Workstation
UDP  3011  Trusted Web
UDP  3012  Trusted Web Client
UDP  3013  Gilat Sky Surfer
UDP  3014  Broker Service
UDP  3015  NATI DSTP
UDP  3016  Notify Server
UDP  3017  Event Listener
UDP  3018  Service Registry
UDP  3019  Resource Manager
UDP  3020  CIFS
UDP  3021  AGRI Server
UDP  3022  CSREGAGENT
UDP  3023  magicnotes
UDP  3024  NDS_SSO
UDP  3025  Arepa Raft
UDP  3026  AGRI Gateway
UDP  3027  LiebDevMgmt_C
UDP  3028  LiebDevMgmt_DM
UDP  3029  LiebDevMgmt_A
UDP  3030  Arepa Cas
UDP  3031  AgentVU
UDP  3032  Redwood Chat
UDP  3033  PDB
UDP  3034  Osmosis AEEA
UDP  3035  FJSV gssagt
UDP  3036  Hagel DUMP
UDP  3037  HP SAN Mgmt
UDP  3038  Santak UPS
UDP  3039  Cogitate Inc.
UDP  3040  Tomato Springs
UDP  3041  di-traceware
UDP  3042  journee
UDP  3043  BRP
UDP  3045  ResponseNet
UDP  3046  di-ase
UDP  3047  Fast Security HL Server
UDP  3048  Sierra Net PC Trader
UDP  3049  NSWS
UDP  3050  gds_db
UDP  3051  Galaxy Server
UDP  3052  APCPCNS
UDP  3053  dsom-server
UDP  3054  AMT CNF PROT
UDP  3055  Policy Server
UDP  3056  CDL Server
UDP  3057  GoAhead FldUp
UDP  3058  videobeans
UDP  3059  earlhaig.com
UDP  3060  interserver
UDP  3061  cautcpd
UDP  3062  ncacn-ip-tcp
UDP  3063  ncadg-ip-udp
UDP  3065  slinterbase
UDP  3066  NETATTACHSDMP
UDP  3067  FJHPJP
UDP  3068  ls3 Broadcast
UDP  3069  ls3
UDP  3070  MGXSWITCH
UDP  3075  Orbix 2000 Locator
UDP  3076  Orbix 2000 Config
UDP  3077  Orbix 2000 Locator SSL
UDP  3078  Orbix 2000 Locator SSL
UDP  3079  LV Front Panel
UDP  3080  stm_pproc
UDP  3081  TL1-LV
UDP  3082  TL1-RAW
UDP  3083  TL1-TELNET
UDP  3084  ITM-MCCS
UDP  3085  PCIHReq
UDP  3086  JDL-DBKitchen
UDP  3105  Cardbox
UDP  3106  Cardbox HTTP
UDP  3130  ICPv2
UDP  3131  Net Book Mark
UDP  3141  VMODEM
UDP  3142  RDC WH EOS
UDP  3143  Sea View
UDP  3144  Tarantella
UDP  3145  CSI-LFAP
UDP  3147  RFIO
UDP  3148  NetMike Game Administrator
UDP  3149  NetMike Game Server
UDP  3150  NetMike Assessor Administrator / Deep Throat (Windows Trojan) / Deep Throat 2 (Windows Trojan)
UDP  3151  NetMike Assessor
UDP  3180  Millicent Broker Server
UDP  3181  BMC Patrol Agent
UDP  3182  BMC Patrol Rendezvous
UDP  3262  NECP
UDP  3264  cc:mail/lotus
UDP  3265  Altav Tunnel
UDP  3266  NS CFG Server
UDP  3267  IBM Dial Out
UDP  3268  Microsoft Global Catalog
UDP  3269  Microsoft Global Catalog with LDAP/SSL
UDP  3270  Verismart
UDP  3271  CSoft Prev Port
UDP  3272  Fujitsu User Manager
UDP  3273  Simple Extensible Multiplexed Protocol
UDP  3274  Ordinox Server
UDP  3275  SAMD
UDP  3276  Maxim ASICs
UDP  3277  AWG Proxy
UDP  3278  LKCM Server
UDP  3279  admind
UDP  3280  VS Server
UDP  3281  SYSOPT
UDP  3282  Datusorb
UDP  3283  Net Assistant
UDP  3284  4Talk
UDP  3285  Plato
UDP  3286  E-Net
UDP  3287  DIRECTVDATA
UDP  3288  COPS
UDP  3289  ENPC
UDP  3290  CAPS LOGISTICS TOOLKIT - LM
UDP  3291  S A Holditch & Associates - LM
UDP  3292  Cart O Rama
UDP  3293  fg-fps
UDP  3294  fg-gip
UDP  3295  Dynamic IP Lookup
UDP  3296  Rib License Manager
UDP  3297  Cytel License Manager
UDP  3298  Transview
UDP  3299  pdrncs
UDP  3301  Unathorised use by SAP R/3
UDP  3302  MCS Fastmail
UDP  3303  OP Session Client
UDP  3304  OP Session Server
UDP  3305  ODETTE-FTP
UDP  3306  MySQL
UDP  3307  OP Session Proxy
UDP  3308  TNS Server
UDP  3309  TND ADV
UDP  3310  Dyna Access
UDP  3311  MCNS Tel Ret
UDP  3312  Application Management Server
UDP  3313  Unify Object Broker
UDP  3314  Unify Object Host
UDP  3315  CDID
UDP  3316  AICC/CMI
UDP  3317  VSAI PORT
UDP  3318  Swith to Swith Routing Information Protocol
UDP  3319  SDT License Manager
UDP  3320  Office Link 2000
UDP  3321  VNSSTR
UDP  3325  isi.edu
UDP  3326  SFTU
UDP  3327  BBARS
UDP  3328  Eaglepoint License Manager
UDP  3329  HP Device Disc
UDP  3330  MCS Calypso ICF
UDP  3331  MCS Messaging
UDP  3332  MCS Mail Server
UDP  3333  DEC Notes
UDP  3334  Direct TV Webcasting
UDP  3335  Direct TV Software Updates
UDP  3336  Direct TV Tickers
UDP  3337  Direct TV Data Catalog
UDP  3338  OMF data b
UDP  3339  OMF data l
UDP  3340  OMF data m
UDP  3341  OMF data h
UDP  3342  WebTIE
UDP  3343  MS Cluster Net
UDP  3344  BNT Manager
UDP  3345  Influence
UDP  3346  Trnsprnt Proxy
UDP  3347  Phoenix RPC
UDP  3348  Pangolin Laser
UDP  3349  Chevin Services
UDP  3350  FINDVIATV
UDP  3351  BTRIEVE
UDP  3352  SSQL
UDP  3353  FATPIPE
UDP  3354  SUITJD
UDP  3355  Ordinox Dbase
UDP  3356  UPNOTIFYPS
UDP  3357  Adtech Test IP
UDP  3358  Mp Sys Rmsvr
UDP  3359  WG NetForce
UDP  3360  KV Server
UDP  3361  KV Agent
UDP  3362  DJ ILM
UDP  3363  NATI Vi Server
UDP  3364  Creative Server
UDP  3365  Content Server
UDP  3366  Creative Partner
UDP  3371  ccm.jf.intel.com
UDP  3372  TIP 2
UDP  3373  Lavenir License Manager
UDP  3374  Cluster Disc
UDP  3375  VSNM Agent
UDP  3376  CD Broker
UDP  3377  Cogsys Network License Manager
UDP  3378  WSICOPY
UDP  3379  SOCORFS
UDP  3380  SNS Channels
UDP  3381  Geneous
UDP  3382  Fujitsu Network Enhanced Antitheft function
UDP  3383  Enterprise Software Products License Manager
UDP  3384  Hardware Management
UDP  3385  qnxnetman
UDP  3386  GPRS SIG
UDP  3387  Back Room Net
UDP  3388  CB Server
UDP  3389  MS WBT Server
UDP  3390  Distributed Service Coordinator
UDP  3391  SAVANT
UDP  3392  EFI License Management
UDP  3393  D2K Tapestry Client to Server
UDP  3394  D2K Tapestry Server to Server
UDP  3395  Dyna License Manager (Elam)
UDP  3396  Printer Agent
UDP  3397  Cloanto License Manager
UDP  3398  Mercantile
UDP  3399  CSMS
UDP  3400  CSMS2
UDP  3401  filecast
UDP  3421  Bull Apprise portmapper
UDP  3454  Apple Remote Access Protocol um.cc.umich.edu
UDP  3455  RSVP Port
UDP  3456  Microsoft IIS Server ATQ Backlog Monitor/ VAT default data
UDP  3457  VAT default control
UDP  3458  DsWinOSFI
UDP  3459  TIP Integral
UDP  3460  EDM Manger
UDP  3461  EDM Stager
UDP  3462  EDM STD Notify
UDP  3463  EDM ADM Notify
UDP  3464  EDM MGR Sync
UDP  3465  EDM MGR Cntrl
UDP  3466  WORKFLOW
UDP  3467  RCST
UDP  3468  TTCM Remote Controll
UDP  3469  Pluribus
UDP  3470  jt400
UDP  3471  jt400-ssl
UDP  3527  Microsoft Message Queuing Ping
UDP  3535  MS-LA
UDP  3563  Watcom Debug
UDP  3572  harlequin.co.uk
UDP  3672  harlequinorb
UDP  3802  VHD
UDP  3845  V-ONE Single Port Proxy
UDP  3862  GIGA-POCKET
UDP  3875  PNBSCADA
UDP  3900  Unidata UDT OS
UDP  3984  MAPPER network node manager
UDP  3985  MAPPER TCP/IP server
UDP  3986  MAPPER workstation server
UDP  3987  Centerline
UDP  4000  Terabase
UDP  4001  NewOak
UDP  4002  pxc-spvr-ft
UDP  4003  pxc-splr-ft
UDP  4004  pxc-roid
UDP  4005  pxc-pin
UDP  4006  pxc-spvr
UDP  4007  pxc-splr
UDP  4008  NetCheque accounting
UDP  4009  Chimera HWM
UDP  4010  Samsung Unidex
UDP  4011  BINLSVC / Alternate Service Boot
UDP  4012  PDA Gate
UDP  4013  ACL Manager
UDP  4014  TAICLOCK
UDP  4015  Talarian Mcast
UDP  4016  Talarian Mcast
UDP  4017  Talarian Mcast
UDP  4018  Talarian Mcast
UDP  4019  Talarian Mcast
UDP  4045  NFS lock daemon/manager
UDP  4096  BRE (Bridge Relay Element)
UDP  4097  Patrol View
UDP  4098  drmsfsd
UDP  4099  DPCP
UDP  4132  NUTS Daemon
UDP  4133  NUTS Bootp Server
UDP  4134  NIFTY-Serve HMI protocol
UDP  4141  Workflow Server
UDP  4142  Document Server
UDP  4143  Document Replication
UDP  4144  Compuserve pc windows (unoffically)
UDP  4156  Slapper.C
UDP  4160  Jini Discovery
UDP  4199  EIMS ADMIN
UDP  4299  earth.path.net
UDP  4300  Corel CCam
UDP  4321  Remote Who Is
UDP  4343  UNICALL
UDP  4344  VinaInstall
UDP  4345  Macro 4 Network AS
UDP  4346  ELAN LM
UDP  4347  LAN Surveyor
UDP  4348  ITOSE
UDP  4349  File System Port Map
UDP  4350  Net Device
UDP  4351  PLCY Net Services
UDP  4353  F5 iQuery
UDP  4442  Saris
UDP  4443  Pharos
UDP  4444  NV Video default
UDP  4445  UPNOTIFYP
UDP  4446  N1-FWP
UDP  4447  N1-RMGMT
UDP  4448  ASC Licence Manager
UDP  4449  PrivateWire
UDP  4450  Camp
UDP  4451  CTI System Msg
UDP  4452  CTI Program Load
UDP  4453  NSS Alert Manager
UDP  4454  NSS Agent Manager
UDP  4455  PR Chat User
UDP  4456  PR Chat Server
UDP  4457  PR Register
UDP  4500  sae-urn / LSASS / NAT-T
UDP  4501  urn-x-cdchoice
UDP  4545  WorldScores
UDP  4546  SF License Manager (Sentinel)
UDP  4547  Lanner License Manager
UDP  4567  TRAM
UDP  4568  BMC Reporting
UDP  4600  Piranha1
UDP  4601  Piranha2
UDP  4665  eDonkey
UDP  4672  remote file access server
UDP  4800  Icona Instant Messenging System
UDP  4801  Icona Web Embedded Chat
UDP  4802  Icona License System Server
UDP  4827  HTCP
UDP  4837  Varadero-0
UDP  4838  Varadero-1
UDP  4839  Varadero-2
UDP  4868  Photon Relay
UDP  4869  Photon Relay Debug
UDP  4885  ABBS
UDP  4983  AT&T Intercom
UDP  5000  filmaker.com
UDP  5001  filmaker.com
UDP  5002  radio free ethernet
UDP  5003  FileMaker Inc. - Proprietary name binding
UDP  5004  WMServer RTP / avt-profile-1
UDP  5005  WMServer RTCP / avt-profile-2
UDP  5006  wsm server
UDP  5007  wsm server ssl
UDP  5010  TelepathStart
UDP  5011  TelepathAttack
UDP  5020  zenginkyo-1
UDP  5021  zenginkyo-2
UDP  5042  asnaacceler8db
UDP  5050  multimedia conference control tool
UDP  5051  ITA Agent
UDP  5052  ITA Manager
UDP  5055  UNOT
UDP  5060  SIP
UDP  5069  I/Net 2000-NPR
UDP  5071  PowerSchool
UDP  5093  Sentinel LM
UDP  5099  SentLM Srv2Srv
UDP  5145  RMONITOR SECURE
UDP  5150  Ascend Tunnel Management Protocol
UDP  5151  ESRI SDE Remote Start
UDP  5152  ESRI SDE Instance Discovery
UDP  5165  ife_1corp
UDP  5190  America-Online
UDP  5191  AmericaOnline1
UDP  5192  AmericaOnline2
UDP  5193  AmericaOnline3
UDP  5200  Targus AIB 1
UDP  5201  Targus AIB 2
UDP  5202  Targus TNTS 1
UDP  5203  Targus TNTS 2
UDP  5236  padl2sim
UDP  5272  PK
UDP  5300  HA cluster heartbeat
UDP  5301  HA cluster general services
UDP  5302  HA cluster configuration
UDP  5303  HA cluster probing
UDP  5304  HA Cluster Commands hp.com
UDP  5305  HA Cluster Test hp.com
UDP  5306  Sun MC Group
UDP  5307  SCO AIP
UDP  5308  CFengine
UDP  5309  J Printer
UDP  5310  Outlaws
UDP  5311  TM Login
UDP  5400  Excerpt Search
UDP  5401  Excerpt Search Secure
UDP  5402  MFTP
UDP  5403  HPOMS-CI-LSTN
UDP  5404  HPOMS-DPS-LSTN
UDP  5405  NetSupport
UDP  5406  Systemics Sox
UDP  5407  Foresyte-Clear
UDP  5408  Foresyte-Sec
UDP  5409  Salient Data Server
UDP  5410  Salient User Manager
UDP  5411  ActNet
UDP  5412  Continuus
UDP  5413  WWIOTALK
UDP  5414  StatusD
UDP  5415  NS Server
UDP  5416  SNS Gateway
UDP  5417  SNS Agent
UDP  5418  MCNTP
UDP  5419  DJ-ICE
UDP  5420  Cylink-C
UDP  5421  Net Support 2
UDP  5422  Salient MUX
UDP  5423  VIRTUALUSER
UDP  5426  DEVBASIC
UDP  5427  SCO-PEER-TTA
UDP  5428  TELACONSOLE
UDP  5429  Billing and Accounting System Exchange
UDP  5430  RADEC CORP
UDP  5431  PARK AGENT
UDP  5435  Data Tunneling Transceiver Linking (DTTL)
UDP  5454  apc-tcp-udp-4
UDP  5455  apc-tcp-udp-5
UDP  5456  apc-tcp-udp-6
UDP  5461  SILKMETER
UDP  5462  TTL Publisher
UDP  5465  NETOPS-BROKER
UDP  5500  fcp-addr-srvr1
UDP  5501  fcp-addr-srvr2
UDP  5502  fcp-srvr-inst1
UDP  5503  fcp-srvr-inst2
UDP  5504  fcp-cics-gw1
UDP  5540  ACE/Server Services
UDP  5554  SGI ESP HTTP
UDP  5555  Personal Agent
UDP  5599  Enterprise Security Remote Install
UDP  5600  Enterprise Security Manager
UDP  5601  Enterprise Security Agent
UDP  5602  A1-MSC
UDP  5603  A1-BS
UDP  5604  A3-SDUNode
UDP  5605  A4-SDUNode
UDP  5631  pcANYWHEREdata
UDP  5632  pcANYWHEREstat
UDP  5678  Remote Replication Agent Connection
UDP  5679  Direct Cable Connect Manager
UDP  5713  proshare conf audio
UDP  5714  proshare conf video
UDP  5715  proshare conf data
UDP  5716  proshare conf request
UDP  5717  proshare conf notify
UDP  5729  Openmail User Agent Layer
UDP  5741  IDA Discover Port 1
UDP  5742  IDA Discover Port 2
UDP  5745  fcopy-server
UDP  5746  fcopys-server
UDP  5755  OpenMail Desk Gateway server
UDP  5757  OpenMail X.500 Directory Server
UDP  5766  OpenMail NewMail Server
UDP  5767  OpenMail Suer Agent Layer (Secure)
UDP  5768  OpenMail CMTS Server
UDP  5771  NetAgent
UDP  5813  ICMPD
UDP  5859  WHEREHOO
UDP  5968  mppolicy-v5
UDP  5969  mppolicy-mgr
UDP  5999  CVSup
UDP  6063  X Windows System mit.edu
UDP  6064  NDL-AHP-SVC
UDP  6065  WinPharaoh
UDP  6066  EWCTSP
UDP  6067  SRB
UDP  6068  GSMP
UDP  6069  TRIP
UDP  6070  Messageasap
UDP  6071  SSDTP
UDP  6072  DIAGNOSE-PROC
UDP  6073  DirectPlay8
UDP  6100  SynchroNet-db
UDP  6101  SynchroNet-rtc
UDP  6102  SynchroNet-upd
UDP  6103  RETS
UDP  6104  DBDB
UDP  6105  Prima Server
UDP  6106  MPS Server
UDP  6107  ETC Control
UDP  6108  Sercomm-SCAdmin
UDP  6109  GLOBECAST-ID
UDP  6110  HP SoftBench CM
UDP  6111  HP SoftBench Sub-Process Control
UDP  6112  dtspcd
UDP  6123  Backup Express
UDP  6141  Meta Corporation License Manager
UDP  6142  Aspen Technology License Manager
UDP  6143  Watershed License Manager
UDP  6144  StatSci License Manager - 1
UDP  6145  StatSci License Manager - 2
UDP  6146  Lone Wolf Systems License Manager
UDP  6147  Montage License Manager
UDP  6148  Ricardo North America License Manager
UDP  6149  tal-pod
UDP  6253  CRIP
UDP  6321  Empress Software Connectivity Server 1
UDP  6322  Empress Software Connectivity Server 2
UDP  6389  clariion-evr01
UDP  6400  saegatesoftware.com
UDP  6401  saegatesoftware.com
UDP  6402  saegatesoftware.com
UDP  6403  saegatesoftware.com
UDP  6404  saegatesoftware.com
UDP  6405  saegatesoftware.com
UDP  6406  saegatesoftware.com
UDP  6407  saegatesoftware.com
UDP  6408  saegatesoftware.com
UDP  6409  saegatesoftware.com
UDP  6410  saegatesoftware.com
UDP  6455  osmosys.incog.com
UDP  6456  osmosys.incog.com
UDP  6471  LVision License Manager
UDP  6500  BoKS Master
UDP  6501  BoKS Servc
UDP  6502  BoKS Servm
UDP  6503  BoKS Clntd
UDP  6505  BoKS Admin Private Port
UDP  6506  BoKS Admin Public Port
UDP  6507  BoKS Dir Server Private Port
UDP  6508  BoKS Dir Server Public Port
UDP  6547  apc-tcp-udp-1
UDP  6548  apc-tcp-udp-2
UDP  6549  apc-tcp-udp-3
UDP  6550  fg-sysupdate
UDP  6558  xdsxdm
UDP  6669  Internet Relay Chat acrux.com
UDP  6670  Vocaltec Global Online Directory
UDP  6672  vision_server
UDP  6673  vision_elmd
UDP  6699  Napster
UDP  6700  Napster
UDP  6701  KTI/ICAD Nameserver
UDP  6702  Carracho (client)
UDP  6767  BMC PERFORM AGENT
UDP  6768  BMC PERFORM MGRD
UDP  6790  HNMP
UDP  6831  ambit-lm
UDP  6838  DDOS communication UDP
UDP  6841  Netmo Default
UDP  6842  Netmo HTTP
UDP  6850  ICCRUSHMORE
UDP  6888  MUSE
UDP  6961  JMACT3
UDP  6962  jmevt2
UDP  6963  swismgr1
UDP  6964  swismgr2
UDP  6965  swistrap
UDP  6966  swispol
UDP  6969  acmsoda
UDP  6998  IATP-highPri
UDP  6999  IATP-normalPri
UDP  7000  file server itself
UDP  7001  callbacks to cache managers
UDP  7002  users & groups database
UDP  7003  volume location database
UDP  7004  AFS/Kerberos authentication service
UDP  7005  volume managment server
UDP  7006  error interpretation service
UDP  7007  basic overseer process
UDP  7008  server-to-server updater
UDP  7009  remote cache manager service
UDP  7010  onlinet uninterruptable power supplies
UDP  7011  Talon Discovery Port
UDP  7012  Talon Engine
UDP  7013  Microtalon Discovery
UDP  7014  Microtalon Communications
UDP  7015  Talon Webserver
UDP  7020  DP Serve
UDP  7021  DP Serve Admin
UDP  7070  ARCP
UDP  7099  lazy-ptop
UDP  7100  X Font Service
UDP  7121  Virtual Prototypes License Manager
UDP  7141  vnet.ibm.com
UDP  7170  Audio (inclusive) for incoming traffic only
UDP  7174  Clutild
UDP  7200  FODMS FLIP
UDP  7201  DLIP
UDP  7390  The Swiss Exchange swx.ch
UDP  7395  winqedit
UDP  7426  OpenView DM Postmaster Manager
UDP  7427  OpenView DM Event Agent Manager
UDP  7428  OpenView DM Log Agent Manager
UDP  7429  OpenView DM rqt communication
UDP  7430  OpenView DM xmpv7 api pipe
UDP  7431  OpenView DM ovc/xmpv3 api pipe
UDP  7437  Faximum
UDP  7491  telops-lmd
UDP  7511  pafec-lm
UDP  7544  FlowAnalyzer DisplayServer
UDP  7545  FlowAnalyzer UtilityServer
UDP  7566  VSI Omega
UDP  7570  Aries Kfinder
UDP  7588  Sun License Manager
UDP  7597  TROJAN WORM
UDP  7633  PMDF Management
UDP  7640  CUSeeMe
UDP  7648  CUCME live video/audio server
UDP  7649  CUCME live video/audio server
UDP  7650  CUCME live video/audio server
UDP  7651  CUCME live video/audio server
UDP  7777  cbt
UDP  7778  Interwise
UDP  7781  accu-lmgr
UDP  7786  MINIVEND
UDP  7932  Tier 2 Data Resource Manager
UDP  7933  Tier 2 Business Rules Manager
UDP  7967  Supercell
UDP  7979  Micromuse-ncps
UDP  7980  Quest Vista
UDP  7983  DDOS communication UDP
UDP  7999  iRDMI2
UDP  8000  iRDMI
UDP  8001  VCOM Tunnel
UDP  8002  Teradata ORDBMS
UDP  8008  HTTP Alternate
UDP  8032  ProEd
UDP  8033  MindPrint
UDP  8080  HTTP
UDP  8082  BlackICE Capture
UDP  8099  TestTrack Pro Client
UDP  8130  INDIGO-VRMI
UDP  8131  INDIGO-VBCP
UDP  8160  Patrol
UDP  8161  Patrol SNMP
UDP  8200  TRIVNET
UDP  8201  TRIVNET
UDP  8204  LM Perfworks
UDP  8205  LM Instmgr
UDP  8206  LM Dta
UDP  8207  LM SServer
UDP  8208  LM Webwatcher
UDP  8351  Server Find
UDP  8376  Cruise ENUM
UDP  8377  Cruise SWROUTE
UDP  8378  Cruise CONFIG
UDP  8379  Cruise DIAGS
UDP  8380  Cruise UPDATE
UDP  8400  cvd
UDP  8401  sabarsd
UDP  8402  abarsd
UDP  8403  admind
UDP  8450  npmp
UDP  8473  Virtual Point to Point
UDP  8554  RTSP Alternate (see port 554)
UDP  8733  iBus
UDP  8763  MC-APPSERVER
UDP  8764  OPENQUEUE
UDP  8765  Ultraseek HTTP
UDP  8804  truecm
UDP  8880  CDDBP
UDP  8888  NewsEDGE server UDP (UDP 1)
UDP  8889  NewsEDGE server broadcast
UDP  8890  NewsEDGE client broadcast
UDP  8891  Desktop Data UDP 3: NESS application
UDP  8892  Desktop Data UDP 4: FARM product
UDP  8893  Desktop Data UDP 5: NewsEDGE/Web application
UDP  8894  Desktop Data UDP 6: COAL application
UDP  8900  JMB-CDS 1
UDP  8901  JMB-CDS 2
UDP  9000  CSlistener
UDP  9090  WebSM
UDP  9160  NetLOCK1
UDP  9161  NetLOCK2
UDP  9162  NetLOCK3
UDP  9163  NetLOCK4
UDP  9164  NetLOCK5
UDP  9200  WAP connectionless session service
UDP  9201  WAP session service
UDP  9202  WAP secure connectionless session service
UDP  9203  WAP secure session service
UDP  9204  WAP vCard
UDP  9205  WAP vCal
UDP  9206  WAP vCard Secure
UDP  9207  WAP vCal Secure
UDP  9321  guibase
UDP  9325  DDOS communication UDP
UDP  9343  MpIdcMgr
UDP  9344  Mphlpdmc
UDP  9374  fjdmimgr
UDP  9396  fjinvmgr
UDP  9397  MpIdcAgt
UDP  9500  ismserver
UDP  9535  Remote man server
UDP  9594  Message System
UDP  9595  Ping Discovery Service
UDP  9600  MICROMUSE-NCPW
UDP  9753  rasadv
UDP  9876  Session Director
UDP  9888  CYBORG Systems
UDP  9898  MonkeyCom
UDP  9899  SCTP TUNNELING
UDP  9900  IUA
UDP  9909  domaintime
UDP  9950  APCPCPLUSWIN1
UDP  9951  APCPCPLUSWIN2
UDP  9952  APCPCPLUSWIN3
UDP  9992  Palace
UDP  9993  Palace
UDP  9994  Palace
UDP  9995  Palace
UDP  9996  Palace
UDP  9997  Palace
UDP  9998  Distinct32
UDP  9999  distinct
UDP  10000  Network Data Management Protocol
UDP  10001  rscsl
UDP  10002  rscs2
UDP  10003  rscs3
UDP  10004  rscs4
UDP  10005  rscs5
UDP  10006  rscs6
UDP  10007  MVS Capacity
UDP  10008  rscs8
UDP  10009  rscs9
UDP  10010  rscsa
UDP  10011  rscsb
UDP  10012  qmaster
UDP  10067  Portal of Doom remote access backdoor
UDP  10080  Amanda
UDP  10113  NetIQ Endpoint
UDP  10114  NetIQ Qcheck
UDP  10115  Ganymede Endpoint
UDP  10128  BMC-PERFORM-SERVICE DAEMON
UDP  10167  Portal of Doom remote access backdoor
UDP  10288  Blocks
UDP  10498  DDOS Communication UDP
UDP  11000  IRISA
UDP  11001  Metasys
UDP  11111  Viral Computing Environment (VCE)
UDP  11367  ATM UHAS
UDP  11487  Dell OpenManage Client Instrumentation
UDP  11720  h323 Call Signal Alternate
UDP  12000  IBM Enterprise Extender SNA XID Exchange
UDP  12001  IBM Enterprise Extender SNA COS Network Priority
UDP  12002  IBM Enterprise Extender SNA COS High Priority
UDP  12003  IBM Enterprise Extender SNA COS Medium Priority
UDP  12004  IBM Enterprise Extender SNA COS Low Priority
UDP  12172  HiveP
UDP  12753  tsaf port
UDP  13160  I-ZIPQD
UDP  13223  PowWow Client
UDP  13224  PowWow Server
UDP  13720  BPRD Protocol (VERITAS NetBackup)
UDP  13721  BPBRM Protocol (VERITAS NetBackup)
UDP  13722  BP Java MSVC Protocol
UDP  13782  VERITAS NetBackup
UDP  13783  VOPIED Protocol
UDP  13818  DSMCC Config
UDP  13819  DSMCC Session Messages
UDP  13820  DSMCC Pass-Thru Messages
UDP  13821  DSMCC Download Protocol
UDP  13822  DSMCC Channel Change Protocol
UDP  14001  ITU SCCP (SS7)
UDP  14238  Palm Network Hotsync
UDP  16360  netserialext1
UDP  16361  netserialext2
UDP  16367  netserialext3
UDP  16368  netserialext4
UDP  16991  INTEL-RCI-MP
UDP  17007  isode-dua
UDP  17219  Chipper
UDP  18000  Beckman Instruments Inc.
UDP  18181  OPSEC CVP
UDP  18182  OPSEC UFP
UDP  18183  OPSEC SAM
UDP  18184  OPSEC LEA
UDP  18185  OPSEC OMI
UDP  18187  OPSEC ELA
UDP  18463  AC Cluster
UDP  18753  Shaft distributed attack tool handler agent
UDP  18888  APCNECMP
UDP  19283  Key Server for SASSAFRAS
UDP  19315  Key Shadow for SASSAFRAS
UDP  19410  hp-sco
UDP  19411  hp-sca
UDP  19412  HP-SESSMON
UDP  19541  JCP Client
UDP  20000  DNP
UDP  20432  Shaft distributed attack agent
UDP  20670  Track
UDP  20999  AT Hand MMP
UDP  21590  VoFR Gateway
UDP  21845  webphone
UDP  21846  NetSpeak Corp. Directory Services
UDP  21847  NetSpeak Corp. Connection Services
UDP  21848  NetSpeak Corp. Automatic Call Distribution
UDP  21849  NetSpeak Corp. Credit Processing System
UDP  22000  SNAPenetIO
UDP  22001  OptoControl
UDP  22273  wnn6
UDP  22555  Vocaltec Internet Phone
UDP  22800  Telerate Information Platform LAN
UDP  22951  Telerate Information Platform WAN
UDP  24000  med-ltp
UDP  24001  med-fsp-rx
UDP  24002  med-fsp-tx
UDP  24003  med-supp
UDP  24004  med-ovw
UDP  24005  med-ci
UDP  24006  med-net-svc
UDP  24386  Intel RCI
UDP  24554  BINKP
UDP  25000  icl-twobase1
UDP  25001  icl-twobase2
UDP  25002  icl-twobase3
UDP  25003  icl-twobase4
UDP  25004  icl-twobase5
UDP  25005  icl-twobase6
UDP  25006  icl-twobase7
UDP  25007  icl-twobase8
UDP  25008  icl-twobase9
UDP  25009  icl-twobase10
UDP  25793  Vocaltec Address Server
UDP  26000  quake
UDP  26208  wnn6-ds
UDP  27010  Half-Life Server Master
UDP  27011  Half-Life Mod Master
UDP  27374  Linux.Ramen.Worm (RedHat Linux)
UDP  27444  Trinoo distributed attack tool Master
UDP  27999  Attribute Certificate Services
UDP  31335  Trinoo distributed attack tool Bcast Daemon registration port
UDP  31337  Back Orifice (Windows Trojan)
UDP  31338  Deep Back Orifice (Windows Trojan)
UDP  31789  Hack-A-Tack Remote Access Trojan (Windows Trojan)
UDP  31791  Hack-A-Tack Remote Access Trojan (Windows Trojan)
UDP  32768  Filenet TMS
UDP  32769  Filenet RPC
UDP  32770  Filenet NCH
UDP  32780  RPC
UDP  33270  Trinity v3 distributed attack tool
UDP  33434  traceroute use
UDP  34555  Trinoo distributed attack tool Handler
UDP  36865  KastenX Pipe
UDP  40841  CSCP
UDP  43981  Netware IP
UDP  44333  Kerio WinRoute Firewall Administration
UDP  44334  Kerio Personal Firewall Administration
UDP  44337  Kerio MailServer Administration
UDP  44818  Rockwell Encapsulation
UDP  45678  EBA PRISE
UDP  45966  SSRServerMgr
UDP  47557  Databeam Corporation
UDP  47624  Direct Play Server
UDP  47806  ALC Protocol
UDP  47808  Building Automation and Control Networks
UDP  48000  Nimbus Controller
UDP  48001  Nimbus Spooler
UDP  48002  Nimbus Hub
UDP  48003  Nimbus Gateway
UDP  54321  Orifice 2000 (UDP)


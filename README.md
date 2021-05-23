# Snort-Open-Source-Intrusion-Detection-System


 ## _Project Name_
 

* _Snort | Open Source Intrusion Detection System_


## _Project Program Used_
 

*  _Snort_


## _What is Snort?_

#### Snort is a network intrusion detection system developed in 1998 by Martin Roesch. Snort, an open source and free software distributed under GNU license, is currently developed by Sourcefire, a company founded by Martin Roesch. 

## _Features of Snort_

*	Real-time traffic monitor
*	Packet logging
*	Analysis of protocol
*	Content matching
*	OS fingerprinting
*	Can be installed in any network environment.
*	Creates logs
*	Open Sourse
*	Rules are easy to implement

## _Purpose of Snort_

#### The main purpose of Snort is to perform packet logging and traffic analysis on the network. In this case, Snort has three primary uses: As a packet sniffer, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. 

## _Snort Architectural Structure_

#### Snort is made up of different components, and these components work together to identify attacks and generate output. Snort-based IDS systems mainly consist of the following components:

* Packet Decoder
* Preprocessors
* Detection Engine
* Logging and Alerting System
* Output Modules

![image](https://user-images.githubusercontent.com/45822686/118878770-979d4a00-b8f8-11eb-8a56-a4e781a8f931.png)

## _Some Advantages and Disadvantages_

* Snort provides open source and free monitoring for network and computer.
* Any alterations to files and directories on the system can be easily detected and reported.

* When deploying Snort, it’s important to make sure the used rules are relevant and up to date, otherwise the system will be much less efficient
* Although Snort is flexible, it does lack some features found in commercial intrusion detection systems.


## _Cyber Security Solutions Provided by Snort_

#### It has some cyber security solutions provided to us. 
* Snort is to do packet logging and traffic analysis on the network. 
* Snort can detect many attacks and malicious / suspicious software.
* Snort can also be used to perform network/protocol analysis, content searching and matching.

## _Snort Alerts_

#### Alerts are placed in the Alert file in the logging directory. Snort has 6 alert modes. These are fast, full, console, cmg, unsock and none. We applied cmg and console modes. Also, the mode Snort is run in depends on which flags are used with the Snort command.


#### Each alert carry the following information:

*	IP  address of the source
*	IP address of the destination
*	Packet type and useful header information


## _Snort Rules Structure_

The SNORT rule language determines which network traffic should be collected and what should happen when it detects malicious packets. Snort rules are divided into two logical sections, the rule header and the rule options.  The rule header contains the rule's action, protocol, source, destination IP addresses, netmasks,  the source and destination ports information. The rule option section contains alert messages and information on which parts of the packet should be inspected to determine if the rule action should be taken.

```
<Rule Actions> <Protocol> <Source IP Address> <Source Port> <Direction Operator> <Destination IP Address> <Destination port > (rule options)

```

![image](https://user-images.githubusercontent.com/45822686/118878921-c9161580-b8f8-11eb-8787-14ec99898dea.png)



## _Snort Setup_

#### In the installation to be done on the Ubuntu 17.04 in the virtual machine, we first made machine updates and then went to the installation phase. 

## Install Steps

```
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
                      
wget https://www.snort.org/downloads/snort/snort-2.9.17.1.tar.gz
tar xvzf daq-2.0.7.tar.gz
                      
cd daq-2.0.7
./configure && make && sudo make install
tar xvzf snort-2.9.17.1.tar.gz
                      
cd snort-2.9.17.1
./configure --enable-sourcefire && make && sudo make install 

```


## _Configure Snort_

```
 Commands Used:
 
- snort -V
- ifconfig
- sudo snort -T -i eth0 -c /etc/cnort/snort.conf
- snort -r
- apt-get update
- apt-get install nmap

```



## _Detecting Ping in Snort With Various Snort Alerts Modes_


```
Snort CMG MODE

- Ping 192.168.x.x
- snort -c /etc/snort/snort.conf -q -A cmg

```


```
Snort Console MODE

- ping 192.168.x.x
- snort -c /etc/snort/snort.conf -q -A console
```


```
Creating Rule for Ping Attacks

- sudo gedit /etc/snort/rules/local.rules
- alert  icmp 192.168.x.x any -> $HOME_NET any (msg:”Warning Ping Detected”; sid:1000002; rev:1; classtype:icmp-event;)
- sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3
- ping 192.168.x.x

```



## _Detecting FTP Connection Example_

```
Creating Rule for FTP

- sudo gedit /etc/snort/rules/local.rules
- alert tcp 192.168.x.x any -> $HOME_NET 21 (msg:”FTP connection attempt”; sid:1000002; rev:1;)
- snort -c /etc/snort/snort.conf -q -A console
- ftp 192.168.x.x

```

## _Snort Nmap Scan Detecting Examples_


```
Nmap Scan Detect Without Rule

- snort -c /etc/snort/snort.conf -q -A console
- nmap -sP 192.168.x.x --disable-arp-ping

```


```
Nmap Scan Detect With Rule

- sudo gedit /etc/snort/rules/local.rules
- alert  icmp 192.168.x.x any -> $HOME_NET any (msg:”Nmap Scan Detected”; sid:1000001; rev:1; classtype:icmp-event;)
- snort -c /etc/snort/snort.conf -q -A cmg
- nmap -sP 192.168.x.x --disable-arp-ping

```

```
Nmap TCP Scan Detect With Rule

- sudo gedit /etc/snort/rules/local.rules
- alert  icmp 192.168.x.x any -> $HOME_NET 22 (msg:”Nmap TCP Scan Detected”; sid:10000005; rev:2; classtype:tcp-event;)
- snort -c /etc/snort/snort.conf -q -A console
- nmap -sT -p22 192.168.x.x

```


## _Team Members_


* _Aleyna Eser - 17030411052_  
* _Rumeysa Özer - 17030411005_


## _References_

* Raj Chande, December 22, 2017,  https://www.hackingarticles.in/detect-nmap-scan-using-snort/
* Infosec, March 1, 2021, https://resources.infosecinstitute.com/topic/snort-rules-workshop-part-one/
* sankethj, 3 Ara 2020, https://dev.to/sankethj/detect-dos-ping-etc-using-snort-4gab
* Ivan Vanney, 2019, https://linuxhint.com/snort_alerts/
* Hüsnü İŞLEYEN, 8 Sep 2014, https://github.com/slyn/Snort/blob/master/Snort%20ve%20Eklentileri.md
* Prısma, https://www.prismacsi.com/snort-kullanimi/#:~:text=Snort%20esnek%20mimarisi%20sayesinde%20bir,esnek%20kurallar%20yazabilme%20imkan%C4%B1%20vermesidir.
* P. Israelsson, J.Karlsson and G. Giamarchi, October 17, 2005, https://www.it.uu.se/edu/course/homepage/sakdat/ht05/assignments/pm/programme/Introduction_to_snort.pdf

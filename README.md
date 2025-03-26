# End-to-End Detection of Network Compression

## Contents of this file

 - Introduction
 - Requirements
 - Installation
 - Configuration
 - Preparation
 - Part 1 - Client - Server Program
 - Part 2 - Standalone Application
 - Troubleshooting
 - Maintainers
## Introduction

This project is to detect when in robust sending HUGE number of UDP packet, the low entropy packets and high entropy packets payload will have similar time. 

- Low entropy packets: Static or patterned text such as 0000..., aaaa..., abab..., etc.
- High entropy packets: Payload full of randomized characters a8Tr39Vvs...

If both time difference is less than 100ms threshold, then it means low entropy packets does not have compression when going through router and network. If high entropy time subracting low entropy time has over 100ms threshold, that means there is indeed compression happening on low entropy packets when going through network and router. 

Normally, there should be mostly "Compression not detected" in both client-server program and standalone application. However, it is not guaranteed since there might be problem at network, routers, or even OS. In addition, if there are occasions that low entropy time is higher than high entropy, but the absolute value is still within 100ms, it should be fine as just proving there is no compression detected for low entropy packet train.

Note: The default test always gives 6000 UDP packet for each train, and each UDP packet has 1000 byte payload(1000 ASCII characters)
 
## Requirements

### CJSON Library

You need CJson libarary installed and C compiler newer or atleast C11. You also need a Linux Ubuntu or Debian environment and 2 machines having those OS.

**Note**: C11 solves issue for empty declaring pointer struct

### Increase Receive Buffer on OS level
- You also need to set receiver buffer on server/destination machine to 32 MB\
`sudo sysctl net.core.rmem_max=33554432`

- If you do not feel save even after you call `setsockopt()` to increase receiving buffer in program, you can also do\
`sudo sysctl net.core.rmem_default=33554432`



## Installation

- install CJSON for parsing your configuration on Ubuntu/Debian OS\
`sudo apt-get install libcjson-dev`\
Make sure it is on /usr/include/cJSON/cJSON.h so you can do `#include<cjson/cJSON>`


### Configuration

These are configuration parameters set in `myconfig.JSON`
 - `src_ip` is the source/client IP in IPv4
 - `dest_ip` is destination/server IP in IPv4
 - `udp_src_port` is UDP source/client port (Default: 9876)
 - `udp_dest_port` is UDP destination/server Port (Default: 8765)
 - `tcp_head_syn_dest_port` is TCP syn head port (Only for part 2, Default: 9999)
 - `tcp_tail_syn_dest_port` is TCP syn head port (Only for part 2, Default: 8888)
 - `tcp_port_pre_probe` is TCP pre probe port (Only for part 1, Default: 7777)
 - `tcp_port_post_probe` is TCP post probe port (Only for part 1, Default: 6666)
 - `packet_size` is size of payload in each UDP packet (Default: 1000)
 - `inter_time` is inter-measurement time between sending low and high UDP entropy train
 - `packet_count` is total packet count to be sent in UDP train
 - `udp_ttl` is time to live for UDP (Only for part 2, Default: 255)

## Peparation

Type `ifconfig` in Linux terminal, you will see such:

- eth0: flags...\
- eth1: flags... inet 192.168.xxx.xxx
- eth3: flags...

In eth1, you see inet parameter starts with `192.168.xxx.xxx`, That is the IPv4 you will need to fill on configuration file depending on you role(server/client)

## Part 1

- Boot up client and server's terminal, assume you filled out required `myconfig.JSON` on both machines

- In client, enter `gcc compdetect_client.c -o compdetect_client`

- In server, enter `gcc compdetect_server.c -o compdetect_server`

- In wireshark, click on interface to be captured as the network interface that has inet IPv4 appeared on `ifconfig`. Set capture filter `host 192.168.xxx.xxx and 192.168.xxx.xxx and (tcp or udp)`. 2 hosts are source and destination IP address. You can choose to whether also capture on server, but client is a must.

- You will see both object or exe files of corresponding name appearing

- Enter `./compdetect_server 7777` on server terminal and press enter to run. 7777 means you set your server's TCP pre probing phase port number

- After your server starts running, enter `./compdetect_client myconfig.JSON`

- Now both client and server will start communicating and wait until client shows either `Compression detected!` or `Compression not detected!`

## Maintainers

Current maintainers:
- Sascha Eggenberger ([@saschaeggi](https://www.drupal.org/u/saschaeggi))

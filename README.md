# Gin Admin Theme

## Contents of this file

 - Introduction
 - Requirements
 - Installation
 - Configuration
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
Make sure it is on /usr/include/cJSON/cJSON.h so you can do #include<cjson/cJSON>


### Set Gin as default admin theme

 - Navigate to Admin > Appearance
 - On the same page, click "Install" under Gin
 - At the bottom of the page, switch the Administration theme to Gin

## Troubleshooting

- Setup Gin locally that you can compile CSS & JS files.\
`nvm use && npm i`

- Run dev env with watcher and debug output (development process)\
`npm run dev`

- Compile assets\
`npm run build`

## Maintainers

Current maintainers:
- Sascha Eggenberger ([@saschaeggi](https://www.drupal.org/u/saschaeggi))

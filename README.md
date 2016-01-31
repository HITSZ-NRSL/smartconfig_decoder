# smartconfig_decoder for ESP8266, airkiss

Version 0.1 airkiss is not supported

## How to use the code

- Download and make
```
  $ git clone https://github.com/HITSZ-NRSL/smartconfig_decoder.git
  $ cd smartconfig-decoder/molmc-smartconfig-0.1/files/
  $ make
```
   With the code compiled, you can find two excutable files: smartconfig-dump and smartconfig-response, as well as one script file in scripts airmon-ng
  
- Use to test smartconfig
   The smartconfig can be tested at PC-Linux and OpenWrt
   - PC-Linux:
      ```
        $ sudo airmon-ng start wlan0
        $ sudo ifconfig wlan0 down
        $ sudo smartconfig-dump
      ```
      Open your smartphone IntoRobot App and perform the device configuration. You can find your shell printing some interesting information which is sent by your App
   
    - OpenWrt:
      Copy the molmc-smartconfig-0.1 direction to the openwrt's package/intorobot/, and then compile the openwrt source code
      ```
        $ make V=99
      ```
      if the compilation succeeds, flash the built firmware to your IntoRobot-Atom.Login to Atom via telnet
      ```
        $ telnet 192.168.8.1
        atom$ airmon-ng start wlan0
        atom$ smartconfig_get_ap_info
      ```
       Open your smartphone IntoRobot App and perform the device configuration. You can find your shell printing some interesting information which is sent by your App

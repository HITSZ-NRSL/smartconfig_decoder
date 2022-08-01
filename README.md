## 1. 说明：
由NROS-Lab开发的WIFI账户密码智能配置算法库，该方法通过WIFI广播信号的信息编码，无需手动输入即可实现账号和密码的自动设置，可以用于大批量机器人和物联网设备的快速自主联网配置，简单便捷。这个代码可以直接用于ESP8266相关的设备。
   
## 2. How to use the code

- Download and make
```
  $ git clone https://github.com/HITSZ-NRSL/smartconfig_decoder.git
  $ cd smartconfig-decoder/molmc-smartconfig-0.1/files/
  $ make
```
   With the code compiled, you can find two excutable files: smartconfig-dump and smartconfig-response, as well as one script file in scripts airmon-ng
  
- Test smartconfig at PC-Linux 
    ```
      $ sudo airmon-ng start wlan0
      $ sudo ifconfig wlan0 down
      $ sudo smartconfig-dump
    ```   
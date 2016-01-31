/*
 * File:   main.c
 * Author: tianshuai
 *
 * Created on 2011年11月29日, 下午10:34
 *
 * 主要实现：发送20个文本消息，然后再发送一个终止消息
 */

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "smartconfig-response.h"

int port=5557;
//the response packet format is: ApSsid, ApPasswd, mac地址，ip地址，数据总长度．
//the argument is: (ApSsid+ApPasswd).length+9, mac地址，ip地址，数据总长度．
int main(int argc, char** argv) {

    if(argc<5)
	return 0; //not enough arguments

    char *ap_ssid;
    char *ap_passwd;
    char *mac;
    char *ip;
    int total_length;
    int ssid_pass_length;
 
    ap_ssid = (char*)malloc(sizeof(argv[1]);
    memcpy(ap_ssid, argv[1]);
    ap_passwd = (char*)malloc(sizeof(argv[2]));
    memcpy(ap_passwd, argv[2]);
    mac = (char*)malloc(sizeof(argv[3]));
    memcpy(ap_passwd, argv[3]);
    ip = (char*)malloc(sizeof(argv[4]));
    memcpy(ip, argv[4]);
    total_length = atoi(argv[4]);

    ssid_pass_length = strlen(ap_ssid) + strlen(ap_passwd) + 9;
    int socket_descriptor; //套接口描述字
    int iter=0;
    char buf[80];
    struct sockaddr_in address;//处理网络通信的地址

    strcat(buf, (char)ssid_pass_length);
    strcat(buf, mac);
    strcat(buf, ip);
    strcat(buf, (char)total_length);

    bzero(&address,sizeof(address));
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=inet_addr(ip);//这里不一样
    address.sin_port=htons(port);

    //创建一个 UDP socket

    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议）

    for(iter=0;iter<=20;iter++)
    {
       sprintf(s, "%d%s%s%d", ssid_pass_length, mac, ip, total_lenght); //产生：" 123 4567"
       sendto(socket_descriptor,buf,sizeof(buf),0,(struct sockaddr *)&address,sizeof(address));
    }

    sprintf(buf,"stop\n");
    sendto(socket_descriptor,buf,sizeof(buf),0,(struct sockaddr *)&address,sizeof(address));//发送stop 命令
    close(socket_descriptor);
    printf("Messages Sent,terminating\n");

    exit(0);

    return (EXIT_SUCCESS);
}

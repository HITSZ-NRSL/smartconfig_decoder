/*
 * File:   smartconfig-response.c
 * Author: Haoyao Chen
 *
 * Created on Jan 20 2016
 *
 * Description: Send response message back to User's App to notice the result of smart config.
 */

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

char usage[] =
"\n"
"  %s - (C) 2016-2017 MOLMC Ltd. Co.\n"
"  http://www.intorobot.com\n"
"\n"
"  usage: smartconfig-response <options> \n"
"\n"
"  Options:\n"
"      -s --apssid              : AP's ssid\n"
"      -w --appasswd            : AP's password\n"
"      -b --apbssid             : AP's bssid (mac address)\n"
"      -p --port                : udp socket port of User's App\n"
"      -i --ip                  : ip address of User's Phone\n"
"\n"
"      -h --help                : Displays this usage screen\n"
"\n";


struct option long_options[] = {
        {"apssid",   1, 0, 's'},
        {"appasswd", 1, 0, 'w'},
        {"apbssid",  1, 0, 'b'},
        {"port",     1, 0, 'p'},
        {"ip",       1, 0, 'i'},
        {"help",     0, 0, 'h'},
    };

//the response packet format is: -s ApSsid, -p ApPasswd, -b bssid(mac)地址，-i ip地址．
//the argument is: (ApSsid+ApPasswd).length+9, mac地址，ip地址，数据总长度．
int main(int argc, char** argv) {

	int i;
    char *string = NULL;
    int port=5557;
    char *ap_ssid = NULL;
    char *ap_passwd = NULL;
    unsigned char ap_bssid[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char ip[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    char *str_ip = NULL;
    int total_length = 11;  //1+4+6=11 constant value
    int ssidpasswd_length;
    int option;
    int socket_descriptor; //套接口描述字
    int iter=0;
    char buf[80];
    struct sockaddr_in address;//处理网络通信的地址
    char version[] = "0.1";

    if(argc != 11) {
		printf("Please provide all the arguments");
		printf(usage, version );
		return 0; //not enough arguments
	}

    do {
        option = getopt_long( argc, argv, "s:w:b:p:i:", long_options, NULL);

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :
                break;

            case ':':
                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?':
                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 's':
            	ap_ssid = (char*)malloc(strlen(optarg) + 1);
            	strcpy(ap_ssid, optarg);
                break;

            case 'w':
            	ap_passwd = (char*)malloc(strlen(optarg) + 1);
            	strcpy(ap_passwd, optarg);
                break;

            case 'b':
            	sscanf(optarg, "%x:%x:%x:%x:%x:%x", &ap_bssid[0], &ap_bssid[1], &ap_bssid[2], &ap_bssid[3], &ap_bssid[4], &ap_bssid[5]);
            	//string = strtok( optarg, ":");
            	//ap_bssid[0] = atoi(string);
            	//i=0;
            	//while(string != NULL) {
            	//	string = strtok(NULL, ".");
            	//	i++;
            	//	ap_bssid[i] = atoi(string);
            	//}
                break;

            case 'p':
            	port = atoi(optarg);
                break;

            case 'i':
            	str_ip = (char*)malloc(strlen(optarg) + 1);
            	strcpy(str_ip, optarg);

            	sscanf(optarg, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]);
            	//string = strtok( optarg, ".");
            	//ip[0] = atoi(string);
            	//i=0;
            	//while(string != NULL) {
            ///		string = strtok(NULL, ".");
            //		i++;
            //		ip[i] = atoi(string);
           // 	}
                break;

        }
     }while(1); 

    if(ap_passwd!=NULL)  //no password
	ssidpasswd_length = strlen(ap_ssid) + strlen(ap_passwd) + 9;
    else
	ssidpasswd_length = strlen(ap_ssid) + 9;

    bzero(&address,sizeof(address));
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=inet_addr(str_ip);
    address.sin_port=htons(port);

    //创建一个 UDP socket
    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议）

    for(iter=0;iter<=11120;iter++)
    {
		buf[0] = (unsigned char)ssidpasswd_length;

		for(i=0; i<6;i++){
			buf[1+i] = ap_bssid[i];
		}
	
		for(i=0; i<4;i++){
			buf[7+i] = ip[i];
		}
		buf[11] = (unsigned char)total_length;
		//sprintf(buf,"%c%s%s%c", (unsigned char)ssidpasswd_length, ap_bssid, ip, (unsigned char)total_length);
        sendto(socket_descriptor,buf,12,0,(struct sockaddr *)&address,sizeof(address));
    }
    //  printf("%s, %s, %s, %d, %d " , str_ip, ap_ssid, ap_passwd, total_length, ssidpasswd_length);
	for(iter = 0; iter<12; iter++)
		printf("%02X ", (unsigned char)buf[iter]);

    close(socket_descriptor);
    printf("Messages Sent,terminating\n");

	if(ap_ssid!=NULL)
		free(ap_ssid);

	if(ap_passwd!=NULL)
		free(ap_passwd);

	if(str_ip!=NULL)
			free(str_ip);

    exit(0);

    return (EXIT_SUCCESS);
}

/*
 *  pcap-compatible 802.11 packet sniffer
 *
 *  Copyright (C) 2006-2013 Thomas d'Otreppe
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#ifndef TIOCGWINSZ
	#include <sys/termios.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <termios.h>

#include <sys/wait.h>

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "version.h"
#include "pcap.h"
#include "uniqueiv.h"
#include "crypto.h"
#include "osdep/osdep.h"
#include "airodump-ng.h"
#include "osdep/common.h"
#include "common.h"

#ifdef USE_GCRYPT
	GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

void reset_term() {
  struct termios oldt,
                 newt;
  tcgetattr( STDIN_FILENO, &oldt );
  newt = oldt;
  newt.c_lflag |= ( ICANON | ECHO );
  tcsetattr( STDIN_FILENO, TCSANOW, &newt );
}

int mygetch( ) {
  struct termios oldt,
                 newt;
  int            ch;
  tcgetattr( STDIN_FILENO, &oldt );
  newt = oldt;
  newt.c_lflag &= ~( ICANON | ECHO );
  tcsetattr( STDIN_FILENO, TCSANOW, &newt );
  ch = getchar();
  tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
  return ch;
}

void resetSelection()
{
    G.sort_by = SORT_BY_POWER;
    G.sort_inv = 1;

    G.start_print_ap=1;
    G.start_print_sta=1;
    G.selected_ap=1;
    G.selected_sta=1;
    G.selection_ap=0;
    G.selection_sta=0;
    G.mark_cur_ap=0;
    G.skip_columns=0;
    G.do_pause=0;
    G.do_sort_always=0;
    memset(G.selected_bssid, '\x00', 6);
}


void trim(char *str)
{
    int i;
    int begin = 0;
    int end = strlen(str) - 1;

    while (isspace((int)str[begin])) begin++;
    while ((end >= begin) && isspace((int)str[end])) end--;
    // Shift all characters back to the start of the string array.
    for (i = begin; i <= end; i++)
        str[i - begin] = str[i];
    str[i - begin] = '\0'; // Null terminate string.
}

int check_shared_key(unsigned char *h80211, int caplen)
{
    int m_bmac, m_smac, m_dmac, n, textlen;
    char ofn[1024];
    char text[4096];
    char prga[4096];
    unsigned int long crc;

    if((unsigned)caplen > sizeof(G.sharedkey[0])) return 1;

    m_bmac = 16;
    m_smac = 10;
    m_dmac = 4;

    if( time(NULL) - G.sk_start > 5)
    {
        /* timeout(5sec) - remove all packets, restart timer */
        memset(G.sharedkey, '\x00', 4096*3);
        G.sk_start = time(NULL);
    }

    /* is auth packet */
    if( (h80211[1] & 0x40) != 0x40 )
    {
        /* not encrypted */
        if( ( h80211[24] + (h80211[25] << 8) ) == 1 )
        {
            /* Shared-Key Authentication */
            if( ( h80211[26] + (h80211[27] << 8) ) == 2 )
            {
                /* sequence == 2 */
                memcpy(G.sharedkey[0], h80211, caplen);
                G.sk_len = caplen-24;
            }
            if( ( h80211[26] + (h80211[27] << 8) ) == 4 )
            {
                /* sequence == 4 */
                memcpy(G.sharedkey[2], h80211, caplen);
            }
        }
        else return 1;
    }
    else
    {
        /* encrypted */
        memcpy(G.sharedkey[1], h80211, caplen);
        G.sk_len2 = caplen-24-4;
    }

    /* check if the 3 packets form a proper authentication */

    if( ( memcmp(G.sharedkey[0]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[1]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[2]+m_bmac, NULL_MAC, 6) == 0 ) ) /* some bssids == zero */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[1]+m_bmac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[2]+m_bmac, 6) != 0 ) ) /* all bssids aren't equal */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[2]+m_smac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[1]+m_dmac, 6) != 0 ) ) /* SA in 2&4 != DA in 3 */
    {
        return 1;
    }

    if( (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[2]+m_dmac, 6) != 0 ) ||
        (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[1]+m_smac, 6) != 0 ) ) /* DA in 2&4 != SA in 3 */
    {
        return 1;
    }

    textlen = G.sk_len;

    if(textlen+4 != G.sk_len2)
    {
        snprintf(G.message, sizeof(G.message), "][ Broken SKA: %02X:%02X:%02X:%02X:%02X:%02X ",
                    *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
                *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));
        return 1;
    }

    if((unsigned)textlen > sizeof(text) - 4) return 1;

    memcpy(text, G.sharedkey[0]+24, textlen);

    /* increment sequence number from 2 to 3 */
    text[2] = text[2]+1;

    crc = 0xFFFFFFFF;

    for( n = 0; n < textlen; n++ )
        crc = crc_tbl[(crc ^ text[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    /* append crc32 over body */
    text[textlen]     = (crc      ) & 0xFF;
    text[textlen+1]   = (crc >>  8) & 0xFF;
    text[textlen+2]   = (crc >> 16) & 0xFF;
    text[textlen+3]   = (crc >> 24) & 0xFF;

    /* cleartext XOR cipher */
    for(n=0; n<(textlen+4); n++)
    {
        prga[4+n] = (text[n] ^ G.sharedkey[1][28+n]) & 0xFF;
    }

    /* write IV+index */
    prga[0] = G.sharedkey[1][24] & 0xFF;
    prga[1] = G.sharedkey[1][25] & 0xFF;
    prga[2] = G.sharedkey[1][26] & 0xFF;
    prga[3] = G.sharedkey[1][27] & 0xFF;

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf( ofn, sizeof( ofn ) - 1, "%s-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s", G.prefix, G.f_index,
              *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5), "xor" );

    G.f_xor = fopen( ofn, "w");
    if(G.f_xor == NULL)
        return 1;

    for(n=0; n<textlen+8; n++)
        fputc((prga[n] & 0xFF), G.f_xor);

    fflush(G.f_xor);

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf(G.message, sizeof(G.message), "][ %d bytes keystream: %02X:%02X:%02X:%02X:%02X:%02X ",
                textlen+4, *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));

    memset(G.sharedkey, '\x00', 512*3);
    /* ok, keystream saved */
    return 0;
}

int is_filtered_netmask(unsigned char *bssid)
{
    unsigned char mac1[6];
    unsigned char mac2[6];
    int i;

    for(i=0; i<6; i++)
    {
        mac1[i] = bssid[i]     & G.f_netmask[i];
        mac2[i] = G.f_bssid[i] & G.f_netmask[i];
    }

    if( memcmp(mac1, mac2, 6) != 0 )
    {
        return( 1 );
    }

    return 0;
}

int is_filtered_essid(unsigned char *essid)
{
    int ret = 0;
    int i;

    if(G.f_essid)
    {
        for(i=0; i<G.f_essid_count; i++)
        {
            if(strncmp((char*)essid, G.f_essid[i], MAX_IE_ELEMENT_SIZE) == 0)
            {
                return 0;
            }
        }

        ret = 1;
    }

#ifdef HAVE_PCRE
    if(G.f_essid_regex)
    {
        return pcre_exec(G.f_essid_regex, NULL, (char*)essid, strnlen((char *)essid, MAX_IE_ELEMENT_SIZE), 0, 0, NULL, 0) < 0;
    }
#endif

    return ret;
}

int update_dataps()
{
    struct timeval tv;
    struct AP_info *ap_cur;
    struct NA_info *na_cur;
    int sec, usec, diff, ps;
    float pause;

    gettimeofday(&tv, NULL);

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        sec = (tv.tv_sec - ap_cur->tv.tv_sec);
        usec = (tv.tv_usec - ap_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = ap_cur->nb_data - ap_cur->nb_data_old;
            ps = (int)(((float)diff)/pause);
            ap_cur->nb_dataps = ps;
            ap_cur->nb_data_old = ap_cur->nb_data;
            gettimeofday(&(ap_cur->tv), NULL);
        }
        ap_cur = ap_cur->prev;
    }

    na_cur = G.na_1st;

    while( na_cur != NULL )
    {
        sec = (tv.tv_sec - na_cur->tv.tv_sec);
        usec = (tv.tv_usec - na_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = na_cur->ack - na_cur->ack_old;
            ps = (int)(((float)diff)/pause);
            na_cur->ackps = ps;
            na_cur->ack_old = na_cur->ack;
            gettimeofday(&(na_cur->tv), NULL);
        }
        na_cur = na_cur->next;
    }
    return(0);
}

int list_tail_free(struct pkt_buf **list)
{
    struct pkt_buf **pkts;
    struct pkt_buf *next;

    if(list == NULL) return 1;

    pkts = list;

    while(*pkts != NULL)
    {
        next = (*pkts)->next;
        if( (*pkts)->packet )
        {
            free( (*pkts)->packet);
            (*pkts)->packet=NULL;
        }

        if(*pkts)
        {
            free(*pkts);
            *pkts = NULL;
        }
        *pkts = next;
    }

    *list=NULL;

    return 0;
}

int list_add_packet(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;

    if(length <= 0) return 1;
    if(packet == NULL) return 1;
    if(list == NULL) return 1;

    *list = (struct pkt_buf*) malloc(sizeof(struct pkt_buf));
    if( *list == NULL ) return 1;
    (*list)->packet = (unsigned char*) malloc(length);
    if( (*list)->packet == NULL ) return 1;

    memcpy((*list)->packet,  packet, length);
    (*list)->next = next;
    (*list)->length = length;
    gettimeofday( &((*list)->ctime), NULL);

    return 0;
}

/*
 * Check if the same IV was used if the first two bytes were the same.
 * If they are not identical, it would complain.
 * The reason is that the first two bytes unencrypted are 'aa'
 * so with the same IV it should always be encrypted to the same thing.
 */
int list_check_decloak(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;
    struct timeval tv1;
    int timediff;
    int i, correct;

    if( packet == NULL) return 1;
    if( list == NULL ) return 1;
    if( *list == NULL ) return 1;
    if( length <= 0) return 1;

    gettimeofday(&tv1, NULL);

    timediff = (((tv1.tv_sec - ((*list)->ctime.tv_sec)) * 1000000) + (tv1.tv_usec - ((*list)->ctime.tv_usec))) / 1000;
    if( timediff > BUFFER_TIME )
    {
        list_tail_free(list);
        next=NULL;
    }

    while(next != NULL)
    {
        if(next->next != NULL)
        {
            timediff = (((tv1.tv_sec - (next->next->ctime.tv_sec)) * 1000000) + (tv1.tv_usec - (next->next->ctime.tv_usec))) / 1000;
            if( timediff > BUFFER_TIME )
            {
                list_tail_free(&(next->next));
                break;
            }
        }
        if( (next->length + 4) == length)
        {
            correct = 1;
            // check for 4 bytes added after the end
            for(i=28;i<length-28;i++)   //check everything (in the old packet) after the IV (including crc32 at the end)
            {
                if(next->packet[i] != packet[i])
                {
                    correct = 0;
                    break;
                }
            }
            if(!correct)
            {
                correct = 1;
                // check for 4 bytes added at the beginning
                for(i=28;i<length-28;i++)   //check everything (in the old packet) after the IV (including crc32 at the end)
                {
                    if(next->packet[i] != packet[4+i])
                    {
                        correct = 0;
                        break;
                    }
                }
            }
            if(correct == 1)
                    return 0;   //found decloaking!
        }
        next = next->next;
    }

    return 1; //didn't find decloak
}

int remove_namac(unsigned char* mac)
{
    struct NA_info *na_cur = NULL;
    struct NA_info *na_prv = NULL;

    if(mac == NULL)
        return( -1 );

    na_cur = G.na_1st;
    na_prv = NULL;

    while( na_cur != NULL )
    {
        if( ! memcmp( na_cur->namac, mac, 6 ) )
            break;

        na_prv = na_cur;
        na_cur = na_cur->next;
    }

    /* if it's known, remove it */
    if( na_cur != NULL )
    {
        /* first in linked list */
        if(na_cur == G.na_1st)
        {
            G.na_1st = na_cur->next;
        }
        else
        {
            na_prv->next = na_cur->next;
        }
        free(na_cur);
        na_cur=NULL;
    }

    return( 0 );
}

int dump_add_packet( unsigned char *h80211, int caplen, struct rx_info *ri, int cardnum )
{
    int i, n, seq, msd, dlen, offset, clen, o;
    unsigned z;
    int type, length, numuni=0, numauth=0;
    struct pcap_pkthdr pkh;
    struct timeval tv;
    struct ivs2_pkthdr ivs2;
    unsigned char *p, *org_p, c;
    unsigned char bssid[6];
    unsigned char stmac[6];
    unsigned char namac[6];
    unsigned char clear[2048];
    int weight[16];
    int num_xor=0;

    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct NA_info *na_cur = NULL;
    struct AP_info *ap_prv = NULL;
    struct ST_info *st_prv = NULL;
    struct NA_info *na_prv = NULL;

    /* skip all non probe response frames in active scanning simulation mode */
    if( G.active_scan_sim > 0 && h80211[0] != 0x50 )
        return(0);

    /* skip packets smaller than a 802.11 header */

    if( caplen < 24 )
        goto write_packet;

    /* skip (uninteresting) control frames */

    if( ( h80211[0] & 0x0C ) == 0x04 )
        goto write_packet;

    /* if it's a LLC null packet, just forget it (may change in the future) */

    if ( caplen > 28)
        if ( memcmp(h80211 + 24, llcnull, 4) == 0)
            return ( 0 );

    /* grab the sequence number */
    seq = ((h80211[22]>>4)+(h80211[23]<<4));

    /* locate the access point's MAC address */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( bssid, h80211 + 16, 6 ); break;  //Adhoc
        case  1: memcpy( bssid, h80211 +  4, 6 ); break;  //ToDS
        case  2: memcpy( bssid, h80211 + 10, 6 ); break;  //FromDS
        case  3: memcpy( bssid, h80211 + 10, 6 ); break;  //WDS -> Transmitter taken as BSSID
    }
    
    if ((h80211[1] &3) == 1){
	
        unsigned char dst_mac[6];
        memcpy( dst_mac, h80211 +  16, 6 );  //DS
	printf("The dst mac address is %02X:%02X:%02X:%02X:%02X:%02X ", dst_mac[0], dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
	printf("The bssid is %02X:%02X:%02X:%02X:%02X:%02X ", bssid[0], bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
	printf("The caplen: %d\n", caplen - 50 - 20 - 8);
	return(0);
    }

    if( memcmp(G.f_bssid, NULL_MAC, 6) != 0 )
    {
        if( memcmp(G.f_netmask, NULL_MAC, 6) != 0 )
        {
            if(is_filtered_netmask(bssid)) return(1);
        }
        else
        {
            if( memcmp(G.f_bssid, bssid, 6) != 0 ) return(1);
        }
    }

    /* update our chained list of access points */

    ap_cur = G.ap_1st;
    ap_prv = NULL;

    while( ap_cur != NULL )
    {
        if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
            break;

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    /* if it's a new access point, add it */

    if( ap_cur == NULL )
    {
        if( ! ( ap_cur = (struct AP_info *) malloc(
                         sizeof( struct AP_info ) ) ) )
        {
            perror( "malloc failed" );
            return( 1 );
        }

        /* if mac is listed as unknown, remove it */
        remove_namac(bssid);

        memset( ap_cur, 0, sizeof( struct AP_info ) );

        if( G.ap_1st == NULL )
            G.ap_1st = ap_cur;
        else
            ap_prv->next  = ap_cur;

        memcpy( ap_cur->bssid, bssid, 6 );

        ap_cur->prev = ap_prv;

        ap_cur->tinit = time( NULL );
        ap_cur->tlast = time( NULL );

        ap_cur->avg_power   = -1;
        ap_cur->best_power  = -1;
        ap_cur->power_index = -1;

        for( i = 0; i < NB_PWR; i++ )
            ap_cur->power_lvl[i] = -1;

        ap_cur->channel    = -1;
        ap_cur->max_speed  = -1;
        ap_cur->security   = 0;

        ap_cur->uiv_root = uniqueiv_init();

        ap_cur->nb_dataps = 0;
        ap_cur->nb_data_old = 0;
        gettimeofday(&(ap_cur->tv), NULL);

        ap_cur->dict_started = 0;

        ap_cur->key = NULL;

        G.ap_end = ap_cur;

        ap_cur->nb_bcn     = 0;

        ap_cur->rx_quality = 0;
        ap_cur->fcapt      = 0;
        ap_cur->fmiss      = 0;
        ap_cur->last_seq   = 0;
        gettimeofday( &(ap_cur->ftimef), NULL);
        gettimeofday( &(ap_cur->ftimel), NULL);
        gettimeofday( &(ap_cur->ftimer), NULL);

        ap_cur->ssid_length = 0;
        ap_cur->essid_stored = 0;
        ap_cur->timestamp = 0;

        ap_cur->decloak_detect=G.decloak;
        ap_cur->is_decloak = 0;
        ap_cur->packets = NULL;

	ap_cur->marked = 0;
	ap_cur->marked_color = 1;

        ap_cur->data_root = NULL;
        ap_cur->EAP_detected = 0;
        memcpy(ap_cur->gps_loc_min, G.gps_loc, sizeof(float)*5);
        memcpy(ap_cur->gps_loc_max, G.gps_loc, sizeof(float)*5);
        memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float)*5);
    }

    /* update the last time seen */

    ap_cur->tlast = time( NULL );

    /* only update power if packets comes from
     * the AP: either type == mgmt and SA != BSSID,
     * or FromDS == 1 and ToDS == 0 */

    if( ( ( h80211[1] & 3 ) == 0 &&
            memcmp( h80211 + 10, bssid, 6 ) == 0 ) ||
        ( ( h80211[1] & 3 ) == 2 ) )
    {
        ap_cur->power_index = ( ap_cur->power_index + 1 ) % NB_PWR;
        ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

        ap_cur->avg_power = 0;

        for( i = 0, n = 0; i < NB_PWR; i++ )
        {
            if( ap_cur->power_lvl[i] != -1 )
            {
                ap_cur->avg_power += ap_cur->power_lvl[i];
                n++;
            }
        }

        if( n > 0 )
        {
            ap_cur->avg_power /= n;
            if( ap_cur->avg_power > ap_cur->best_power )
            {
                ap_cur->best_power = ap_cur->avg_power;
                memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float)*5);
            }
        }
        else
            ap_cur->avg_power = -1;

        /* every packet in here comes from the AP */

        if(G.gps_loc[0] > ap_cur->gps_loc_max[0])
            ap_cur->gps_loc_max[0] = G.gps_loc[0];
        if(G.gps_loc[1] > ap_cur->gps_loc_max[1])
            ap_cur->gps_loc_max[1] = G.gps_loc[1];
        if(G.gps_loc[2] > ap_cur->gps_loc_max[2])
            ap_cur->gps_loc_max[2] = G.gps_loc[2];

        if(G.gps_loc[0] < ap_cur->gps_loc_min[0])
            ap_cur->gps_loc_min[0] = G.gps_loc[0];
        if(G.gps_loc[1] < ap_cur->gps_loc_min[1])
            ap_cur->gps_loc_min[1] = G.gps_loc[1];
        if(G.gps_loc[2] < ap_cur->gps_loc_min[2])
            ap_cur->gps_loc_min[2] = G.gps_loc[2];
//        printf("seqnum: %i\n", seq);

        if(ap_cur->fcapt == 0 && ap_cur->fmiss == 0) gettimeofday( &(ap_cur->ftimef), NULL);
        if(ap_cur->last_seq != 0) ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
        ap_cur->last_seq = seq;
        ap_cur->fcapt++;
        gettimeofday( &(ap_cur->ftimel), NULL);

//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
    }

    if( h80211[0] == 0x80 )
    {
        ap_cur->nb_bcn++;
    }

    ap_cur->nb_pkt++;

    /* find wpa handshake */
    if( h80211[0] == 0x10 )
    {
        /* reset the WPA handshake state */

        if( st_cur != NULL && st_cur->wpa.state != 0xFF )
            st_cur->wpa.state = 0;
//        printf("initial auth %d\n", ap_cur->wpa_state);
    }

    /* locate the station MAC in the 802.11 header */

    switch( h80211[1] & 3 )
    {
        case  0:

            /* if management, check that SA != BSSID */

            if( memcmp( h80211 + 10, bssid, 6 ) == 0 )
                goto skip_station;

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  1:

            /* ToDS packet, must come from a client */

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  2:

            /* FromDS packet, reject broadcast MACs */

            if( (h80211[4]%2) != 0 ) goto skip_station;
            memcpy( stmac, h80211 +  4, 6 ); break;

        default: goto skip_station;
    }
    
skip_station:

    /* packet parsing: Probe Request */

    if( h80211[0] == 0x40 && st_cur != NULL )
    {
        p = h80211 + 24;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
//                n = ( p[1] > 32 ) ? 32 : p[1];
                n = p[1];

                for( i = 0; i < n; i++ )
                    if( p[2 + i] > 0 && p[2 + i] < ' ' )
                        goto skip_probe;

                /* got a valid ASCII probed ESSID, check if it's
                   already in the ring buffer */

                for( i = 0; i < NB_PRB; i++ )
                    if( memcmp( st_cur->probes[i], p + 2, n ) == 0 )
                        goto skip_probe;

                st_cur->probe_index = ( st_cur->probe_index + 1 ) % NB_PRB;
                memset( st_cur->probes[st_cur->probe_index], 0, 256 );
                memcpy( st_cur->probes[st_cur->probe_index], p + 2, n ); //twice?!
                st_cur->ssid_length[st_cur->probe_index] = n;

                for( i = 0; i < n; i++ )
                {
                    c = p[2 + i];
                    if( c == 0 || ( c > 126 && c < 160 ) ) c = '.';  //could also check ||(c>0 && c<32)
                    st_cur->probes[st_cur->probe_index][i] = c;
                }
            }

            p += 2 + p[1];
        }
    }

skip_probe:

    /* packet parsing: Beacon or Probe Response */

    if( h80211[0] == 0x80 || h80211[0] == 0x50 )
    {
        if( !(ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) )
        {
            if( ( h80211[34] & 0x10 ) >> 4 ) ap_cur->security |= STD_WEP|ENC_WEP;
            else ap_cur->security |= STD_OPN;
        }

        ap_cur->preamble = ( h80211[34] & 0x20 ) >> 5;

        unsigned long long *tstamp = (unsigned long long *) (h80211 + 24);
        ap_cur->timestamp = letoh64(*tstamp);

        p = h80211 + 36;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            //only update the essid length if the new length is > the old one
            if( p[0] == 0x00 && (ap_cur->ssid_length < p[1]) ) ap_cur->ssid_length = p[1];

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

//                n = ( p[1] > 32 ) ? 32 : p[1];
                n = p[1];

                memset( ap_cur->essid, 0, 256 );
                memcpy( ap_cur->essid, p + 2, n );

                for( i = 0; i < n; i++ )
                    if( ( ap_cur->essid[i] >   0 && ap_cur->essid[i] <  32 ) ||
                        ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            /* get the maximum speed in Mb and the AP's channel */

            if( p[0] == 0x01 || p[0] == 0x32 )
            {
                if(ap_cur->max_speed < ( p[1 + p[1]] & 0x7F ) / 2)
                    ap_cur->max_speed = ( p[1 + p[1]] & 0x7F ) / 2;
            }

            if( p[0] == 0x03 )
                ap_cur->channel = p[2];

            p += 2 + p[1];
        }
    }

    /* packet parsing: Beacon & Probe response */

    if( (h80211[0] == 0x80 || h80211[0] == 0x50) && caplen > 38)
    {
        p=h80211+36;         //ignore hdr + fixed params

        while( p < h80211 + caplen )
        {
            type = p[0];
            length = p[1];
            if(p+2+length > h80211 + caplen) {
/*                printf("error parsing tags! %p vs. %p (tag: %i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen), type, length, (p-h80211));
                exit(1);*/
                break;
            }

            if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x01\x01\x00", 6) == 0)) || (type == 0x30) )
            {
                ap_cur->security &= ~(STD_WEP|ENC_WEP|STD_WPA);

                org_p = p;
                offset = 0;

                if(type == 0xDD)
                {
                    //WPA defined in vendor specific tag -> WPA1 support
                    ap_cur->security |= STD_WPA;
                    offset = 4;
                }

                if(type == 0x30)
                {
                    ap_cur->security |= STD_WPA2;
                    offset = 0;
                }

                if(length < (18+offset))
                {
                    p += length+2;
                    continue;
                }

                if( p+9+offset > h80211+caplen )
                    break;
                numuni  = p[8+offset] + (p[9+offset]<<8);

                if( p+ (11+offset) + 4*numuni > h80211+caplen)
                    break;
                numauth = p[(10+offset) + 4*numuni] + (p[(11+offset) + 4*numuni]<<8);

                p += (10+offset);

                if(type != 0x30)
                {
                    if( p + (4*numuni) + (2+4*numauth) > h80211+caplen)
                        break;
                }
                else
                {
                    if( p + (4*numuni) + (2+4*numauth) + 2 > h80211+caplen)
                        break;
                }

                for(i=0; i<numuni; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        ap_cur->security |= ENC_WEP;
                        break;
                    case 0x02:
                        ap_cur->security |= ENC_TKIP;
                        break;
                    case 0x03:
                        ap_cur->security |= ENC_WRAP;
                        break;
                    case 0x04:
                        ap_cur->security |= ENC_CCMP;
                        break;
                    case 0x05:
                        ap_cur->security |= ENC_WEP104;
                        break;
                    default:
                        break;
                    }
                }

                p += 2+4*numuni;

                for(i=0; i<numauth; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        ap_cur->security |= AUTH_MGT;
                        break;
                    case 0x02:
                        ap_cur->security |= AUTH_PSK;
                        break;
                    default:
                        break;
                    }
                }

                p += 2+4*numauth;

                if( type == 0x30 ) p += 2;

                p = org_p + length+2;
            }
            else if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
            {
                ap_cur->security |= STD_QOS;
                p += length+2;
            }
            else p += length+2;
        }
    }

    /* packet parsing: Authentication Response */

    if( h80211[0] == 0xB0 && caplen >= 30)
    {
        if( ap_cur->security & STD_WEP )
        {
            //successful step 2 or 4 (coming from the AP)
            if(memcmp(h80211+28, "\x00\x00", 2) == 0 &&
                (h80211[26] == 0x02 || h80211[26] == 0x04))
            {
                ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
                if(h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
                if(h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
            }
        }
    }

    /* packet parsing: Association Request */

    if( h80211[0] == 0x00 && caplen > 28 )
    {
        p = h80211 + 28;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

                n = ( p[1] > 32 ) ? 32 : p[1];

                memset( ap_cur->essid, 0, 33 );
                memcpy( ap_cur->essid, p + 2, n );

               for( i = 0; i < n; i++ )
                    if( ap_cur->essid[i] < 32 ||
                      ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            p += 2 + p[1];
        }
        if(st_cur != NULL)
            st_cur->wpa.state = 0;
    }

    /* packet parsing: some data */

    if( ( h80211[0] & 0x0C ) == 0x08 )
    {
        /* update the channel if we didn't get any beacon */

        if( ap_cur->channel == -1 )
        {
            if(ri->ri_channel > 0 && ri->ri_channel < 167)
                ap_cur->channel = ri->ri_channel;
            else
                ap_cur->channel = G.channel[cardnum];
        }

        /* check the SNAP header to see if data is encrypted */

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if( (h80211[0] & 0x80) == 0x80)
        {
            z+=2;
            if(st_cur != NULL)
            {
                if( (h80211[1] & 3) == 1 ) //ToDS
                    st_cur->qos_to_ds = 1;
                else
                    st_cur->qos_fr_ds = 1;
            }
        }
        else
        {
            if(st_cur != NULL)
            {
                if( (h80211[1] & 3) == 1 ) //ToDS
                    st_cur->qos_to_ds = 0;
                else
                    st_cur->qos_fr_ds = 0;
            }
        }

        if(z==24)
        {
            if(list_check_decloak(&(ap_cur->packets), caplen, h80211) != 0)
            {
                list_add_packet(&(ap_cur->packets), caplen, h80211);
            }
            else
            {
                ap_cur->is_decloak = 1;
                ap_cur->decloak_detect = 0;
                list_tail_free(&(ap_cur->packets));
                memset(G.message, '\x00', sizeof(G.message));
                    snprintf( G.message, sizeof( G.message ) - 1,
                        "][ Decloak: %02X:%02X:%02X:%02X:%02X:%02X ",
                        ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2],
                        ap_cur->bssid[3], ap_cur->bssid[4], ap_cur->bssid[5]);
            }
        }

        if( z + 26 > (unsigned)caplen )
            goto write_packet;

        if( h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03 )
        {
//            if( ap_cur->encryption < 0 )
//                ap_cur->encryption = 0;

            /* if ethertype == IPv4, find the LAN address */

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00 &&
                ( h80211[1] & 3 ) == 0x01 )
                    memcpy( ap_cur->lanip, &h80211[z + 20], 4 );

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06 )
                memcpy( ap_cur->lanip, &h80211[z + 22], 4 );
        }
//        else
//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5 );


        if(ap_cur->security == 0 || (ap_cur->security & STD_WEP) )
        {
            if( (h80211[1] & 0x40) != 0x40 )
            {
                ap_cur->security |= STD_OPN;
            }
            else
            {
                if((h80211[z+3] & 0x20) == 0x20)
                {
                    ap_cur->security |= STD_WPA;
                }
                else
                {
                    ap_cur->security |= STD_WEP;
                    if( (h80211[z+3] & 0xC0) != 0x00)
                    {
                        ap_cur->security |= ENC_WEP40;
                    }
                    else
                    {
                        ap_cur->security &= ~ENC_WEP40;
                        ap_cur->security |= ENC_WEP;
                    }
                }
            }
        }

        if( z + 10 > (unsigned)caplen )
            goto write_packet;

        if( ap_cur->security & STD_WEP )
        {
            /* WEP: check if we've already seen this IV */

            if( ! uniqueiv_check( ap_cur->uiv_root, &h80211[z] ) )
            {
                /* first time seen IVs */

                uniqueiv_mark( ap_cur->uiv_root, &h80211[z] );

                ap_cur->nb_data++;
            }

            // Record all data linked to IV to detect WEP Cloaking
            if( G.f_ivs == NULL && G.detect_anomaly)
            {
				// Only allocate this when seeing WEP AP
				if (ap_cur->data_root == NULL)
					ap_cur->data_root = data_init();

				// Only works with full capture, not IV-only captures
				if (data_check(ap_cur->data_root, &h80211[z], &h80211[z + 4])
					== CLOAKING && ap_cur->EAP_detected == 0)
				{

					//If no EAP/EAP was detected, indicate WEP cloaking
                    memset(G.message, '\x00', sizeof(G.message));
                    snprintf( G.message, sizeof( G.message ) - 1,
                        "][ WEP Cloaking: %02X:%02X:%02X:%02X:%02X:%02X ",
                        ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2],
                        ap_cur->bssid[3], ap_cur->bssid[4], ap_cur->bssid[5]);

				}
			}

        }
        else
        {
            ap_cur->nb_data++;
        }

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if( (h80211[0] & 0x80) == 0x80) z+=2;

        if( z + 26 > (unsigned)caplen )
            goto write_packet;

        z += 6;     //skip LLC header

        /* check ethertype == EAPOL */
        if( h80211[z] == 0x88 && h80211[z + 1] == 0x8E && (h80211[1] & 0x40) != 0x40 )
        {
			ap_cur->EAP_detected = 1;

            z += 2;     //skip ethertype

            if( st_cur == NULL )
                goto write_packet;

            /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                  ( h80211[z + 6] & 0x40 ) == 0 &&
                  ( h80211[z + 6] & 0x80 ) != 0 &&
                  ( h80211[z + 5] & 0x01 ) == 0 )
            {
                memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                st_cur->wpa.state = 1;
            }


            /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

            if( z+17+32 > (unsigned)caplen )
                goto write_packet;

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                  ( h80211[z + 6] & 0x40 ) == 0 &&
                  ( h80211[z + 6] & 0x80 ) == 0 &&
                  ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state |= 2;

                }

                if( (st_cur->wpa.state & 4) != 4 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                            +   h80211[z + 3] + 4;

                    if (caplen - z < st_cur->wpa.eapol_size || st_cur->wpa.eapol_size == 0 ||
                        caplen - z < 81 + 16 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;
                }
            }

            /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                  ( h80211[z + 6] & 0x40 ) != 0 &&
                  ( h80211[z + 6] & 0x80 ) != 0 &&
                  ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state |= 1;
                }

                if( (st_cur->wpa.state & 4) != 4 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                            +   h80211[z + 3] + 4;

                    if (caplen - (unsigned)z < st_cur->wpa.eapol_size || st_cur->wpa.eapol_size == 0 ||
                        caplen - (unsigned)z < 81 + 16 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;
                }
            }

            if( st_cur->wpa.state == 7)
            {
                memcpy( st_cur->wpa.stmac, st_cur->stmac, 6 );
                memcpy( G.wpa_bssid, ap_cur->bssid, 6 );
                memset(G.message, '\x00', sizeof(G.message));
                snprintf( G.message, sizeof( G.message ) - 1,
                    "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
                    G.wpa_bssid[0], G.wpa_bssid[1], G.wpa_bssid[2],
                    G.wpa_bssid[3], G.wpa_bssid[4], G.wpa_bssid[5]);


            }
        }
    }


write_packet:

    if(ap_cur != NULL)
    {
        if( h80211[0] == 0x80 && G.one_beacon){
            if( !ap_cur->beacon_logged )
                ap_cur->beacon_logged = 1;
            else return ( 0 );
        }
    }

    if(G.record_data)
    {
        if( ( (h80211[0] & 0x0C) == 0x00 ) && ( (h80211[0] & 0xF0) == 0xB0 ) )
        {
            /* authentication packet */
            check_shared_key(h80211, caplen);
        }
    }

    if(ap_cur != NULL)
    {
        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            return(1);
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            return(1);
        }

    }

    /* this changes the local ap_cur, st_cur and na_cur variables and should be the last check befor the actual write */
    if(caplen < 24 && caplen >= 10 && h80211[0])
    {
        /* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
        //(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 || h80211[0] == 0xE4 || h80211[0] == 0xF4)

        /* use general control frame detection, as the structure is always the same: mac(s) starting at [4] */
        if(h80211[0] & 0x04)
        {
            p=h80211+4;
            while(p <= h80211+16 && p<=h80211+caplen)
            {
                memcpy(namac, p, 6);

                if(memcmp(namac, NULL_MAC, 6) == 0)
                {
                    p+=6;
                    continue;
                }

                if(memcmp(namac, BROADCAST, 6) == 0)
                {
                    p+=6;
                    continue;
                }

                if(G.hide_known)
                {
                    /* check AP list */
                    ap_cur = G.ap_1st;
                    ap_prv = NULL;

                    while( ap_cur != NULL )
                    {
                        if( ! memcmp( ap_cur->bssid, namac, 6 ) )
                            break;

                        ap_prv = ap_cur;
                        ap_cur = ap_cur->next;
                    }

                    /* if it's an AP, try next mac */

                    if( ap_cur != NULL )
                    {
                        p+=6;
                        continue;
                    }

                    /* check ST list */
                    st_cur = G.st_1st;
                    st_prv = NULL;

                    while( st_cur != NULL )
                    {
                        if( ! memcmp( st_cur->stmac, namac, 6 ) )
                            break;

                        st_prv = st_cur;
                        st_cur = st_cur->next;
                    }

                    /* if it's a client, try next mac */

                    if( st_cur != NULL )
                    {
                        p+=6;
                        continue;
                    }
                }

                /* not found in either AP list or ST list, look through NA list */
                na_cur = G.na_1st;
                na_prv = NULL;

                while( na_cur != NULL )
                {
                    if( ! memcmp( na_cur->namac, namac, 6 ) )
                        break;

                    na_prv = na_cur;
                    na_cur = na_cur->next;
                }

                /* update our chained list of unknown stations */
                /* if it's a new mac, add it */

                if( na_cur == NULL )
                {
                    if( ! ( na_cur = (struct NA_info *) malloc(
                                    sizeof( struct NA_info ) ) ) )
                    {
                        perror( "malloc failed" );
                        return( 1 );
                    }

                    memset( na_cur, 0, sizeof( struct NA_info ) );

                    if( G.na_1st == NULL )
                        G.na_1st = na_cur;
                    else
                        na_prv->next  = na_cur;

                    memcpy( na_cur->namac, namac, 6 );

                    na_cur->prev = na_prv;

                    gettimeofday(&(na_cur->tv), NULL);
                    na_cur->tinit = time( NULL );
                    na_cur->tlast = time( NULL );

                    na_cur->power   = -1;
                    na_cur->channel = -1;
                    na_cur->ack     = 0;
                    na_cur->ack_old = 0;
                    na_cur->ackps   = 0;
                    na_cur->cts     = 0;
                    na_cur->rts_r   = 0;
                    na_cur->rts_t   = 0;
                }

                /* update the last time seen & power*/

                na_cur->tlast = time( NULL );
                na_cur->power = ri->ri_power;
                na_cur->channel = ri->ri_channel;

                switch(h80211[0] & 0xF0)
                {
                    case 0xB0:
                        if(p == h80211+4)
                            na_cur->rts_r++;
                        if(p == h80211+10)
                            na_cur->rts_t++;
                        break;

                    case 0xC0:
                        na_cur->cts++;
                        break;

                    case 0xD0:
                        na_cur->ack++;
                        break;

                    default:
                        na_cur->other++;
                        break;
                }

                /*grab next mac (for rts frames)*/
                p+=6;
            }
        }
    }

    if( G.f_cap != NULL && caplen >= 10)
    {
        pkh.caplen = pkh.len = caplen;

        gettimeofday( &tv, NULL );

        pkh.tv_sec  =   tv.tv_sec;
        pkh.tv_usec = ( tv.tv_usec & ~0x1ff ) + ri->ri_power + 64;

        n = sizeof( pkh );

        if( fwrite( &pkh, 1, n, G.f_cap ) != (size_t) n )
        {
            perror( "fwrite(packet header) failed" );
            return( 1 );
        }

        fflush( stdout );

        n = pkh.caplen;

        if( fwrite( h80211, 1, n, G.f_cap ) != (size_t) n )
        {
            perror( "fwrite(packet data) failed" );
            return( 1 );
        }

        fflush( stdout );
    }

    return( 0 );
}


char * getStringTimeFromSec(double seconds)
{
    int hour[3];
    char * ret;
    char * HourTime;
    char * MinTime;

    if (seconds <0)
        return NULL;

    ret = (char *) calloc(1,256);

    HourTime = (char *) calloc (1,128);
    MinTime  = (char *) calloc (1,128);

    hour[0]  = (int) (seconds);
    hour[1]  = hour[0] / 60;
    hour[2]  = hour[1] / 60;
    hour[0] %= 60 ;
    hour[1] %= 60 ;

    if (hour[2] != 0 )
        snprintf(HourTime, 128, "%d %s", hour[2], ( hour[2] == 1 ) ? "hour" : "hours");
    if (hour[1] != 0 )
        snprintf(MinTime, 128, "%d %s", hour[1], ( hour[1] == 1 ) ? "min" : "mins");

    if ( hour[2] != 0 && hour[1] != 0 )
        snprintf(ret, 256, "%s %s", HourTime, MinTime);
    else
    {
        if (hour[2] == 0 && hour[1] == 0)
            snprintf(ret, 256, "%d s", hour[0] );
        else
            snprintf(ret, 256, "%s", (hour[2] == 0) ? MinTime : HourTime );
    }

    free(MinTime);
    free(HourTime);

    return ret;

}

int get_ap_list_count() {
    time_t tt;
    struct tm *lt;
    struct AP_info *ap_cur;

    int num_ap;

    tt = time( NULL );
    lt = localtime( &tt );

    ap_cur = G.ap_end;

    num_ap = 0;

    while( ap_cur != NULL )
    {
        /* skip APs with only one packet, or those older than 2 min.
         * always skip if bssid == broadcast */

        if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
            memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

	num_ap++;
	ap_cur = ap_cur->prev;
    }

    return num_ap;
}

int get_sta_list_count() {
    time_t tt;
    struct tm *lt;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    int num_sta;

    tt = time( NULL );
    lt = localtime( &tt );

    ap_cur = G.ap_end;

    num_sta = 0;

    while( ap_cur != NULL )
    {
        if( ap_cur->nb_pkt < 2 ||
            time( NULL ) - ap_cur->tlast > G.berlin )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        // Don't filter unassociated clients by ESSID
        if(memcmp(ap_cur->bssid, BROADCAST, 6) && is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        st_cur = G.st_end;

        while( st_cur != NULL )
        {
            if( st_cur->base != ap_cur ||
                time( NULL ) - st_cur->tlast > G.berlin )
            {
                st_cur = st_cur->prev;
                continue;
            }

            if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) && G.asso_client )
            {
                st_cur = st_cur->prev;
                continue;
            }

	    num_sta++;

            st_cur = st_cur->prev;
        }

        ap_cur = ap_cur->prev;
    }
    return num_sta;
}

#define TSTP_SEC 1000000ULL /* It's a 1 MHz clock, so a million ticks per second! */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)

static char *parse_timestamp(unsigned long long timestamp) {
	static char s[15];
	unsigned long long rem;
	unsigned int days, hours, mins, secs;

	days = timestamp / TSTP_DAY;
	rem = timestamp % TSTP_DAY;
	hours = rem / TSTP_HOUR;
	rem %= TSTP_HOUR;
	mins = rem / TSTP_MIN;
	rem %= TSTP_MIN;
	secs = rem / TSTP_SEC;

	snprintf(s, 14, "%3dd %02d:%02d:%02d", days, hours, mins, secs);

	return s;
}

char * sanitize_xml(unsigned char * text, int length)
{
	int i;
	size_t len;
	unsigned char * pos;
	char * newpos;
	char * newtext = NULL;
	if (text != NULL && length > 0) {
		len = 6 * length;
		newtext = (char *)calloc(1, (len + 1) * sizeof(char)); // Make sure we have enough space
		pos = text;
		for (i = 0; i < length; ++i, ++pos) {
			switch (*pos) {
				case '&':
					strncat(newtext, "&amp;", len);
					break;
				case '<':
					strncat(newtext, "&lt;", len);
					break;
				case '>':
					strncat(newtext, "&gt;", len);
					break;
				case '\'':
					strncat(newtext, "&apos;", len);
					break;
				case '"':
					strncat(newtext, "&quot;", len);
					break;
				default:
					if ( isprint((int)(*pos)) || (*pos)>127 ) {
						newtext[strlen(newtext)] = *pos;
					} else {
						newtext[strlen(newtext)] = '\\';
						newpos = newtext + strlen(newtext);
						snprintf(newpos, strlen(newpos) + 1, "%3u", *pos);
					}
					break;
			}
		}
		newtext = (char *) realloc(newtext, strlen(newtext) + 1);
	}

	return newtext;
}

#undef TIME_STR_LENGTH


void sighandler( int signum)
{
	ssize_t unused;
    int card=0;

    signal( signum, sighandler );

    if( signum == SIGUSR1 )
    {
		unused = read( G.cd_pipe[0], &card, sizeof(int) );
        if(G.freqoption)
            unused = read( G.ch_pipe[0], &(G.frequency[card]), sizeof( int ) );
        else
            unused = read( G.ch_pipe[0], &(G.channel[card]), sizeof( int ) );
    }

    if( signum == SIGUSR2 )
        unused = read( G.gc_pipe[0], &G.gps_loc, sizeof( float ) * 5 );

    if( signum == SIGINT || signum == SIGTERM )
    {
	reset_term();
        alarm( 1 );
        G.do_exit = 1;
        signal( SIGALRM, sighandler );
        dprintf( STDOUT_FILENO, "\n" );
    }

    if( signum == SIGSEGV )
    {
        fprintf( stderr, "Caught signal 11 (SIGSEGV). Please"
                         " contact the author!\33[?25h\n\n" );
        fflush( stdout );
        exit( 1 );
    }

    if( signum == SIGALRM )
    {
        dprintf( STDERR_FILENO, "Caught signal 14 (SIGALRM). Please"
                         " contact the author!\33[?25h\n\n" );
        _exit( 1 );
    }

    if( signum == SIGCHLD )
        wait( NULL );

    if( signum == SIGWINCH )
    {
        fprintf( stderr, "\33[2J" );
        fflush( stdout );
    }
}

int send_probe_request(struct wif *wi)
{
    int len;
    unsigned char p[4096], r_smac[6];

    memcpy(p, PROBE_REQ, 24);

    len = 24;

    p[24] = 0x00;      //ESSID Tag Number
    p[25] = 0x00;      //ESSID Tag Length

    len += 2;

    memcpy(p+len, RATES, 16);

    len += 16;

    r_smac[0] = 0x00;
    r_smac[1] = rand() & 0xFF;
    r_smac[2] = rand() & 0xFF;
    r_smac[3] = rand() & 0xFF;
    r_smac[4] = rand() & 0xFF;
    r_smac[5] = rand() & 0xFF;

    memcpy(p+10, r_smac, 6);

    if (wi_write(wi, p, len, NULL) == -1) {
        switch (errno) {
        case EAGAIN:
        case ENOBUFS:
            usleep(10000);
            return 0; /* XXX not sure I like this... -sorbo */
        }

        perror("wi_write()");
        return -1;
    }

    return 0;
}

int send_probe_requests(struct wif *wi[], int cards)
{
    int i=0;
    for(i=0; i<cards; i++)
    {
        send_probe_request(wi[i]);
    }
    return 0;
}

int getchancount(int valid)
{
    int i=0, chan_count=0;

    while(G.channels[i])
    {
        i++;
        if(G.channels[i] != -1)
            chan_count++;
    }

    if(valid) return chan_count;
    return i;
}

int getfreqcount(int valid)
{
    int i=0, freq_count=0;

    while(G.own_frequencies[i])
    {
        i++;
        if(G.own_frequencies[i] != -1)
            freq_count++;
    }

    if(valid) return freq_count;
    return i;
}

void channel_hopper(struct wif *wi[], int if_num, int chan_count )
{
	ssize_t unused;
    int ch, ch_idx = 0, card=0, chi=0, cai=0, j=0, k=0, first=1, again=1;
    int dropped=0;

    while( getppid() != 1 )
    {
        for( j = 0; j < if_num; j++ )
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if( G.chswitch == 2 && !first )
            {
                j = if_num - 1;
                card = if_num - 1;

                if( getchancount(1) > if_num )
                {
                    while( again )
                    {
                        again = 0;
                        for( k = 0; k < ( if_num - 1 ); k++ )
                        {
                            if( G.channels[ch_idx] == G.channel[k] )
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if( G.channels[ch_idx] == -1 )
            {
                j--;
                cai--;
                dropped++;
                if(dropped >= chan_count)
                {
                    ch = wi_get_channel(wi[card]);
                    G.channel[card] = ch;
                    unused = write( G.cd_pipe[1], &card, sizeof(int) );
                    unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                    kill( getppid(), SIGUSR1 );
                    usleep(1000);
                }
                continue;
            }

            dropped = 0;

            ch = G.channels[ch_idx];

            if(wi_set_channel(wi[card], ch ) == 0 )
            {
                G.channel[card] = ch;
                unused = write( G.cd_pipe[1], &card, sizeof(int) );
                unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                if(G.active_scan_sim > 0)
                    send_probe_request(wi[card]);
                kill( getppid(), SIGUSR1 );
                usleep(1000);
            }
            else
            {
                G.channels[ch_idx] = -1;      /* remove invalid channel */
                j--;
                cai--;
                continue;
            }
        }

        if(G.chswitch == 0)
        {
            chi=chi-(if_num - 1);
        }

        if(first)
        {
            first = 0;
        }

        usleep( (G.hopfreq*1000) );
    }

    exit( 0 );
}

void frequency_hopper(struct wif *wi[], int if_num, int chan_count )
{
	ssize_t unused;
    int ch, ch_idx = 0, card=0, chi=0, cai=0, j=0, k=0, first=1, again=1;
    int dropped=0;

    while( getppid() != 1 )
    {
        for( j = 0; j < if_num; j++ )
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if( G.chswitch == 2 && !first )
            {
                j = if_num - 1;
                card = if_num - 1;

                if( getfreqcount(1) > if_num )
                {
                    while( again )
                    {
                        again = 0;
                        for( k = 0; k < ( if_num - 1 ); k++ )
                        {
                            if( G.own_frequencies[ch_idx] == G.frequency[k] )
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if( G.own_frequencies[ch_idx] == -1 )
            {
                j--;
                cai--;
                dropped++;
                if(dropped >= chan_count)
                {
                    ch = wi_get_freq(wi[card]);
                    G.frequency[card] = ch;
                    unused = write( G.cd_pipe[1], &card, sizeof(int) );
                    unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                    kill( getppid(), SIGUSR1 );
                    usleep(1000);
                }
                continue;
            }

            dropped = 0;

            ch = G.own_frequencies[ch_idx];

            if(wi_set_freq(wi[card], ch ) == 0 )
            {
                G.frequency[card] = ch;
                unused = write( G.cd_pipe[1], &card, sizeof(int) );
                unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                kill( getppid(), SIGUSR1 );
                usleep(1000);
            }
            else
            {
                G.own_frequencies[ch_idx] = -1;      /* remove invalid channel */
                j--;
                cai--;
                continue;
            }
        }

        if(G.chswitch == 0)
        {
            chi=chi-(if_num - 1);
        }

        if(first)
        {
            first = 0;
        }

        usleep( (G.hopfreq*1000) );
    }

    exit( 0 );
}

int invalid_channel(int chan)
{
    int i=0;

    do
    {
        if (chan == abg_chans[i] && chan != 0 )
            return 0;
    } while (abg_chans[++i]);
    return 1;
}

int invalid_frequency(int freq)
{
    int i=0;

    do
    {
        if (freq == frequencies[i] && freq != 0 )
            return 0;
    } while (frequencies[++i]);
    return 1;
}

/* parse a string, for example "1,2,3-7,11" */

int getchannels(const char *optarg)
{
    unsigned int i=0,chan_cur=0,chan_first=0,chan_last=0,chan_max=128,chan_remain=0;
    char *optchan = NULL, *optc;
    char *token = NULL;
    int *tmp_channels;

    //got a NULL pointer?
    if(optarg == NULL)
        return -1;

    chan_remain=chan_max;

    //create a writable string
    optc = optchan = (char*) malloc(strlen(optarg)+1);
    strncpy(optchan, optarg, strlen(optarg));
    optchan[strlen(optarg)]='\0';

    tmp_channels = (int*) malloc(sizeof(int)*(chan_max+1));

    //split string in tokens, separated by ','
    while( (token = strsep(&optchan,",")) != NULL)
    {
        //range defined?
        if(strchr(token, '-') != NULL)
        {
            //only 1 '-' ?
            if(strchr(token, '-') == strrchr(token, '-'))
            {
                //are there any illegal characters?
                for(i=0; i<strlen(token); i++)
                {
                    if( (token[i] < '0') && (token[i] > '9') && (token[i] != '-'))
                    {
                        free(tmp_channels);
                        free(optc);
                        return -1;
                    }
                }

                if( sscanf(token, "%d-%d", &chan_first, &chan_last) != EOF )
                {
                    if(chan_first > chan_last)
                    {
                        free(tmp_channels);
                        free(optc);
                        return -1;
                    }
                    for(i=chan_first; i<=chan_last; i++)
                    {
                        if( (! invalid_channel(i)) && (chan_remain > 0) )
                        {
                                tmp_channels[chan_max-chan_remain]=i;
                                chan_remain--;
                        }
                    }
                }
                else
                {
                    free(tmp_channels);
                    free(optc);
                    return -1;
                }

            }
            else
            {
                free(tmp_channels);
                free(optc);
                return -1;
            }
        }
        else
        {
            //are there any illegal characters?
            for(i=0; i<strlen(token); i++)
            {
                if( (token[i] < '0') && (token[i] > '9') )
                {
                    free(tmp_channels);
                    free(optc);
                    return -1;
                }
            }

            if( sscanf(token, "%d", &chan_cur) != EOF)
            {
                if( (! invalid_channel(chan_cur)) && (chan_remain > 0) )
                {
                        tmp_channels[chan_max-chan_remain]=chan_cur;
                        chan_remain--;
                }

            }
            else
            {
                free(tmp_channels);
                free(optc);
                return -1;
            }
        }
    }

    G.own_channels = (int*) malloc(sizeof(int)*(chan_max - chan_remain + 1));

    for(i=0; i<(chan_max - chan_remain); i++)
    {
        G.own_channels[i]=tmp_channels[i];
    }

    G.own_channels[i]=0;

    free(tmp_channels);
    free(optc);
    if(i==1) return G.own_channels[0];
    if(i==0) return -1;
    return 0;
}

/* parse a string, for example "1,2,3-7,11" */

int getfrequencies(const char *optarg)
{
    unsigned int i=0,freq_cur=0,freq_first=0,freq_last=0,freq_max=10000,freq_remain=0;
    char *optfreq = NULL, *optc;
    char *token = NULL;
    int *tmp_frequencies;

    //got a NULL pointer?
    if(optarg == NULL)
        return -1;

    freq_remain=freq_max;

    //create a writable string
    optc = optfreq = (char*) malloc(strlen(optarg)+1);
    strncpy(optfreq, optarg, strlen(optarg));
    optfreq[strlen(optarg)]='\0';

    tmp_frequencies = (int*) malloc(sizeof(int)*(freq_max+1));

    //split string in tokens, separated by ','
    while( (token = strsep(&optfreq,",")) != NULL)
    {
        //range defined?
        if(strchr(token, '-') != NULL)
        {
            //only 1 '-' ?
            if(strchr(token, '-') == strrchr(token, '-'))
            {
                //are there any illegal characters?
                for(i=0; i<strlen(token); i++)
                {
                    if( (token[i] < '0' || token[i] > '9') && (token[i] != '-'))
                    {
                        free(tmp_frequencies);
                        free(optc);
                        return -1;
                    }
                }

                if( sscanf(token, "%d-%d", &freq_first, &freq_last) != EOF )
                {
                    if(freq_first > freq_last)
                    {
                        free(tmp_frequencies);
                        free(optc);
                        return -1;
                    }
                    for(i=freq_first; i<=freq_last; i++)
                    {
                        if( (! invalid_frequency(i)) && (freq_remain > 0) )
                        {
                                tmp_frequencies[freq_max-freq_remain]=i;
                                freq_remain--;
                        }
                    }
                }
                else
                {
                    free(tmp_frequencies);
                    free(optc);
                    return -1;
                }

            }
            else
            {
                free(tmp_frequencies);
                free(optc);
                return -1;
            }
        }
        else
        {
            //are there any illegal characters?
            for(i=0; i<strlen(token); i++)
            {
                if( (token[i] < '0') && (token[i] > '9') )
                {
                    free(tmp_frequencies);
                    free(optc);
                    return -1;
                }
            }

            if( sscanf(token, "%d", &freq_cur) != EOF)
            {
                if( (! invalid_frequency(freq_cur)) && (freq_remain > 0) )
                {
                        tmp_frequencies[freq_max-freq_remain]=freq_cur;
                        freq_remain--;
                }

                /* special case "-C 0" means: scan all available frequencies */
                if(freq_cur == 0)
                {
                    freq_first = 1;
                    freq_last = 9999;
                    for(i=freq_first; i<=freq_last; i++)
                    {
                        if( (! invalid_frequency(i)) && (freq_remain > 0) )
                        {
                                tmp_frequencies[freq_max-freq_remain]=i;
                                freq_remain--;
                        }
                    }
                }

            }
            else
            {
                free(tmp_frequencies);
                free(optc);
                return -1;
            }
        }
    }

    G.own_frequencies = (int*) malloc(sizeof(int)*(freq_max - freq_remain + 1));

    for(i=0; i<(freq_max - freq_remain); i++)
    {
        G.own_frequencies[i]=tmp_frequencies[i];
    }

    G.own_frequencies[i]=0;

    free(tmp_frequencies);
    free(optc);
    if(i==1) return G.own_frequencies[0];   //exactly 1 frequency given
    if(i==0) return -1;                     //error occured
    return 0;                               //frequency hopping
}

int setup_card(char *iface, struct wif **wis)
{
	struct wif *wi;

	wi = wi_open(iface);
	if (!wi)
		return -1;
	*wis = wi;

	return 0;
}

int init_cards(const char* cardstr, char *iface[], struct wif **wi)
{
    char *buffer;
    char *buf;
    int if_count=0;
    int i=0, again=0;

    buf = buffer = (char*) malloc( sizeof(char) * 1025 );
    strncpy( buffer, cardstr, 1025 );
    buffer[1024] = '\0';

    while( ((iface[if_count]=strsep(&buffer, ",")) != NULL) && (if_count < MAX_CARDS) )
    {
        again=0;
        for(i=0; i<if_count; i++)
        {
            if(strcmp(iface[i], iface[if_count]) == 0)
            again=1;
        }
        if(again) continue;
        if(setup_card(iface[if_count], &(wi[if_count])) != 0)
        {
            free(buf);
            return -1;
        }
        if_count++;
    }

    free(buf);
    return if_count;
}

#if 0
int get_if_num(const char* cardstr)
{
    char *buffer;
    int if_count=0;

    buffer = (char*) malloc(sizeof(char)*1025);
    if (buffer == NULL) {
		return -1;
	}

    strncpy(buffer, cardstr, 1025);
    buffer[1024] = '\0';

    while( (strsep(&buffer, ",") != NULL) && (if_count < MAX_CARDS) )
    {
        if_count++;
    }

    free(buffer)

    return if_count;
}
#endif

int set_encryption_filter(const char* input)
{
    if(input == NULL) return 1;

    if(strlen(input) < 3) return 1;

    if(strcasecmp(input, "opn") == 0)
        G.f_encrypt |= STD_OPN;

    if(strcasecmp(input, "wep") == 0)
        G.f_encrypt |= STD_WEP;

    if(strcasecmp(input, "wpa") == 0)
    {
        G.f_encrypt |= STD_WPA;
        G.f_encrypt |= STD_WPA2;
    }

    if(strcasecmp(input, "wpa1") == 0)
        G.f_encrypt |= STD_WPA;

    if(strcasecmp(input, "wpa2") == 0)
        G.f_encrypt |= STD_WPA2;

    return 0;
}

int check_monitor(struct wif *wi[], int *fd_raw, int *fdh, int cards)
{
    int i, monitor;
    char ifname[64];

    for(i=0; i<cards; i++)
    {
        monitor = wi_get_monitor(wi[i]);
        if(monitor != 0)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ %s reset to monitor mode", wi_get_ifname(wi[i]));
            //reopen in monitor mode

            strncpy(ifname, wi_get_ifname(wi[i]), sizeof(ifname)-1);
            ifname[sizeof(ifname)-1] = 0;

            wi_close(wi[i]);
            wi[i] = wi_open(ifname);
            if (!wi[i]) {
                printf("Can't reopen %s\n", ifname);
                exit(1);
            }

            fd_raw[i] = wi_fd(wi[i]);
            if (fd_raw[i] > *fdh)
                *fdh = fd_raw[i];
        }
    }
    return 0;
}

int check_channel(struct wif *wi[], int cards)
{
    int i, chan;
    for(i=0; i<cards; i++)
    {
        chan = wi_get_channel(wi[i]);
        if(G.ignore_negative_one == 1 && chan==-1) return 0;
        if(G.channel[i] != chan)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ fixed channel %s: %d ", wi_get_ifname(wi[i]), chan);
            wi_set_channel(wi[i], G.channel[i]);
        }
    }
    return 0;
}

int check_frequency(struct wif *wi[], int cards)
{
    int i, freq;
    for(i=0; i<cards; i++)
    {
        freq = wi_get_freq(wi[i]);
        if(freq < 0) continue;
        if(G.frequency[i] != freq)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ fixed frequency %s: %d ", wi_get_ifname(wi[i]), freq);
            wi_set_freq(wi[i], G.frequency[i]);
        }
    }
    return 0;
}

int detect_frequencies(struct wif *wi)
{
    int start_freq = 2192;
    int end_freq = 2732;
    int max_freq_num = 2048; //should be enough to keep all available channels
    int freq=0, i=0;

    printf("Checking available frequencies, this could take few seconds.\n");

    frequencies = (int*) malloc((max_freq_num+1) * sizeof(int)); //field for frequencies supported
    memset(frequencies, 0, (max_freq_num+1) * sizeof(int));
    for(freq=start_freq; freq<=end_freq; freq+=5)
    {
        if(wi_set_freq(wi, freq) == 0)
        {
            frequencies[i] = freq;
            i++;
        }
        if(freq == 2482)
        {
            //special case for chan 14, as its 12MHz away from 13, not 5MHz
            freq = 2484;
            if(wi_set_freq(wi, freq) == 0)
            {
                frequencies[i] = freq;
                i++;
            }
            freq = 2482;
        }
    }

    //again for 5GHz channels
    start_freq=4800;
    end_freq=6000;
    for(freq=start_freq; freq<=end_freq; freq+=5)
    {
        if(wi_set_freq(wi, freq) == 0)
        {
            frequencies[i] = freq;
            i++;
        }
    }

    printf("Done.\n");
    return 0;
}

int array_contains(int *array, int length, int value)
{
    int i;
    for(i=0;i<length;i++)
        if(array[i] == value)
            return 1;

    return 0;
}

int rearrange_frequencies()
{
    int *freqs;
    int count, left, pos;
    int width, last_used=0;
    int cur_freq, last_freq, round_done;
//     int i;

    width = DEFAULT_CWIDTH;
    cur_freq=0;

    count = getfreqcount(0);
    left = count;
    pos = 0;

    freqs = malloc(sizeof(int) * (count + 1));
    memset(freqs, 0, sizeof(int) * (count + 1));
    round_done = 0;

    while(left > 0)
    {
//         printf("pos: %d\n", pos);
        last_freq = cur_freq;
        cur_freq = G.own_frequencies[pos%count];
        if(cur_freq == last_used)
            round_done=1;
//         printf("count: %d, left: %d, last_used: %d, cur_freq: %d, width: %d\n", count, left, last_used, cur_freq, width);
        if(((count-left) > 0) && !round_done && ( ABS( last_used-cur_freq ) < width ) )
        {
//             printf("skip it!\n");
            pos++;
            continue;
        }
        if(!array_contains( freqs, count, cur_freq))
        {
//             printf("not in there yet: %d\n", cur_freq);
            freqs[count - left] = cur_freq;
            last_used = cur_freq;
            left--;
            round_done = 0;
        }

        pos++;
    }

    memcpy(G.own_frequencies, freqs, count*sizeof(int));
    free(freqs);

    return 0;
}

int main( int argc, char *argv[] )
{
    long time_slept, cycle_time, cycle_time2;
    int caplen=0, i, j, fdh, fd_is_set, chan_count, freq_count, unused;
    int fd_raw[MAX_CARDS], arptype[MAX_CARDS];
    int ivs_only, found;
    int valid_channel;
    int freq [2];
    int num_opts = 0;
    int option = 0;
    int option_index = 0;
    char ifnam[64];
    int wi_read_failed=0;
    int n = 0;
    int output_format_first_time = 1;
#ifdef HAVE_PCRE
    const char *pcreerror;
    int pcreerroffset;
#endif

    struct AP_info *ap_cur, *ap_prv, *ap_next;
    struct ST_info *st_cur, *st_next;
    struct NA_info *na_cur, *na_next;
    struct oui *oui_cur, *oui_next;

    struct pcap_pkthdr pkh;

    time_t tt1, tt2, tt3, start_time;

    struct wif	       *wi[MAX_CARDS];
    struct rx_info     ri;
    unsigned char      tmpbuf[4096];
    unsigned char      buffer[4096];
    unsigned char      *h80211;
    char               *iface[MAX_CARDS];

    struct timeval     tv0;
    struct timeval     tv1;
    struct timeval     tv2;
    struct timeval     tv3;
    struct timeval     tv4;
    struct tm          *lt;

    /*
    struct sockaddr_in provis_addr;
    */

    fd_set             rfds;

#ifdef USE_GCRYPT
    // Register callback functions to ensure proper locking in the sensitive parts of libgcrypt.
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    // Disable secure memory.
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    // Tell Libgcrypt that initialization has completed.
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
	pthread_mutex_init( &(G.mx_print), NULL );
    pthread_mutex_init( &(G.mx_sort), NULL );

    /* initialize a bunch of variables */

	srand( time( NULL ) );
    memset( &G, 0, sizeof( G ) );

    h80211         =  NULL;
    ivs_only       =  0;
    G.chanoption   =  0;
    G.freqoption   =  0;
    G.num_cards	   =  0;
    fdh		   =  0;
    fd_is_set	   =  0;
    chan_count	   =  0;
    time_slept     =  0;
    G.batt         =  NULL;
    G.chswitch     =  0;
    valid_channel  =  0;
    G.usegpsd      =  0;
    G.channels     =  bg_chans;
    G.one_beacon   =  1;
    G.singlechan   =  0;
    G.singlefreq   =  0;
    G.dump_prefix  =  NULL;
    G.record_data  =  0;
    G.f_cap        =  NULL;
    G.f_ivs        =  NULL;
    G.f_txt        =  NULL;
    G.f_kis        =  NULL;
    G.f_kis_xml    =  NULL;
    G.f_gps        =  NULL;
    G.keyout       =  NULL;
    G.f_xor        =  NULL;
    G.sk_len       =  0;
    G.sk_len2      =  0;
    G.sk_start     =  0;
    G.prefix       =  NULL;
    G.f_encrypt    =  0;
    G.asso_client  =  0;
    G.f_essid      =  NULL;
    G.f_essid_count = 0;
    G.active_scan_sim  =  0;
    G.update_s     =  0;
    G.decloak      =  1;
    G.is_berlin    =  0;
    G.numaps       =  0;
    G.maxnumaps    =  0;
    G.berlin       =  120;
    G.show_ap      =  1;
    G.show_sta     =  1;
    G.show_ack     =  0;
    G.hide_known   =  0;
    G.maxsize_essid_seen  =  5; // Initial value: length of "ESSID"
    G.show_manufacturer = 0;
    G.show_uptime  = 0;
    G.hopfreq      =  DEFAULT_HOPFREQ;
    G.s_file       =  NULL;
    G.s_iface      =  NULL;
    G.f_cap_in     =  NULL;
    G.detect_anomaly = 0;
    G.airodump_start_time = NULL;
	G.manufList = NULL;

	G.output_format_pcap = 1;
    G.output_format_csv = 1;
    G.output_format_kismet_csv = 1;
    G.output_format_kismet_netxml = 1;

#ifdef HAVE_PCRE
    G.f_essid_regex = NULL;
#endif

	// Default selection.
    resetSelection();

    memset(G.sharedkey, '\x00', 512*3);
    memset(G.message, '\x00', sizeof(G.message));
    memset(&G.pfh_in, '\x00', sizeof(struct pcap_file_header));

    gettimeofday( &tv0, NULL );

    lt = localtime( (time_t *) &tv0.tv_sec );

    G.keyout = (char*) malloc(512);
    memset( G.keyout, 0, 512 );
    snprintf( G.keyout,  511,
              "keyout-%02d%02d-%02d%02d%02d.keys",
              lt->tm_mon + 1, lt->tm_mday,
              lt->tm_hour, lt->tm_min, lt->tm_sec );

    for(i=0; i<MAX_CARDS; i++)
    {
        arptype[i]=0;
        fd_raw[i]=-1;
        G.channel[i]=0;
    }

    memset(G.f_bssid, '\x00', 6);
    memset(G.f_netmask, '\x00', 6);
    memset(G.wpa_bssid, '\x00', 6);

    G.s_iface = "mon0";

    if(G.s_iface != NULL)
    {
        /* initialize cards */
        G.num_cards = init_cards(G.s_iface, iface, wi);

        if(G.num_cards <= 0)
            return( 1 );

        for (i = 0; i < G.num_cards; i++) {
            fd_raw[i] = wi_fd(wi[i]);
            if (fd_raw[i] > fdh)
                fdh = fd_raw[i];
        }

        //use channels
        chan_count = getchancount(0);

	G.channel[0]= 6;	
        for( i=0; i<G.num_cards; i++ )
        {
             wi_set_channel(wi[i], G.channel[0]);
             G.channel[i] = G.channel[0];
        }
        G.singlechan = 1;
     }

     /* Drop privileges */
     if (setuid( getuid() ) == -1) {
	perror("setuid");

     }

    
    signal( SIGINT,   sighandler );
    signal( SIGSEGV,  sighandler );
    signal( SIGTERM,  sighandler );
    signal( SIGWINCH, sighandler );

    sighandler( SIGWINCH );
    
    start_time = time( NULL );
    tt1        = time( NULL );
    tt2        = time( NULL );
    tt3        = time( NULL );
    gettimeofday( &tv3, NULL );
    gettimeofday( &tv4, NULL );

    while( 1 )
    {
        if( G.do_exit )
        {
            break;
        }

       gettimeofday( &tv1, NULL );

        cycle_time = 1000000 * ( tv1.tv_sec  - tv3.tv_sec  )
                             + ( tv1.tv_usec - tv3.tv_usec );

        cycle_time2 = 1000000 * ( tv1.tv_sec  - tv4.tv_sec  )
                              + ( tv1.tv_usec - tv4.tv_usec );

        if( G.active_scan_sim > 0 && cycle_time2 > G.active_scan_sim*1000 )
        {
            gettimeofday( &tv4, NULL );
            send_probe_requests(wi, G.num_cards);
        }

        if( cycle_time > 500000 )
        {
            gettimeofday( &tv3, NULL );
            if(G.s_iface != NULL)
            {
                check_monitor(wi, fd_raw, &fdh, G.num_cards);
                if(G.singlechan)
                    check_channel(wi, G.num_cards);
                if(G.singlefreq)
                    check_frequency(wi, G.num_cards);
            }
        }

        if(G.s_iface != NULL)
        {
            /* capture one packet */

            FD_ZERO( &rfds );
            for(i=0; i<G.num_cards; i++)
            {
                FD_SET( fd_raw[i], &rfds );
            }

            tv0.tv_sec  = G.update_s;
            tv0.tv_usec = (G.update_s == 0) ? REFRESH_RATE : 0;

            gettimeofday( &tv1, NULL );

            if( select( fdh + 1, &rfds, NULL, NULL, &tv0 ) < 0 )
            {
                if( errno == EINTR )
                {
                    gettimeofday( &tv2, NULL );

                    time_slept += 1000000 * ( tv2.tv_sec  - tv1.tv_sec  )
                                        + ( tv2.tv_usec - tv1.tv_usec );

                    continue;
                }
                perror( "select failed" );

                return( 1 );
            }
        }
        else
            usleep(1);

   
        if(G.s_iface != NULL)
        {
            fd_is_set = 0;

            for(i=0; i<G.num_cards; i++)
            {
                if( FD_ISSET( fd_raw[i], &rfds ) )
                {

                    memset(buffer, 0, sizeof(buffer));
                    h80211 = buffer;
                    if ((caplen = wi_read(wi[i], h80211, sizeof(buffer), &ri)) == -1) {
                        wi_read_failed++;
                        if(wi_read_failed > 1)
                        {
                            G.do_exit = 1;
                            break;
                        }
                        memset(G.message, '\x00', sizeof(G.message));
                        snprintf(G.message, sizeof(G.message), "][ interface %s down ", wi_get_ifname(wi[i]));

                        //reopen in monitor mode

                        strncpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam)-1);
                        ifnam[sizeof(ifnam)-1] = 0;

                        wi_close(wi[i]);
                        wi[i] = wi_open(ifnam);
                        if (!wi[i]) {
                            printf("Can't reopen %s\n", ifnam);

                            /* Restore terminal */
                            fprintf( stderr, "\33[?25h" );
                            fflush( stdout );

                            exit(1);
                        }

                        fd_raw[i] = wi_fd(wi[i]);
                        if (fd_raw[i] > fdh)
                            fdh = fd_raw[i];

                        break;
//                         return 1;
                    }

                    read_pkts++;

                    wi_read_failed = 0;
                    dump_add_packet( h80211, caplen, &ri, i );
                }
            }
        }
    }

    if(G.elapsed_time)
        free(G.elapsed_time);

    if(G.own_channels)
        free(G.own_channels);
    
    if(G.f_essid)
        free(G.f_essid);

    if(G.prefix)
        free(G.prefix);

    if(G.f_cap_name)
        free(G.f_cap_name);

    if(G.keyout)
        free(G.keyout);

#ifdef HAVE_PCRE
    if(G.f_essid_regex)
        pcre_free(G.f_essid_regex);
#endif

    for(i=0; i<G.num_cards; i++)
        wi_close(wi[i]);

    
    if( ! G.save_gps )
    {
        snprintf( (char *) buffer, 4096, "%s-%02d.gps", argv[2], G.f_index );
        unlink(  (char *) buffer );
    }

    ap_prv = NULL;
    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
		// Clean content of ap_cur list (first element: G.ap_1st)
        uniqueiv_wipe( ap_cur->uiv_root );

        list_tail_free(&(ap_cur->packets));

	if (G.manufList)
		free(ap_cur->manuf);

	if (G.detect_anomaly)
        	data_wipe(ap_cur->data_root);

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
		// Freeing AP List
        ap_next = ap_cur->next;

        if( ap_cur != NULL )
            free(ap_cur);

        ap_cur = ap_next;
    }

    st_cur = G.st_1st;
    st_next= NULL;

    while(st_cur != NULL)
    {
        st_next = st_cur->next;
	if (G.manufList)
		free(st_cur->manuf);
        free(st_cur);
        st_cur = st_next;
    }

    na_cur = G.na_1st;
    na_next= NULL;

    while(na_cur != NULL)
    {
        na_next = na_cur->next;
        free(na_cur);
        na_cur = na_next;
    }

    fprintf( stderr, "\33[?25h" );
    fflush( stdout );

    return( 0 );
}

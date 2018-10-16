#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <pcap.h>
#include <time.h>

// #include<netdb.h>
// #include<sys/socket.h>
// #include<net/if.h>
// #include<netinet/in.h>
// #include<netinet/ip.h>
// #include<netinet/ip_icmp.h>
// #include<linux/if_ether.h>
// #include<linux/if_packet.h>
// #include <sys/time.h>
// #include <sys/types.h>
// #include <stdlib.h>

#include "net/ty_80211_header.h"
#include "product_config.h"
#include "tuya_ipc_api.h"

#include "tycam_hisi_slink.h"


#define WLAN_DEV        "wlan0"
static tycam_hisi_slink_handle_s s_slink_hdl = {0};

// 802.11 frame info
typedef enum {
    WFT_BEACON = 0x80,      // Beacon
    WFT_DATA = 0x08,        // Data
    WFT_QOS_DATA = 0x88,    // QOS Data
}WLAN_FRM_TP_E;


#define FIXED_MAC_SKIP_LEN      (256)

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{  
    //int * id = (int *)arg;
    //int i;

    if (NULL == pkthdr || NULL == packet){
        printf("%s %d data error\n",__FUNCTION__,__LINE__);
        return;
    }
  //printf("pcap id: %d len:%d\n", ++(*id),pkthdr->len);
  
#if 0 
  printf("Packet length: %d\n", pkthdr->len);  
  printf("Number of bytes: %d\n", pkthdr->caplen);  
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
#endif
    int skipLen = 0;
    if (0 == strcmp(WIFI_CHIP,"8188fu")){
        ieee80211_radiotap_header *pHeader = (ieee80211_radiotap_header *)packet;
        skipLen = pHeader->it_len;  
    }else if (0 == strcmp(WIFI_CHIP,"mt7601")){
        skipLen = 0x90;
    }else{
        printf("wifi chip not support[%s]\n",WIFI_CHIP);
        sleep(3);
    }
    
    if ((packet[skipLen] != WFT_DATA)
        && (packet[skipLen] != WFT_BEACON)
        && (packet[skipLen] != WFT_QOS_DATA)){
        return;
    }

    if (pkthdr->len > skipLen){
        if (s_slink_hdl.data_cbk){
            s_slink_hdl.data_cbk(packet + skipLen, pkthdr->len - skipLen);
        }
    }
}

pcap_t * g_device = NULL;

void *tycam_hisi_slink_pcap_proc(void *arg)
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;

    /* get a g_device */
    devStr = pcap_lookupdev(errBuf);

    if(devStr){
        printf("success: g_device: %s\n", devStr);
    }else{
        printf("error: %s\n", errBuf);
        return NULL;
    }

    /* open a g_device, wait until a packet arrives */
    g_device = pcap_open_live(devStr, 2048, 1, 0, errBuf);

    if(!g_device){
        printf("error: pcap_open_live(): %s\n", errBuf);
        return NULL;
    }

    /* wait loop forever */
    int id = 0;
    int retLoop = 0;
    retLoop = pcap_loop(g_device, -1, getPacket, (u_char*)&id);
    printf("########pcap_loop = %d %s\n",retLoop,pcap_geterr(g_device));

    pcap_close(g_device);
    s_slink_hdl.sThreadSta = 0;

    return NULL;  
}

int __hisi_start_pcap_thread()
{
    int ret;
    
    pthread_attr_t attrs;
    pthread_attr_init(&attrs);
    pthread_attr_setstacksize(&attrs, 1024*1024);
    
    ret = pthread_create(&s_slink_hdl.stid, &attrs, tycam_hisi_slink_pcap_proc, &s_slink_hdl);
    if (0 != ret){
        printf("%s[%d] pthread create failed[%d]\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }
    s_slink_hdl.sThreadSta = 1;  //作为判断pcap_loop是否存活得标识
    pthread_detach(s_slink_hdl.stid);

    return 0;
}

int tycam_hisi_slink_start(SNIFFER_CALLBACK cb)
{
    printf("%s[%d] into func\n",__FUNCTION__,__LINE__);

    int ret;
    if(1 == s_slink_hdl.sThreadSta) {
        printf("smart link thread have start...\n");
        return -1;
    }
    //ret = __hisi_start_pcap_thread();
    ret = __hisi_start_netlink_thread();
    if (0 != ret){
        printf("%s[%d] pcap thread create failed\n",__FUNCTION__,__LINE__);
        return ret;
    }
    s_slink_hdl.data_cbk = cb;
   
    return 0;
}

#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>

#define NETLINK_TEST 25
#define MAX_PAYLOAD 1024 // maximum payload size

static int netlink_flag = 0;
void *tycam_hisi_slink_netlink_proc(void *arg)
{
    netlink_flag = 1;

    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;
    int state_smg = 0;
    // Create a socket

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(sock_fd == -1){
        printf("error getting socket: %s", strerror(errno));
        return -1;
    }
    
    // To prepare binding
    memset(&msg,0,sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // self pid
    
    src_addr.nl_groups = 0; // multi cast
    retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0){
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }
    // To prepare recvmsg
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return -1;
    }
    
    memset(&dest_addr,0,sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh),"start");

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;



    printf("state_smg\n");
    state_smg = sendmsg(sock_fd,&msg,0);

    if(state_smg == -1)
    {
        printf("get error sendmsg = %s\n",strerror(errno));
    }

    memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
    printf("waiting received!\n");    
    while(1 == netlink_flag){
        static int recv_cnt = 1;
        state = recvmsg(sock_fd, &msg, 0);
        if(state<0)
        {
            printf("state<1");
        }
        //memcpy(&macInfo, (char *)NLMSG_DATA(nlh), NLMSG_DATALEN(nlh));   
        if (s_slink_hdl.data_cbk){
            int len = nlh->nlmsg_len - sizeof(struct nlmsghdr);
            //printf("recv len[%d]\n",len);  
            s_slink_hdl.data_cbk((char *)NLMSG_DATA(nlh), len);
        }
    }

    //发送结束
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh),"stop");

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    state_smg = sendmsg(sock_fd,&msg,0);  
    fclose(sock_fd);
    free(nlh);
    
}

int __hisi_start_netlink_thread()
{
    int ret;
    pthread_t pid;
    pthread_attr_t attrs;
    pthread_attr_init(&attrs);
    pthread_attr_setstacksize(&attrs, 1024*1024);
    
    ret = pthread_create(&pid, &attrs, tycam_hisi_slink_netlink_proc, NULL);
    if (0 != ret){
        printf("%s[%d] pthread create failed[%d]\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }
    pthread_detach(pid);

}

int tycam_hisi_slink_stop()
{
    printf("%s[%d] into func\n",__FUNCTION__,__LINE__);
#if 0    
    pcap_breakloop(g_device);
    pthread_join(s_slink_hdl.stid, NULL);
#else
    netlink_flag = 0;
#endif
    memset(&s_slink_hdl,0x00,sizeof(s_slink_hdl));

    return 0;
}



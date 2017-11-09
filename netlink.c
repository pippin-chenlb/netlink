#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>

#define NETLINK_TEST 25
#define MAX_PAYLOAD 1024 // maximum payload size

typedef struct ieee80211_hdr_{
	unsigned short fc;
	unsigned short di;
	unsigned char addr1[6];
	unsigned char addr2[6];
	unsigned char addr3[6];
	unsigned short seq_ctrl;
	unsigned char addr4[6];
	
}ieee80211_hdr_u;

int main(int argc, char* argv[])
{
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
    strcpy(NLMSG_DATA(nlh),"Hello you!");

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

    while(1){
        static int recv_cnt = 1;
	ieee80211_hdr_u macInfo;
        state = recvmsg(sock_fd, &msg, 0);
        if(state<0)
        {
            printf("state<1");
        }
	memcpy(&macInfo, (char *)NLMSG_DATA(nlh), sizeof(ieee80211_hdr_u));
	printf("mac count(%d) fc = %d\n",recv_cnt, macInfo.fc);
	printf("addr1 %x-%x-%x-%x-%x-%x\n",macInfo.addr1[0],macInfo.addr1[1],
		macInfo.addr1[2],macInfo.addr1[3],macInfo.addr1[4],macInfo.addr1[5]);
	printf("addr2 %x-%x-%x-%x-%x-%x\n",macInfo.addr2[0],macInfo.addr2[1],
		macInfo.addr2[2],macInfo.addr2[3],macInfo.addr2[4],macInfo.addr2[5]);
	printf("addr3 %x-%x-%x-%x-%x-%x\n",macInfo.addr3[0],macInfo.addr3[1],
		macInfo.addr3[2],macInfo.addr3[3],macInfo.addr3[4],macInfo.addr3[5]);
        recv_cnt++;
    }

    close(sock_fd);

    return 0;
}


#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#ifndef _WIN32
    #include <unistd.h>
    #include <signal.h>
    #include <netdb.h>
    #include <netinet/ip_icmp.h>
    #include <netinet/ip.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <sysexits.h>
    #include<features.h>
    #include<linux/if_packet.h>
    #include<linux/if_ether.h>
    #include<sys/ioctl.h>
    #include<net/if.h>
    #define SOCKET_T int
    #define SOCKLEN_T socklen_t
    #define MY_EX_USAGE EX_USAGE
    #define INVALID_SOCKET (-1)
#endif

#include <event2/event.h>



#define MSG_SIZE 1500
#define pkt_number 1000
char* serverString = NULL;
struct event_base* base;               /* main base */
struct sockaddr_in server;
struct timeval timeval1;
struct event* sendEvent;
struct event* recvEvent;
struct event *sig_event;
int traceCount = 0;
int msgCount = 0;
double sendtime = 0.0;    
int max_hop = -1;
int  tos = 0;
int ttl   = 1;                 

int   myoptind;
char* myoptarg;


static int GetOpt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}

double get_ms (void)
{
    double            ms; // Milliseconds
    time_t          s;
    struct timeval spec;
    double combine;
    //clock_gettime(CLOCK_REALTIME, &spec);
    gettimeofday(&spec,NULL);
    //printf("%ld\n",spec.tv_usec);
    s  = spec.tv_sec;
    ms = (double)spec.tv_usec / 1.0e6; // Convert nanoseconds to milliseconds

    combine = (double)s + (double)ms;

    //printf("%f\n", combine);
    return combine;
}

static void newTrace(evutil_socket_t fd, short which, void* arg){

    int ret = 0;
    static struct icmphdr icmphdr;
    char msg[MSG_SIZE];
    int  msgLen;
    double RTT[3];
    struct iphdr *recv_iphdr;
    struct icmphdr *recv_icmphdr;
    struct in_addr insaddr;

    if(msgCount == 0){
        memset(&icmphdr, 0, sizeof(icmphdr));
    }

    msgLen = recv(fd, msg, MSG_SIZE, 0);
    if(msgLen > 0){
        recv_iphdr = (struct iphdr *)msg;
        recv_icmphdr = (struct icmphdr *)(msg + (recv_iphdr->ihl << 2));
        insaddr.s_addr = recv_iphdr->saddr;
        if(recv_icmphdr->type == ICMP_TIME_EXCEEDED){
            RTT[msgCount%3] = (get_ms()-sendtime) * 1000;
            if(msgCount % 3 == 2){
                ttl++;
                setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
                printf("%d  %.3fms  %.3fms  %.3fms  %s\n", (msgCount/3)+1, RTT[0], RTT[1], RTT[2], inet_ntoa(insaddr));
            }
            msgCount++;
            if(msgCount/3 < max_hop){
                setup_icmphdr(ICMP_ECHO, 0, 0, msgCount, &icmphdr);
                ret = sendto(fd, (char *)&icmphdr, sizeof(icmphdr), 0, (struct sockaddr *)&server, sizeof(server));
                if(ret < 0) {
                    perror("send failed");
                    exit(EXIT_FAILURE);
                }
                sendtime = get_ms();
            }
            else{
                printf("maximum hop\n");
                exit(EXIT_SUCCESS);
            }

        }
        else if(!strcmp(serverString, inet_ntoa(insaddr)) && recv_icmphdr->type == ICMP_ECHOREPLY){
            RTT[msgCount%3] = (get_ms()-sendtime) * 1000;
            if(msgCount % 3 == 2){
                printf("%d  %.3fms  %.3fms  %.3fms  %s\n", (msgCount/3)+1, RTT[0], RTT[1], RTT[2], inet_ntoa(insaddr));
                exit(EXIT_SUCCESS);
            }
            msgCount++;
            setup_icmphdr(ICMP_ECHO, 0, 0, msgCount, &icmphdr);
            ret = sendto(fd, (char *)&icmphdr, sizeof(icmphdr), 0, (struct sockaddr *)&server, sizeof(server));
            if(ret < 0) {
                perror("send failed");
                exit(EXIT_FAILURE);
            }
            sendtime = get_ms();
        }
    }


}

void handler(int signo, short events, void* arg) {
        printf("interrupt\n");
        exit(EXIT_SUCCESS);
}


static void Usage(void)
{
    printf("HongZhiTraceRoute \n");
    printf("-h                  Help, print this usage\n");
    printf("-t <maximun_hop>    Set the max number of hops, default 30\n");
    printf("-s <address>        address in dotted decimal\n");
    printf("-d                  TOS/DSCP, Set the TOS/DSCP (IPv4 type of service), default 0\n");
    printf("-y <num>            first ttl, Start from the first_ttl hop , default 1\n");
}

u_int16_t checksum(unsigned short *buf, int size)
{
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buf;
        buf++;
        size -= 2;
    }
    if (size == 1)
        sum += *(unsigned char *)buf;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

void setup_icmphdr(u_int8_t type, u_int8_t code, u_int16_t id, u_int16_t seq, struct icmphdr *icmphdr)
{
    icmphdr->type = type;
    icmphdr->code = code;
    icmphdr->checksum = 0;
    icmphdr->un.echo.id = id;
    icmphdr->un.echo.sequence = seq;
    icmphdr->checksum = checksum((unsigned short *)icmphdr, sizeof(struct icmphdr));
}

int main(int argc, char** argv)
{
    SOCKET_T sockfd;
    int ret,ch = 1;
    struct icmphdr icmphdr;

    while ( (ch = GetOpt(argc, argv, "hd:t:s:y:")) != -1) {
        switch (ch) {
            case 'h' :
                Usage();
                exit(EXIT_SUCCESS);
                break;

            case 't' :
                max_hop = atoi(myoptarg);
                break;

            case 'd' :
                tos = atoi(myoptarg);
                break;

            case 'y' :
                ttl = atoi(myoptarg);
                break;

            case 's' :
                serverString = myoptarg;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
                break;
        }
    }

    if (max_hop <= 0) {
        max_hop = 30;
    }

    if(!(tos == 0 || tos == 32 || tos == 224 || tos == 192 || tos == 40 || tos == 56 || tos == 72 || tos == 88 || 
        tos == 96 || tos == 112 || tos == 136 || tos == 144 || tos == 152 || tos == 160 || tos == 184)){
        tos = 0;
        printf("tos invalid\n");
    }

    if (serverString == NULL) {
        printf("need to set destination address\n");
        Usage();
        exit(MY_EX_USAGE);
    }
    
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    memset(&server, 0, sizeof(server));
    server.sin_family = PF_INET;
    server.sin_addr.s_addr = inet_addr(serverString);
    if(inet_addr(serverString) == -1){
        printf("invalid address\n");
        Usage();
        exit(MY_EX_USAGE);
    }

    memset(&icmphdr, 0, sizeof(icmphdr));
    setup_icmphdr(ICMP_ECHO, 0, 0, 0, &icmphdr);

    base = event_base_new();
    if (base == NULL) {
        perror("event_base_new failed");
        exit(EXIT_FAILURE);
    }

    printf("TraceRoute %s\n",serverString);

    ret = sendto(sockfd, (char *)&icmphdr, sizeof(icmphdr), 0, (struct sockaddr *)&server, sizeof(server));
    sendtime = get_ms();
    if (ret < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }

    recvEvent = event_new(base, sockfd, EV_READ|EV_PERSIST, newTrace, NULL);
    if (recvEvent == NULL) {
        perror("event_new failed for recvEvent");
        exit(EXIT_FAILURE);
    }

    event_add(recvEvent, NULL);

    int signo = SIGINT;
    sig_event = evsignal_new(base, signo, handler, NULL);
    evsignal_add(sig_event, NULL);

    event_base_dispatch(base);

    printf("done with dispatching\n");

    return 0;
}

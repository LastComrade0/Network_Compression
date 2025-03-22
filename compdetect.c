#define __USE_BSD	/* use bsd'ish ip header */
#define __FAVOR_BSD	/* use bsd'ish tcp header */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>



#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <cjson/cJSON.h>


#define PACKET_SIZE 1200
#define NUM_PACKETS 100
#define TIMEOUT_SEC 5


struct prototype_header{ //For checksum
    uint32_t src_addr;
    uint32_t dest_addr;
    uint32_t reserved;
    uint32_t protocol;
    uint32_t tcp_length;
};

long time_diff(struct timeval start, struct timeval end) {
    return ((end.tv_sec - start.tv_sec) * 1000000L) + (end.tv_usec - start.tv_usec);
}

unsigned short check_sum(unsigned short *buffer, int nwords){
    unsigned long sum;
    for(sum = 0; nwords > 0; nwords -= 1){
        sum += *buffer++;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void send_syn_pkt(int socket, struct sockaddr_in *dest, int port, const char *server_ip){
    char datagram[4096];

    struct ip *iph = (struct ip*)datagram;
    struct tcphdr *tcpheader = (struct tcphdr*)(datagram + sizeof(struct ip));

    memset(datagram, 0, 4096);

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); //No payload
    iph->ip_id = htonl(10090); //Value does not matter
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP; //Which is 6
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr("1.2.3.4");
    iph->ip_dst.s_addr = dest->sin_addr.s_addr;

    tcpheader->th_sport = htons(1234); //Arbitrary port
    tcpheader->th_dport = htons(port);
    tcpheader->th_seq = random();
    tcpheader->th_ack = 0;
    tcpheader->th_x2 = 0;
    tcpheader->th_off = sizeof(struct tcphdr) / 4;
    tcpheader->th_flags = TH_SYN;
    tcpheader->th_win = htons(65535); //Max allowed window size
    tcpheader->th_sum = 0; //If set 0, kernel's IP stack will fill correct checksum during transmission
    tcpheader->th_urp = 0;

    iph->ip_sum = check_sum((unsigned short *) datagram, iph->ip_len >> 1);
    
    int one = 1;
    const int *val = &one;
    int set_HDRINCL = setsockopt(socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
    if(set_HDRINCL < 0){
        syslog(LOG_INFO, "Warning: Unable to set HDRINCL!\n");
    }

    int send_syn = sendto(socket, datagram, iph->ip_len, 0, (struct sockaddr *) dest, sizeof(struct sockaddr_in));
    if(send_syn <= 0){
        syslog(LOG_PERROR, "Error: Unable to send syn! %d\n", send_syn);
        exit(1);
    }
    else{
        syslog(LOG_INFO, "Sucessfully sent one SYN packet.\n");
    }

}

int capture_rst_pkt(int socket, struct timeval *timestamp){

    syslog(LOG_INFO, "Capturing RST pkt\n");
    struct timeval timeout;

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    fd_set fd;
    FD_ZERO(&fd);
    FD_SET(socket, &fd);

    int select_blocking = select(socket + 1, &fd, NULL, NULL, &timeout);

    if(select_blocking > 0){
        char buffer[4096];
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        recvfrom(socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen);//(struct sockaddr*)&addr?
        gettimeofday(timestamp, NULL);
        syslog(LOG_INFO, "Captured RST pkt\n");
        return 1;
    }

    syslog(LOG_INFO, "Catched nothing before timeout\n");
    return 0;
    
}

void send_syn_packet(struct timeval *start, struct timeval *end){
    char packet[4096];
}


int main(int argc, char* argv[]){

    openlog("Server", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);

    char* server_ip = "192.168.132.210";

    int port_x = atoi("9999");
    int port_y = atoi("8888");

    int tcp_raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP);

    if(tcp_raw_socket < 0){
        syslog(LOG_ERR, "Unable to create TCP raw socket: %d", tcp_raw_socket);
        exit(1);
    }

    int self_ip_enable = 1;
    int set_self_ip = setsockopt(tcp_raw_socket, IPPROTO_IP, IP_HDRINCL, &self_ip_enable, sizeof(self_ip_enable));
    if(set_self_ip < 0){
        syslog(LOG_ERR, "Error setting IP_HDRINCL: Unable to enable self ip header");
        exit(1);
    }
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = inet_addr(server_ip);
    //inet_pton(AF_INET, server_ip, &sin.sin_addr);

    struct addrinfo udp_hint, *udp_res;
    memset(&udp_hint, 0, sizeof(udp_hint));
    udp_hint.ai_family = AF_INET;
    udp_hint.ai_socktype = SOCK_DGRAM;

    int get_udp_address_info = getaddrinfo(server_ip, "9999", &udp_hint, &udp_res);
    if(get_udp_address_info != 0){
        syslog(LOG_PERROR, "Get address info for UDP failed");
        exit(1);
    }

    struct timeval low_rst1_time, low_rst2_time, high_rst1_time, high_rst2_time;

    send_syn_pkt(tcp_raw_socket, &sin, port_x, server_ip); //thread1
    //send_udp_train(); Low entropy
    send_syn_pkt(tcp_raw_socket, &sin, port_y, server_ip); 

    sleep(15);

    send_syn_pkt(tcp_raw_socket, &sin, port_x, server_ip);
    //send_udp_train();
    send_syn_pkt(tcp_raw_socket, &sin, port_y, server_ip);

    int rst1 = capture_rst_pkt(tcp_raw_socket, &low_rst1_time); //thread 2
    int rst2 = capture_rst_pkt(tcp_raw_socket, &low_rst2_time);
    //int rst3 = capture_rst_pkt(host 192.168.132.210 a_raw_socket, &high_rst1_time);
    //int rst4 = capture_rst_pkt(tcp_raw_socket, &high_rst2_time);


    //if(!rst1 | !rst2 | !rst3 | !rst4)
    

    //long low_entropy_time = time_diff(&low_rst1_time,  &low_rst2_time)
    //long high_entropy_time = time_diff(&high_rst1_time, &high_rst2_time)
    //long diff = high_entropy_time - low_entropy_time;
    //if(diff > 100){ printf("Compression detected!\n") }
    //else{ printf("No Compression detected.\n") }

    close(udp_sock);
    close(tcp_raw_socket);
    return 0;
    

}


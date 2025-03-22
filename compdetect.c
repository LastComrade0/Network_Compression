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
#include <pthread.h>



#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <cjson/cJSON.h>


#define PACKET_SIZE 1200
#define NUM_PACKETS 100
#define TIMEOUT_SEC 5
#define ID_EXTRACT sizeof(uint16_t)

struct rst_capture_args{
    int socket;
    struct timeval *timestamp;
    int *result_ptr;
};

struct prototype_header{ //For checksum
    uint32_t src_addr;
    uint32_t dest_addr;
    uint32_t reserved;
    uint32_t protocol;
    uint32_t tcp_length;
};

typedef struct{
    char server_ip[16];
    char udp_src_port[6];
    char udp_dest_port[6];
    char tcp_head_syn_dest_port[6];
    char tcp_tail_syn_dest_port[6];
    char tcp_port_pre_probe[6]; //For part 1
    char tcp_port_post_probe[6]; //For part 1
    int packet_size;
    int inter_time;
    int packet_count;
    int udp_ttl;

    
} Config;

void parse_configfile(char *json_file, Config *config, char *json_buffer){
    FILE *file = fopen(json_file, "r");
    if(!file){
        perror("Failed to open config file");
        exit(1);
    }

    fseek(file, 0, SEEK_END); //Move pointer to last byte
    long file_size = ftell(file); //Get size given the last pointer
    fseek(file, 0, SEEK_SET); //Move pointer back to start of file

    fread(json_buffer, 1, file_size, file);
    json_buffer[file_size] = '\0';
    fclose(file);

    cJSON *json_parser = cJSON_Parse(json_buffer);
    if(!json_parser){
        perror("Error parsing JSON");
        exit(1);
    }
    
    strcpy(config->server_ip, cJSON_GetObjectItem(json_parser, "server_ip")->valuestring);
    strcpy(config->udp_src_port, cJSON_GetObjectItem(json_parser, "udp_src_port")->valuestring);
    strcpy(config->udp_dest_port, cJSON_GetObjectItem(json_parser, "udp_dest_port")->valuestring);
    strcpy(config->tcp_head_syn_dest_port, cJSON_GetObjectItem(json_parser, "tcp_head_syn_dest_port")->valuestring);
    strcpy(config->tcp_tail_syn_dest_port, cJSON_GetObjectItem(json_parser, "tcp_tail_syn_dest_port")->valuestring);
    strcpy(config->tcp_port_pre_probe, cJSON_GetObjectItem(json_parser, "tcp_port_pre_probe")->valuestring);
    strcpy(config->tcp_port_post_probe, cJSON_GetObjectItem(json_parser, "tcp_port_post_probe")->valuestring);
    config->packet_size = cJSON_GetObjectItem(json_parser, "packet_size")->valueint;
    config->inter_time = cJSON_GetObjectItem(json_parser, "inter_time")->valueint;
    config->packet_count = cJSON_GetObjectItem(json_parser, "packet_count")->valueint;
    config->udp_ttl = cJSON_GetObjectItem(json_parser, "udp_ttl")->valueint;

    cJSON_Delete(json_parser);

    syslog(LOG_INFO, "Successfully parsed JSON to struct\n\n");
    syslog(LOG_INFO, "Server ip: %s\n", config->server_ip);
    syslog(LOG_INFO, "UDP src port: %s\n", config->udp_src_port);
    syslog(LOG_INFO, "UDP dest port: %s\n", config->udp_dest_port);
    syslog(LOG_INFO, "TCP head syn dest port: %s\n", config->tcp_head_syn_dest_port);
    syslog(LOG_INFO, "TCP tail syn dest port: %s\n", config->tcp_tail_syn_dest_port);
    syslog(LOG_INFO, "TCP port pre probe: %s\n", config->tcp_port_pre_probe);
    syslog(LOG_INFO, "TCP port post probe: %s\n", config->tcp_port_post_probe);
    syslog(LOG_INFO, "Packet Size: %d\n", config->packet_size);
    syslog(LOG_INFO, "Inter time %d\n", config->inter_time);
    syslog(LOG_INFO, "Packet count: %d\n\n", config->packet_count);
    syslog(LOG_INFO, "UDP ttl: %d\n\n", config->udp_ttl);

}

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

void send_syn_pkt(int socket, struct sockaddr_in *dest, int port, const char *src_ip){
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
    iph->ip_src.s_addr = inet_addr(src_ip);
    iph->ip_dst.s_addr = dest->sin_addr.s_addr;

    tcpheader->th_sport = htons(port); //Arbitrary port
    tcpheader->th_dport = htons(9999);
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

int set_udp_socket(const char *application_ip, const char *src_port, const char* dest_port, struct addrinfo **res, Config *config){

    syslog(LOG_INFO, "Setting UDP socket");

    struct addrinfo hints;
    int udp_socket;
    int addr_info;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    //Resolve destination address
    addr_info = getaddrinfo(application_ip, dest_port, &hints, res);

    if(addr_info == -1){
        fprintf(stderr, "Addr_info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    udp_socket = socket((*res)->ai_family, (*res)->ai_socktype, (*res)->ai_protocol);
    
    if(udp_socket == -1){
        fprintf(stderr, "UDP socket error %s\n", strerror(errno));
        exit(1);
    }

    int dont_fragment = IP_PMTUDISC_DO;
    if(setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) < 0){
        fprintf(stderr, "UDP don't fragment error %s\n", strerror(errno));
        exit(1);
    }

    int ttl = config->udp_ttl;
    int set_ttl = setsockopt(udp_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if(set_ttl < 0){
        fprintf(stderr, "UDP set ttl error %s\n", strerror(errno));
        exit(1);
    }
    

    syslog(LOG_INFO, "Successfully set UDP socket\n");
    return udp_socket;
}

void send_udp_train(int udp_socket, struct addrinfo *server_info, int entropy_type, Config *config){
    char buffer[config->packet_size];
    int packet_id;
    int packet_sent = 0;
    
    switch(entropy_type){
        case 0:
            memset(buffer, 0, config->packet_size);

            syslog(LOG_INFO, "Sending low entropy train...\n");
            for(int i = 0; i < config->packet_count; i += 1){
                //printf("Sending packet id: %d\n", i);
                packet_id = htons(i);
                memcpy(buffer, &packet_id, ID_EXTRACT);
                ssize_t sent_udp = sendto(udp_socket, buffer, config->packet_size, 0, server_info->ai_addr, server_info->ai_addrlen);
                if (sent_udp != config->packet_size) {
                    if (sent_udp < 0) {
                        perror("UDP send error");
                        exit(EXIT_FAILURE);
                    } else {
                        // Log a warning if the sent bytes are less than expected
                        syslog(LOG_WARNING, "Sent fewer bytes than expected: %zd instead of %d", sent_udp, config->packet_size);
                    }
                } else {
                    packet_sent += 1;
                }

                //printf("Sent low-entropy packet id: %d\n", i);
            }

            syslog(LOG_INFO, "Low entropy packet sent: %d\n", packet_sent);

            break;

        case 1:

            syslog(LOG_INFO, "Sending high entropy udp packet\n");
            
            int urandom_fd = open("/dev/urandom", O_RDONLY);

            if(urandom_fd < 0){
                fprintf(stderr, "Urandom open error: %s\n Must be 0 or 1\n", gai_strerror(urandom_fd));
                exit(1);
            }

            for(int i = 0; i < config->packet_count; i += 1){
                packet_id = htons(i);
                memcpy(buffer, &packet_id, ID_EXTRACT);

                ssize_t urandom_read = read(urandom_fd, buffer + ID_EXTRACT, config->packet_size - ID_EXTRACT);
                
                // printf("Current bit: ");
                
                // printf("%s\n", buffer);

                if(urandom_read < 0){
                    perror("Error opening /dev/urandom");
                    close(urandom_fd);
                    exit(1);
                }
                
                ssize_t sent_udp = sendto(udp_socket, buffer, config->packet_size, 0, server_info->ai_addr, server_info->ai_addrlen);
                
                if (sent_udp != config->packet_size) {
                    if (sent_udp < 0) {
                        perror("UDP send error");
                        exit(EXIT_FAILURE);
                    } else {
                        // Log a warning if the sent bytes are less than expected
                        syslog(LOG_WARNING, "Sent fewer bytes than expected: %zd instead of %d", sent_udp, config->packet_size);
                    }
                } else {
                    packet_sent += 1;
                }
                
                
                //printf("Sent high-entropy packet id: %d\n", i);
            }

            syslog(LOG_INFO, "High entropy packet sent: %d\n", packet_sent);

            close(urandom_fd);

            break;

        default:
            fprintf(stderr, "Invalid entropy type: %s\n Must be 0 or 1\n", gai_strerror(entropy_type));
            exit(1);
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
        struct ip *iph = (struct ip *)buffer;
        int ip_header_len = iph->ip_hl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + ip_header_len);

        if (tcph->th_flags & TH_RST) {
            gettimeofday(timestamp, NULL);
            syslog(LOG_INFO, " Captured RST pkt (from port %d)\n", ntohs(tcph->th_sport));
            return 1;
        } else {
            syslog(LOG_INFO, " Captured non-RST TCP packet (flags: 0x%02x)\n", tcph->th_flags);
            return 0;  // Or keep looping if you want to wait for an actual RST
        }
        
        gettimeofday(timestamp, NULL);
        syslog(LOG_INFO, "Captured RST pkt\n");
        return 1;
    }

    syslog(LOG_INFO, "Catched nothing before timeout\n");
    return 0;
    
}


// ✅ Then thread function
void *capture_rst_wrapper(void *args_ptr) {
    struct rst_capture_args *args = (struct rst_capture_args *)args_ptr;
    *(args->result_ptr) = capture_rst_pkt(args->socket, args->timestamp);
    return NULL;
}

int main(int argc, char* argv[]){

    openlog("Server", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);

    char* application_ip = "192.168.132.210";

    int port_x = atoi("9999");
    int port_y = atoi("8888");

    int tcp_raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int udp_socket;

    Config config;
    char json_buffer[2048];

    if(argc != 2){
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(1);
    }

    syslog(LOG_INFO, "Loading configuration file...\n\n");

    parse_configfile(argv[1], &config, json_buffer);

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
    sin.sin_addr.s_addr = inet_addr(application_ip);
    //inet_pton(AF_INET, application_ip, &sin.sin_addr);

    pthread_t capture_thread; // ✅ Declare the thread variable

    struct addrinfo *udp_res;
    udp_socket = set_udp_socket(config.server_ip, config.udp_src_port, config.udp_dest_port, &udp_res, &config);

    // int rst1;

     struct timeval low_rst1_time, low_rst2_time, high_rst1_time, high_rst2_time;
    
    // struct rst_capture_args args1 = {
    //     .socket = tcp_raw_socket,
    //     .timestamp = &low_rst1_time,
    //     .result_ptr = &rst1
    // };
    
    
    
    // // ✅ Start capture thread
    // if (pthread_create(&capture_thread, NULL, capture_rst_wrapper, &args1) != 0) {
    //     perror("pthread_create failed");
    //     exit(1);
    // }
    
    // // ✅ Send SYN while the thread is capturing
    // send_syn_pkt(tcp_raw_socket, &sin, port_x, application_ip);
    
    // // ✅ Wait for capture thread to finish
    // pthread_join(capture_thread, NULL);
    
    // // ✅ Check result
    // if (rst1) {
    //     printf("Captured RST at time: %ld.%06ld\n", low_rst1_time.tv_sec, low_rst1_time.tv_usec);
    // } else {
    //     printf("No RST captured.\n");
    // }

    send_syn_pkt(tcp_raw_socket, &sin, port_x, application_ip); //thread1
    send_udp_train(udp_socket, udp_res, 0, &config); //Low entropy
    send_syn_pkt(tcp_raw_socket, &sin, port_y, application_ip); 

    // sleep(15);

    // send_syn_pkt(tcp_raw_socket, &sin, port_x, application_ip);
    // send_udp_train(udp_socket, udp_res, 1, &config); //High entropy
    // send_syn_pkt(tcp_raw_socket, &sin, port_y, application_ip);
    
    //int rst1 = capture_rst_pkt(tcp_raw_socket, &low_rst1_time); //thread 2
    int rst2 = capture_rst_pkt(tcp_raw_socket, &low_rst2_time);
    //int rst3 = capture_rst_pkt(host 192.168.132.210 a_raw_socket, &high_rst1_time);
    //int rst4 = capture_rst_pkt(tcp_raw_socket, &high_rst2_time);


    //if(!rst1 | !rst2 | !rst3 | !rst4)
    

    //long low_entropy_time = time_diff(&low_rst1_time,  &low_rst2_time)
    //long high_entropy_time = time_diff(&high_rst1_time, &high_rst2_time)
    //long diff = high_entropy_time - low_entropy_time;
    //if(diff > 100){ printf("Compression detected!\n") }
    //else{ printf("No Compression detected.\n") }

    close(udp_socket);
    close(tcp_raw_socket);
    return 0;
    

}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <syslog.h>
//#include <cjson/cJSON.h>

#define TCP_PORT "7777"
#define ID_EXTRACT sizeof(uint16_t)
#define COMPRESSION_THRESHOLD 100000 //Threashold for 100ms
#define TIME_OUT 10
#define RECV_BUFFER 16777216

// typedef struct{
//     char server_ip[16];
//     char udp_src_port[6];
//     char udp_dest_port[6];
//     char tcp_head_syn_dest_port[6];
//     char tcp_tail_syn_dest_port[6];
//     char tcp_port_pre_probe[6]; //For part1
//     char tcp_port_post_probe[6]; //For part1
//     int packet_size;
//     int inter_time;
//     int packet_count;
//     int udp_ttl;
// } Config;



// void parse_configfile(const char *json_buffer, Config *config){

//     cJSON *json_parser = cJSON_Parse(json_buffer);
//     if(!json_parser){
//         perror("Error parsing JSON");
//         exit(1);
//     }

//     strcpy(config->server_ip, cJSON_GetObjectItem(json_parser, "server_ip")->valuestring);
//     strcpy(config->udp_src_port, cJSON_GetObjectItem(json_parser, "udp_src_port")->valuestring);
//     strcpy(config->udp_dest_port, cJSON_GetObjectItem(json_parser, "udp_dest_port")->valuestring);
//     strcpy(config->tcp_head_syn_dest_port, cJSON_GetObjectItem(json_parser, "tcp_head_syn_dest_port")->valuestring);
//     strcpy(config->tcp_tail_syn_dest_port, cJSON_GetObjectItem(json_parser, "tcp_tail_syn_dest_port")->valuestring);
//     strcpy(config->tcp_port_pre_probe, cJSON_GetObjectItem(json_parser, "tcp_port_pre_probe")->valuestring);
//     strcpy(config->tcp_port_post_probe, cJSON_GetObjectItem(json_parser, "tcp_port_post_probe")->valuestring);
//     config->packet_size = cJSON_GetObjectItem(json_parser, "packet_size")->valueint;
//     config->inter_time = cJSON_GetObjectItem(json_parser, "inter_time")->valueint;
//     config->packet_count = cJSON_GetObjectItem(json_parser, "packet_count")->valueint;

//     cJSON_Delete(json_parser);

//     syslog(LOG_INFO, "Successfully parsed JSON to struct\n\n");
//     syslog(LOG_INFO, "Server ip: %s\n", config->server_ip);
//     syslog(LOG_INFO, "UDP src port: %s\n", config->udp_src_port);
//     syslog(LOG_INFO, "UDP dest port: %s\n", config->udp_dest_port);
//     syslog(LOG_INFO, "TCP head syn dest port: %s\n", config->tcp_head_syn_dest_port);
//     syslog(LOG_INFO, "TCP tail syn dest port: %s\n", config->tcp_tail_syn_dest_port);
//     syslog(LOG_INFO, "TCP port pre probe: %s\n", config->tcp_port_pre_probe);
//     syslog(LOG_INFO, "TCP port post probe: %s\n", config->tcp_port_post_probe);
//     syslog(LOG_INFO, "Packet Size: %d\n", config->packet_size);
//     syslog(LOG_INFO, "Inter time %d\n", config->inter_time);
//     syslog(LOG_INFO, "Packet count: %d\n\n", config->packet_count);

// }

int server_udp_probing(const char *server_port){
    int udp_socket;
    struct addrinfo hints, *res;
    int addr_info;
    int set_recv_buffer;

    int set_timeout;
    struct timeval timeout;//, current, timeout;
    timeout.tv_sec = TIME_OUT;
    timeout.tv_usec = 0;

    memset(&hints, 0 , sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    addr_info = getaddrinfo(NULL, server_port, &hints, &res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    //Create UDP socket
    udp_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(udp_socket == -1){
        fprintf(stderr, "UDP socket error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    int receive_buffer = RECV_BUFFER;
    set_recv_buffer = setsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    if(set_recv_buffer < 0){
        fprintf(stderr, "Set receive buffer error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    int actual;
    socklen_t optlen = sizeof(actual);
    getsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, &actual, &optlen);
    syslog(LOG_INFO, "Actual receive buffer: %d bytes\n", actual);
    
    // set_timeout = setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    // if(set_timeout < 0){
    //     fprintf(stderr, "UDP set timeout error %s\n", gai_strerror(udp_socket));
    //     exit(1);
    // }


    // int dont_fragment = IP_PMTUDISC_DO;
    // if (setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) < 0) {
    //     perror("Failed to set Don't Fragment flag");
    //     exit(1);
    // }

    int binder = bind(udp_socket, res->ai_addr, res->ai_addrlen);

    if(binder == -1){
        fprintf(stderr, "UDP Bind error %s\n", gai_strerror(binder));
        exit(1);
    }

    freeaddrinfo(res);

    return udp_socket;
}

long calculate_delta_time(struct timeval start, struct timeval end){
    return ((end.tv_sec - start.tv_sec) * 1000000L) + (end.tv_usec - start.tv_usec);
}

long local_time_diff(struct timeval start, struct timeval end) {
    return ((end.tv_sec - start.tv_sec) * 1000000L) + (end.tv_usec - start.tv_usec);
}

int recv_udp_pkt(int udp_socket){//, Config *config
    syslog(LOG_INFO, "Receiving packet train...\n\n");

    char buffer[1000];//config->packet_size
    struct sockaddr_storage client_info;
    socklen_t addr_len = sizeof(client_info);
    int packet_id = 0;
    int first_packet_id = -1;
    int last_packet_id = -1;
    int pkt_count = 0;

    struct timeval start, end, finish;

    while(1){
        ssize_t receiver = recvfrom(udp_socket, buffer, 1000, 0,  (struct sockaddr*)&client_info, &addr_len);//config->packet_count
        if(receiver > 0){
            memcpy(&packet_id, buffer, ID_EXTRACT);
            packet_id = ntohs(packet_id);
            last_packet_id = packet_id;
            pkt_count += 1;
            
        }
        syslog(LOG_INFO, "Packet received: %d, id = %d", pkt_count, packet_id);
    }

}


int main(int argc, char *argv[]){
    char json_buffer[2048];
    char result[64];
    int tcp_socket_pre_probe;
    int tcp_socket_post_probe;
    int udp_socket;
    //Config config;

    openlog("Server", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);

    syslog(LOG_INFO, "Server Start\n");
    syslog(LOG_INFO, "Waiting client connection... \n\n");
    syslog(LOG_INFO, "Setting up UDP socket...\n");

    udp_socket = server_udp_probing("8765");

    syslog(LOG_INFO, "Setting up UDP socket done\n\n");
        
    //Low entropy UDP train

    syslog(LOG_INFO, "Ready to receive UDP packets....\n");

    syslog(LOG_INFO, "Receiveing UDP packets\n");
    long receive = recv_udp_pkt(udp_socket);  //, &config

    //close(client_socket_post_probe);
    close(udp_socket);

    closelog();

    return 0;
}
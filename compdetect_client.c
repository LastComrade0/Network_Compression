#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <cjson/cJSON.h>

#define SERVER_IP "192.168.132.210"  // 192.168.132.210(PC server) or 192.168.64.15(Mac server)

#define ID_EXTRACT sizeof(uint16_t)

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

    //printf("Config loaded: %s\n", json_buffer);

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

    cJSON_Delete(json_parser);

    printf("\nSuccessfully parsed JSON to struct\n\n");
    printf("Server ip: %s\n", config->server_ip);
    printf("UDP src port: %s\n", config->udp_src_port);
    printf("UDP dest port: %s\n", config->udp_dest_port);
    printf("TCP head syn dest port: %s\n", config->tcp_head_syn_dest_port);
    printf("TCP tail syn dest port: %s\n", config->tcp_tail_syn_dest_port);
    printf("TCP port pre probe: %s\n", config->tcp_port_pre_probe);
    printf("TCP port post probe: %s\n", config->tcp_port_post_probe);
    printf("Packet Size: %d\n", config->packet_size);
    printf("Inter time %d\n", config->inter_time);
    printf("Packet count: %d\n\n", config->packet_count);

}

int client_tcp_pre_probing(const char *server_ip, const char *server_port, char *json_buffer){
    printf("TCP pre probing\n");
    int tcp_socket;
    struct addrinfo hint, *res;
    int addr_info;
    char msg[] = "Sending Configuration";
    //char send_json_buffer[2048];
    char buffer[2048];
    
    
    memset(&hint, 0, sizeof(hint));

    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    addr_info = getaddrinfo(server_ip, server_port, &hint, &res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    tcp_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(tcp_socket == -1){
        fprintf(stderr, "TCP socket error %s\n", gai_strerror(tcp_socket));
        exit(1);
    }

    int connector = connect(tcp_socket, res->ai_addr, res->ai_addrlen);

    if(connector == -1){
        fprintf(stderr, "Connect error pre probing %s\n", gai_strerror(connector));
        exit(1);
    }

    //Send message to server
    //send(tcp_socket, msg, strlen(msg), 0);
    //memcpy(send_json_buffer, json_buffer, sizeof(json_buffer));
    send(tcp_socket, json_buffer, strlen(json_buffer), 0);
    
    int bytes_recvd = recv(tcp_socket, buffer, sizeof(buffer) - 1, 0);

    if(bytes_recvd > 0){
        buffer[bytes_recvd] = '\0';
        printf("Received response: %s\n", buffer);
        
    }
    //close(tcp_socket);

    freeaddrinfo(res);
    return tcp_socket;

}

int client_udp_probing(const char *server_ip, const char *src_port, const char* dest_port, struct addrinfo **res){
    printf("UDP probing\n");

    struct addrinfo hints;
    int udp_socket;
    int addr_info;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    //Resolve destination address
    addr_info = getaddrinfo(server_ip, dest_port, &hints, res);

    if(addr_info == -1){
        fprintf(stderr, "Addr_info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    udp_socket = socket((*res)->ai_family, (*res)->ai_socktype, (*res)->ai_protocol);
    
    if(udp_socket == -1){
        fprintf(stderr, "UDP socket error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    int dont_fragment = IP_PMTUDISC_DO;
    if(setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) < 0){
        fprintf(stderr, "UDP socket error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    // //Resolve source address
    // addr_info = getaddrinfo(NULL, src_port, &hints, &res);

    // if(addr_info != 0){
    //     fprintf(stderr, "Source hints to src res error %s\n", gai_strerror(addr_info));
    //     exit(1);
    // }

    //freeaddrinfo(src_res);
    return udp_socket;
}

int send_udp_pkt(int udp_socket, struct addrinfo *server_info, int entropy_type, Config *config){
    char buffer[config->packet_size];
    int packet_id;
    
    switch(entropy_type){
        case 0:
            memset(buffer, 0, config->packet_size);

            printf("Sending low entropy train...\n");
            for(int i = 0; i < config->packet_count; i += 1){
                //printf("Sending packet id: %d\n", i);
                packet_id = htons(i);
                memcpy(buffer, &packet_id, ID_EXTRACT);
                ssize_t sent_udp = sendto(udp_socket, buffer, config->packet_size, 0, server_info->ai_addr, server_info->ai_addrlen);
                if(sent_udp < 0){
                    perror("UDP send error");
                    exit(1);
                }
                //printf("Sent low-entropy packet id: %d\n", i);
            }

            break;

        case 1:

            printf("Sending high entropy udp packet\n");
            
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
                
                if(sent_udp < 0){
                    perror("UDP send error");
                    exit(1);
                }
                
                //printf("Sent high-entropy packet id: %d\n", i);
            }

            close(urandom_fd);

            break;

        default:
            fprintf(stderr, "Invalid entropy type: %s\n Must be 0 or 1\n", gai_strerror(entropy_type));
            exit(1);
    }
}

int client_tcp_post_probing(const char *server_ip, const char *server_port){
    printf("TCP post probing\n");
    int tcp_socket;
    struct addrinfo hint, *res;
    int addr_info;
    char msg[] = "Test request delta_t result";
    char buffer[1024];
    
    
    memset(&hint, 0, sizeof(hint));

    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    addr_info = getaddrinfo(server_ip, server_port, &hint, &res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    tcp_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(tcp_socket == -1){
        fprintf(stderr, "TCP socket error %s\n", gai_strerror(tcp_socket));
        exit(1);
    }

    int connector = connect(tcp_socket, res->ai_addr, res->ai_addrlen);

    if(connector == -1){
        fprintf(stderr, "Connect error post probing%s\n", gai_strerror(connector));
        exit(1);
    }

    send(tcp_socket, msg, strlen(msg), 0);
    
    int bytes_recvd = recv(tcp_socket, buffer, sizeof(buffer) - 1, 0);

    if(bytes_recvd > 0){
        buffer[bytes_recvd] = '\0';
        printf("Received response from server: %s\n", buffer);
        
    }
    //close(tcp_socket);

    sleep(3);

    freeaddrinfo(res);
    return tcp_socket;
}


int main(int argc, char *argv[]){
    int tcp_socket_pre_probe, tcp_socket_post_probe;
    int udp_socket;
    Config config;
    char json_buffer[2048];

    if(argc != 2){
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(1);
    }

    printf("Loading configuration file...\n");

    parse_configfile(argv[1], &config, json_buffer);

    printf("Client\n");

    printf("\nJson buffer successfully passed on\n\n");
    printf("%s\n", json_buffer);
    
    tcp_socket_pre_probe = client_tcp_pre_probing(config.server_ip, config.tcp_port_pre_probe, json_buffer);
    
    close(tcp_socket_pre_probe);

    sleep(1);

    struct addrinfo *udp_res;
    udp_socket = client_udp_probing(config.server_ip, config.udp_src_port, config.udp_dest_port, &udp_res);

    send_udp_pkt(udp_socket, udp_res, 0, &config);//Send Low entropy

    printf("Done sending low entropy UDP packet train\n");
    printf("Wait...\n\n");

    sleep(27);

    send_udp_pkt(udp_socket, udp_res, 1, &config);//Send High entropy

    freeaddrinfo(udp_res);

    close(udp_socket);

    printf("Done sending high entropy UDP packet train\n");
    printf("Wait...\n\n");

    sleep(20);

    printf("Client: Reconnecting to server for result (Post-Probing Phase)...\n");
    tcp_socket_post_probe = client_tcp_post_probing(config.server_ip, config.tcp_port_post_probe);

    //char result[64];
    // recv(tcp_socket, result, sizeof(result), 0);
    // printf("Server response: %s\n", result);
    

    

    close(tcp_socket_post_probe);
    

    return 0;
}
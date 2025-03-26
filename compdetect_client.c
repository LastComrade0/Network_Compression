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
#include <syslog.h>
#include <cjson/cJSON.h>

#define ID_EXTRACT sizeof(uint16_t)

/**
 * @struct Config
 * @brief Configs parsed and loaded from JSON configuration
 *
 * Contains the source address, destination address, UDP source port, UDP destination port,
 * tcp head syn destination port, tcp tail syn destination port, packet size,
 * intermeasure time, packet count, and time to live for UDP packet for this program
 * used in the major setting for address and settings for TCP UDP socket.
 */
typedef struct{
    char src_ip[16];
    char dest_ip[16];
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

/*
 * Function: parse_config_fileZ
 * ----------------------------
 * Open JSON file and parse to put data onto Config struct
 *
 * *json_file: Char pointer for file name
 * *config: Struct for config to be updated
 * *json_buffer: Char buffer for copying JSON text from json file to buffer
 *
 * returns: None but config struct pointer will be updated
 */
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
    

    strcpy(config->dest_ip, cJSON_GetObjectItem(json_parser, "dest_ip")->valuestring);
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

    syslog(LOG_INFO, "Successfully parsed JSON to struct\n\n");
    syslog(LOG_INFO, "Dest ip: %s\n", config->dest_ip);
    syslog(LOG_INFO, "UDP src port: %s\n", config->udp_src_port);
    syslog(LOG_INFO, "UDP dest port: %s\n", config->udp_dest_port);
    syslog(LOG_INFO, "TCP head syn dest port: %s\n", config->tcp_head_syn_dest_port);
    syslog(LOG_INFO, "TCP tail syn dest port: %s\n", config->tcp_tail_syn_dest_port);
    syslog(LOG_INFO, "TCP port pre probe: %s\n", config->tcp_port_pre_probe);
    syslog(LOG_INFO, "TCP port post probe: %s\n", config->tcp_port_post_probe);
    syslog(LOG_INFO, "Packet Size: %d\n", config->packet_size);
    syslog(LOG_INFO, "Inter time %d\n", config->inter_time);
    syslog(LOG_INFO, "Packet count: %d\n\n", config->packet_count);

}

/*
 * Function: client_pre_probing_tcp
 * ----------------------------
 * TCP pre probing for sending json data to server
 *
 * *dest_ip: Destination IP
 * *server_port: Server Port
 * *json_buffer: Char buffer for copying JSON text from json file to buffer
 *
 * returns: None but config struct pointer will be updated
 */
int client_tcp_pre_probing(const char *dest_ip, const char *server_port, char *json_buffer){
    syslog(LOG_INFO, "TCP pre probing\n");
    int tcp_socket;
    struct addrinfo hint, *res;
    int addr_info;
    char msg[] = "Sending Configuration";
    //char send_json_buffer[2048];
    char buffer[2048];
    
    
    memset(&hint, 0, sizeof(hint)); //Fill hint addrinfo all 0

    hint.ai_family = AF_INET; //Set IPv4
    hint.ai_socktype = SOCK_STREAM; //Set TCP

    //Prepare server address info
    addr_info = getaddrinfo(dest_ip, server_port, &hint, &res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    //Set TCP socket
    tcp_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(tcp_socket == -1){
        fprintf(stderr, "TCP socket error %s\n", gai_strerror(tcp_socket));
        exit(1);
    }

    //Connect to server
    int connector = connect(tcp_socket, res->ai_addr, res->ai_addrlen);

    if(connector == -1){
        fprintf(stderr, "Connect error pre probing %s\n", gai_strerror(connector));
        exit(1);
    }

    //Send message to server
    send(tcp_socket, json_buffer, strlen(json_buffer), 0);
    
    //Receive server response message
    int bytes_recvd = recv(tcp_socket, buffer, sizeof(buffer) - 1, 0);

    if(bytes_recvd > 0){
        buffer[bytes_recvd] = '\0';
        syslog(LOG_INFO, "Received response: %s\n", buffer);
        
    }

    freeaddrinfo(res); //Free address info
    return tcp_socket; //Return TCP socket descriptor

}

/*
 * Function: server_udp_probing
 * ----------------------------
 * UDP probing for setting up UDP socket
 *
 * *dest_ip: Destination IP
 * *src_port: Port for source
 * *dest_port: Port for destination
 * **res: Address info resolution
 * 
 *
 * returns: UDP socket file descriptor
 */
int client_udp_probing(const char *dest_ip, const char *src_port, const char* dest_port, struct addrinfo **res){
    syslog(LOG_INFO, "UDP probing\n");

    struct addrinfo hints;
    int udp_socket;
    int addr_info;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    //Resolve destination address
    addr_info = getaddrinfo(dest_ip, dest_port, &hints, res);

    if(addr_info == -1){
        fprintf(stderr, "Addr_info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    //Create UDP socket
    udp_socket = socket((*res)->ai_family, (*res)->ai_socktype, (*res)->ai_protocol);
    
    if(udp_socket == -1){
        fprintf(stderr, "UDP socket error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    //Set don't fragment
    int dont_fragment = IP_PMTUDISC_DO;
    if(setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) < 0){
        fprintf(stderr, "UDP socket error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    return udp_socket; //Return UDP socket descriptor
}

/*
 * Function: send_udp_pkt
 * ----------------------------
 * Send udp packet train based on entropy type input
 *
 * udp_socket: Socket descriptor for UDP socket
 * *server_info: Address info for server
 * entropy_type: Entropy type 0 or 1
 * config: Configurations
 *
 * returns: nothing but should send UDP packet train based on entropy type
 */
void send_udp_pkt(int udp_socket, struct addrinfo *server_info, int entropy_type, Config *config){
    char buffer[config->packet_size]; //Char buffer for sending UDP payload
    int packet_id;
    int packet_sent = 0;
    
    //Switch case: 0 for low entropy and 1 for high entropy
    switch(entropy_type){
        case 0:
            memset(buffer, 0, config->packet_size); //Fill payload buffer to all 0(low entropy)

            //Loop times based on packet count
            syslog(LOG_INFO, "Sending low entropy train...\n");
            for(int i = 0; i < config->packet_count; i += 1){
                //printf("Sending packet id: %d\n", i);
                packet_id = htons(i); //Packet ID by i
                memcpy(buffer, &packet_id, ID_EXTRACT); //Replace 1st 4 bytes of payload to packet ID
                ssize_t sent_udp = sendto(udp_socket, buffer, config->packet_size, 0, server_info->ai_addr, server_info->ai_addrlen); //Send UDP packet
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
            
            //Open urandom
            int urandom_fd = open("/dev/urandom", O_RDONLY);

            if(urandom_fd < 0){
                fprintf(stderr, "Urandom open error: %s\n Must be 0 or 1\n", gai_strerror(urandom_fd));
                exit(1);
            }

            //Loop times based on packet count
            for(int i = 0; i < config->packet_count; i += 1){
                packet_id = htons(i); //Packet ID by i
                memcpy(buffer, &packet_id, ID_EXTRACT); //Replace 1st 4 bytes of payload to packet ID

                //Copy generated random bytes to buffer starting from 5th char bytes
                ssize_t urandom_read = read(urandom_fd, buffer + ID_EXTRACT, config->packet_size - ID_EXTRACT);


                if(urandom_read < 0){
                    perror("Error opening /dev/urandom");
                    close(urandom_fd);
                    exit(1);
                }
                
                //Send UDP packet
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
                
                
            }

            syslog(LOG_INFO, "High entropy packet sent: %d\n", packet_sent);

            close(urandom_fd); //Close urandom read

            break;

        default:
            fprintf(stderr, "Invalid entropy type: %s\n Must be 0 or 1\n", gai_strerror(entropy_type));
            exit(1);
    }
}

/*
 * Function: client_post_probing_tcp
 * ----------------------------
 * Sends TCP request for server to send back result
 * 
 * dest_ip: Destination IP
 * server_port: TCP port for server
 *
 * returns: TCP post probe socket descriptor
 */
int client_tcp_post_probing(const char *dest_ip, const char *server_port){
    syslog(LOG_INFO, "TCP post probing\n");
    int tcp_socket;
    struct addrinfo hint, *res;
    int addr_info;
    char msg[] = "Test request delta_t result";
    char buffer[1024];
    
    
    memset(&hint, 0, sizeof(hint)); //Fill hint addrinfo all 0

    hint.ai_family = AF_INET; //Set IPv4
    hint.ai_socktype = SOCK_STREAM; //Set TCP

    //Prepare server address info
    addr_info = getaddrinfo(dest_ip, server_port, &hint, &res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    //Set TCP socket
    tcp_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(tcp_socket == -1){
        fprintf(stderr, "TCP socket error %s\n", gai_strerror(tcp_socket));
        exit(1);
    }

    /*While loop until connection established*/
    while(1){
        int connector = connect(tcp_socket, res->ai_addr, res->ai_addrlen);

        if(connector == 0){
            syslog(LOG_INFO, "Successfully connected to TCP post probe server\n");
            break;
        }
        else if(connector == -1){
            syslog(LOG_INFO, "Server not yet open post probing TCP port, waiting for 10 seconds..");
            sleep(10);
            continue;
        }
        else{
            fprintf(stderr, "TCP post probe connect error %s\n", gai_strerror(connector));
            exit(1);
        }
    }
    
    //Send message to server
    send(tcp_socket, msg, strlen(msg), 0);
    
    //Receive reply from server
    int bytes_recvd = recv(tcp_socket, buffer, sizeof(buffer) - 1, 0);

    if(bytes_recvd > 0){
        buffer[bytes_recvd] = '\0';
        syslog(LOG_INFO, "Received response from server: %s\n", buffer);
        
    }
    //close(tcp_socket);

    freeaddrinfo(res); //Free address info
    return tcp_socket; //Return TCP post probe socket descriptor
}

/*
 * main - Starting Client.
 *        Sets up TCP pre probing socket and UDP sockets, parses received json text from 
 *        JSON file, send UDP packet train, set up TCP post probing, get results from server
 */
int main(int argc, char *argv[]){
    int tcp_socket_pre_probe, tcp_socket_post_probe; //Socket descriptors for pre/post TCP socket
    int udp_socket; //Set Socket descriptor for UDP socket
    Config config; //Config struct 
    char json_buffer[2048]; //Json text parsed buffer

    //Comment out to now showing logging on terminal
    openlog("Server", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);

    /*Terminate if no argument for JSON file name*/
    if(argc != 2){
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(1);
    }

    syslog(LOG_INFO, "Loading configuration file...\n\n");

    //Parse read json buffer text to config struct
    parse_configfile(argv[1], &config, json_buffer);

    syslog(LOG_INFO, "Client\n\n");

    syslog(LOG_INFO, "Json buffer successfully passed on\n\n");
    syslog(LOG_INFO, "%s\n", json_buffer);
    
    //Set up pre probing TCP, sending JSON configuration to server
    tcp_socket_pre_probe = client_tcp_pre_probing(config.dest_ip, config.tcp_port_pre_probe, json_buffer);
    
    close(tcp_socket_pre_probe);

    sleep(1);//Static slight wait for server setting up UDP port

    struct addrinfo *udp_res;
    //Set up UDP socket 
    udp_socket = client_udp_probing(config.dest_ip, config.udp_src_port, config.udp_dest_port, &udp_res);

    //Send low entropy UDP packet train function
    send_udp_pkt(udp_socket, udp_res, 0, &config);//Send Low entropy

    syslog(LOG_INFO, "Done sending low entropy UDP packet train\n");
    syslog(LOG_INFO, "Wait for %d seconds\n\n", config.inter_time + 12);

    sleep(config.inter_time + 12);

    //Send low entropy UDP packet train function
    send_udp_pkt(udp_socket, udp_res, 1, &config);//Send High entropy

    freeaddrinfo(udp_res); //Free address info

    close(udp_socket); //Close UDP socket

    syslog(LOG_INFO, "Done sending high entropy UDP packet train\n");
    syslog(LOG_INFO, "Wait...\n\n");

    syslog(LOG_INFO, "Client: Reconnecting to server for result (Post-Probing Phase)...\n");
    
    //Set up post probing TCP, receives result from server
    tcp_socket_post_probe = client_tcp_post_probing(config.dest_ip, config.tcp_port_post_probe);

    close(tcp_socket_post_probe); //Close TCP post probe socket
    

    return 0;
}
//#define __USE_BSD	/* use bsd'ish ip header */
//#define __FAVOR_BSD	/* use bsd'ish tcp header */

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
#define OPT_SIZE 20
#define DATAGRAM_LEN 4096

//Lock, Condition, and procedure for low and high entropy train
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int ready = 0; 


/**
 * @struct Pseudo Header
 * @brief Pseudo header for check sum in TCP layer
 *
 * Contains the source address, destination address, reserved field,
 * protocol, and tcp length
 * used in the check sum for TCP layer.
 */
struct pseudo_header{
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint32_t tcp_length;
};

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
    char tcp_head_syn_dest_port[6]; //For part 2
    char tcp_tail_syn_dest_port[6]; //For part 2
    char tcp_port_pre_probe[6]; //For part 1
    char tcp_port_post_probe[6]; //For part 1
    int packet_size;
    int inter_time;
    int packet_count;
    int udp_ttl; //For part 2

    
} Config;

/**
 * @struct MultithreadingArgs
 * @brief Argument struct to pass data when conducting multi threading
 *
 * Contains the source address, destination address, port x/y, udp res, config
 * 4 time stamps(2 for low entropy train and 2 for high entropy train)
 * used to pass data when conducting multi threading.
 */
typedef struct { 
    int tcp_raw_socket;
    int udp_socket;
    struct sockaddr_in src_addr;
    struct sockaddr_in dest_addr;
    int port_x;
    int port_y;
    struct addrinfo *udp_res;
    Config* config;
    struct timeval* low_rst1_time;
    struct timeval* low_rst2_time;
    struct timeval* high_rst1_time;
    struct timeval* high_rst2_time;

} MultithreadingArgs;

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

    fread(json_buffer, 1, file_size, file); //Read file and copy all text to buffer
    json_buffer[file_size] = '\0';
    fclose(file);

    //Parse JSON from read json buffer
    cJSON *json_parser = cJSON_Parse(json_buffer);
    if(!json_parser){
        perror("Error parsing JSON");
        exit(1);
    }
    
    //Parsed json object to corresponding struct data
    strcpy(config->src_ip, cJSON_GetObjectItem(json_parser, "src_ip")->valuestring);
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
    config->udp_ttl = cJSON_GetObjectItem(json_parser, "udp_ttl")->valueint;

    cJSON_Delete(json_parser); //Destroy parse as done parsing
    
    syslog(LOG_INFO, "Successfully parsed JSON to struct\n\n");
    syslog(LOG_INFO, "Src ip: %s\n", config->src_ip);
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
    syslog(LOG_INFO, "UDP ttl: %d\n\n", config->udp_ttl);

}

/*
 * Function: time_diff
 * ---------------------------
 * Calculate time interval between TCP head syn rst and TCP tail syn rst
 *
 * start:   Head rst received time stamp 
 * end:     Sequence number used to identify the probe
 * 
 * returns: Time interval between 2 rst packets of a train
 */
long time_diff(struct timeval start, struct timeval end) {
    return ((end.tv_sec - start.tv_sec) * 1000000L) + (end.tv_usec - start.tv_usec);
}

/*
 * Function: check_sum
 * ---------------------------
 * Check sum for IP header and TCP header
 *
 * buffer: Char buffer for pseudogram for TCP or IP
 * size: Size of buffer for pseudogram
 * 
 * returns: Check sum value later to be received by dest and dest will check if 
 * this value is identical to their calculation
 */
unsigned short check_sum(const char *buffer, unsigned size){
    unsigned long sum = 0, i;
    for(i = 0; i < size - 1; i += 2){
        unsigned short word16 = *(unsigned short*) &buffer[i];
        sum += word16;
    }

    if(size & 1){
        unsigned short word16 = (unsigned char)buffer[i];
        sum += 16;
    }

    while (sum >> 16) {
        uint16_t lower_16 = sum & 0xFFFF;     // Get the lowest 16 bits
        uint16_t carry = sum >> 16;           // Get the upper 16 bits (carry)
        sum = lower_16 + carry;               // Add them together
    }

    return ~sum;
}

/*
 * Function: send_syn_pkt
 * ---------------------------
 * Send TCP syn packet
 *
 * socket: Socket fd for TCP raw socket
 * *src: Source address info
 * *dest: Destination address info
 * dest_port: Destination port
 * 
 * returns: None but a syn packet should be sent
 */
void send_syn_pkt(int socket, struct sockaddr_in *src, struct sockaddr_in *dest, int dest_port){
    char datagram[DATAGRAM_LEN];

    struct iphdr *iph = (struct iphdr*)datagram; //IP header
    struct tcphdr *tcpheader = (struct tcphdr*)(datagram + sizeof(struct iphdr)); //TCP header
    struct pseudo_header psh; //Pseudo header for TCP checksum

    memset(datagram, 0, DATAGRAM_LEN); //Initialize entire datagram buffer to 0

    //Set all relative field for IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE; //No payload
    iph->id = htonl(rand() % 65535); //Value does not matter
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP; //Which is 6
    iph->check = 0;
    iph->saddr = src->sin_addr.s_addr;
    iph->daddr = dest->sin_addr.s_addr;

    //Set all relative field for TCP header
    tcpheader->source = src->sin_port; //Arbitrary port 7777
    tcpheader->dest = htons(dest_port); //x or y port
    tcpheader->seq = htonl(rand() % 4294967295);
    tcpheader->ack_seq = htonl(0);
    tcpheader->doff = 10; //TCP header size
    tcpheader->fin = 0;
    tcpheader->syn = 1;
    tcpheader->rst = 0;
    tcpheader->psh = 0;
    tcpheader->ack = 0;
    tcpheader->urg = 0;
    tcpheader->check = 0;
    tcpheader->th_win = htons(500); //Max allowed window size
    tcpheader->urg_ptr = 0;

    //TCP pseudo header for checksum
    psh.src_addr = src->sin_addr.s_addr;
    psh.dest_addr = dest->sin_addr.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
    int psize =  sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE; //Size of pseudo header of sum of pseudo header, TCP header, and opt size

    //Fill pseudo packet
    char *pseudogram = malloc(psize); //Char buffer with psize
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header)); //Put pseudo header
    memcpy(pseudogram + sizeof(struct pseudo_header), tcpheader, sizeof(struct tcphdr) + OPT_SIZE); //Put 
    
    // TCP options are only set in the SYN packet
	// ---- set mss ----
	datagram[40] = 0x02;
	datagram[41] = 0x04;
	int16_t mss = htons(48); // mss value
	memcpy(datagram + 42, &mss, sizeof(int16_t));
	// ---- enable SACK ----
	datagram[44] = 0x04;
	datagram[45] = 0x02;
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x04;
	pseudogram[37] = 0x02;

    tcpheader->th_sum = check_sum((const char*)pseudogram, psize); //Check sum for TCP header and put it in checksum field
    iph->check = check_sum((const char*) datagram, iph->tot_len); //Same as TCP check sum
    

    
    int one = 1;
    const int *val = &one;
    int set_HDRINCL = setsockopt(socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)); //Set option for IP being self assigned
    if(set_HDRINCL < 0){
        syslog(LOG_INFO, "Warning: Unable to set HDRINCL!\n");
    }


    int send_syn = sendto(socket, datagram, iph->tot_len, 0, (struct sockaddr *) dest, sizeof(struct sockaddr)); //Send SYN packet
    if(send_syn <= 0){
        syslog(LOG_PERROR, "Error: Unable to send syn! %d\n", send_syn);
        exit(1);
    }
    
}

/*
 * Function: set_udp_socket
 * ---------------------------
 * Setting up UDP socket
 *
 * *application_ip: Source ip as application side
 * *src_port: Source port
 * *dest_port: Destination port
 * addr_info: Address info for destination
 * config: Configurations
 * 
 * returns: File descriptor for UDP socket
 */
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

    //Create udp socket
    udp_socket = socket((*res)->ai_family, (*res)->ai_socktype, (*res)->ai_protocol);
    
    if(udp_socket == -1){
        fprintf(stderr, "UDP socket error %s\n", strerror(errno));
        exit(1);
    }

    //Set don't fragment
    int dont_fragment = IP_PMTUDISC_DO;
    if(setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) < 0){
        fprintf(stderr, "UDP don't fragment error %s\n", strerror(errno));
        exit(1);
    }

    //Set time to live
    int ttl = config->udp_ttl;
    int set_ttl = setsockopt(udp_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if(set_ttl < 0){
        fprintf(stderr, "UDP set ttl error %s\n", strerror(errno));
        exit(1);
    }
    

    syslog(LOG_INFO, "Successfully set UDP socket\n");
    return udp_socket;
}

/*
 * Function: send_udp_train
 * ---------------------------
 * Send UDP packet train given size from configuration
 *
 * upd_socket:   Head rst received time stamp 
 * end:     Sequence number used to identify the probe
 * 
 * returns: Time interval between 2 rst packets of a train
 */
void send_udp_train(int udp_socket, struct addrinfo *server_info, int entropy_type, Config *config){
    char buffer[config->packet_size];
    int packet_id;
    int packet_sent = 0;
    
    switch(entropy_type){
        case 0:
            memset(buffer, 0, config->packet_size);

            //syslog(LOG_INFO, "Sending low entropy train...\n");
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

            }


            break;

        case 1:

            //syslog(LOG_INFO, "Sending high entropy udp packet\n");
            
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
                
                
            }

            close(urandom_fd);

            break;

        default:
            fprintf(stderr, "Invalid entropy type: %s\n Must be 0 or 1\n", gai_strerror(entropy_type));
            exit(1);
    }
}

/*
 * Function: capture_rst_pkt
 * ---------------------------
 * Capture rst packet from destination
 *
 * socket:   TCP raw socket
 * timestamp:     Time stamp struct for recording time when rst packet captured
 * expected_ip_from_dest: Expected ip from destination
 * expected_port_from_dest: Expected port from destination
 * 
 * returns: 1 as success capture and 0 for timeout
 */
int capture_rst_pkt(int socket, struct timeval *timestamp, uint32_t expected_ip_from_dest, uint16_t expected_port_from_dest){


    struct timeval start, now;//Recording timestamps for start time and current time
    gettimeofday(&start, NULL);//Record start time

    while (1) {
        // Calculate remaining time (10s timeout)
        gettimeofday(&now, NULL);
        long elapsed_us = ((now.tv_sec - start.tv_sec) * 1000000L) + (now.tv_usec - start.tv_usec); //How many micro seconds passed
        long remaining_us = 10 * 1000000L - elapsed_us; //Current remaining micro seconds since loop starts
        //Break the loop when remaining micro second reaches 0 AKA time out
        if (remaining_us <= 0){
            break;
        }

        //Set timeout for select() as it is inner timeout
        struct timeval timeout;
        timeout.tv_sec = remaining_us / 1000000L; //Updated by remaining microsecond
        timeout.tv_usec = remaining_us % 1000000L;

        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(socket, &fd);

        int ret = select(socket + 1, &fd, NULL, NULL, &timeout); //So blocking receiving will only be shorter as a new loop goes in where remaining_us becomes smaller
        if (ret <= 0) {
            break;  // timeout or error
        }

        char buffer[4096];
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        //Receive rst packet
        ssize_t recv_len = recvfrom(socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen); //Capture any possible packet
        if (recv_len <= 0) {
            continue;
        }

        struct ip *iph = (struct ip *)buffer;
        int ip_header_len = iph->ip_hl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + ip_header_len);

        //Check iff flag is rst and dest ip+port is correct
        if ((tcph->th_flags & TH_RST) &&
            iph->ip_src.s_addr == expected_ip_from_dest &&
            tcph->dest == expected_port_from_dest) {

            gettimeofday(timestamp, NULL);
            return 1;
        }
    }

    syslog(LOG_WARNING, "Catched nothing before timeout\n");
    return 0;
    
}

/*
 * Function: capture_thread_function
 * ---------------------------
 * Function for capturing rst packet in multit hreading
 *
 * *p: Void pointer to pass argument struct
 * 
 * returns: None but should run in concurrency
 */
void *capture_thread_function(void *p){
    syslog(LOG_INFO, "Capturing 1st set of rst...\n");
    MultithreadingArgs *args = (MultithreadingArgs*)p; //Set structs for arguments

    int tcp_raw_socket = args->tcp_raw_socket;

    //Lock and unlock to signal send thread function to go on. Procedure for low entropu train
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);

    int rst1 = capture_rst_pkt(args->tcp_raw_socket, args->low_rst1_time, args->dest_addr.sin_addr.s_addr, args->src_addr.sin_port);

    int rst2 = capture_rst_pkt(args->tcp_raw_socket, args->low_rst2_time, args->dest_addr.sin_addr.s_addr, args->src_addr.sin_port);

    //Check if rst1 and rst2 actually captured rst packet
    if(!rst1 | !rst2){
        syslog(LOG_PERROR, "Captured non rst pkt or timed out");
        printf("Failed to detect due to insufficient information.\n");
        exit(1);
    }

    syslog(LOG_INFO, "Waiting for inter-measure time...\n");
    sleep(args->config->inter_time); //Inter-measure time set by config

    //Procedure for high entropy train
    syslog(LOG_INFO, "Capturing 2nd set of rst...\n");
    pthread_mutex_lock(&lock);
    ready = 2;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);

    int rst3 = capture_rst_pkt(args->tcp_raw_socket, args->high_rst1_time, args->dest_addr.sin_addr.s_addr, args->src_addr.sin_port);

    int rst4 = capture_rst_pkt(args->tcp_raw_socket, args->high_rst2_time, args->dest_addr.sin_addr.s_addr, args->src_addr.sin_port);

    if(!rst3 | !rst4){
        syslog(LOG_PERROR, "Captured non rst pkt or timed out");
        printf("Failed to detect due to insufficient information.\n");
        exit(1);
    }

}

/*
 * Function: send_thread_function
 * ---------------------------
 * Send head SYN TCP packet, send UDP train, then send Tail SYN when done UDP train
 *
 * *p: Void pointer to pass argument struct
 * 
 * returns: None but should run concurrently
 */
void *send_thread_function(void *p){
    MultithreadingArgs *args = (MultithreadingArgs*)p; //Set Struct for arguments

    //Wait and proceed after recv function being called for low UDP train
    pthread_mutex_lock(&lock);
    while(ready < 1){
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    send_syn_pkt(args->tcp_raw_socket, &(args->src_addr), &(args->dest_addr), args->port_x);
    send_udp_train(args->udp_socket, args->udp_res, 0, args->config);
    send_syn_pkt(args->tcp_raw_socket, &(args->src_addr), &(args->dest_addr), args->port_y);
    
    //Wait and proceed after recv function being called for high UDP train
    pthread_mutex_lock(&lock);
    while(ready < 2){
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    send_syn_pkt(args->tcp_raw_socket, &(args->src_addr), &(args->dest_addr), args->port_x);
    send_udp_train(args->udp_socket, args->udp_res, 1, args->config);
    send_syn_pkt(args->tcp_raw_socket, &(args->src_addr), &(args->dest_addr), args->port_y);
}


int main(int argc, char* argv[]){

    openlog("Server", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);

    Config config;
    char json_buffer[2048];

    if(argc != 2){
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(1);
    }

    syslog(LOG_INFO, "Loading configuration file...\n\n");

    parse_configfile(argv[1], &config, json_buffer);

    char* src_ip = config.src_ip;
    char* dest_ip = config.dest_ip;

    int port_x = atoi(config.tcp_head_syn_dest_port);
    int port_y = atoi(config.tcp_tail_syn_dest_port);

    int tcp_raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int udp_socket;

    

    if(tcp_raw_socket < 0){
        syslog(LOG_ERR, "Unable to create TCP raw socket: %d", tcp_raw_socket);
        exit(1);
    }

    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    //dest_addr.sin_port = htons(0);
    int set_dest_addr = inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);
    if(set_dest_addr != 1){
        syslog(LOG_INFO, "Dest ip configuration failed");
        return 1;
    }
    

    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(atoi(config.tcp_port_pre_probe));//rand() % 65535
    int set_src_addr = inet_pton(AF_INET, src_ip, &src_addr.sin_addr);
    if(set_src_addr != 1){
        syslog(LOG_INFO, "Src ip configuration failed");
        return 1;
    }

    int self_ip_enable = 1;
    int set_self_ip = setsockopt(tcp_raw_socket, IPPROTO_IP, IP_HDRINCL, &self_ip_enable, sizeof(self_ip_enable));
    if(set_self_ip < 0){
        syslog(LOG_ERR, "Error setting IP_HDRINCL: Unable to enable self ip header");
        exit(1);
    }

    struct addrinfo *udp_res;
    udp_socket = set_udp_socket(config.dest_ip, config.udp_src_port, config.udp_dest_port, &udp_res, &config);

    struct timeval low_rst1_time, low_rst2_time, high_rst1_time, high_rst2_time;

    //Multithreading
    pthread_t capture_thread;
    pthread_t send_thread;

    MultithreadingArgs args;
    args.tcp_raw_socket = tcp_raw_socket;
    args.udp_socket = udp_socket;
    args.src_addr = src_addr;
    args.dest_addr = dest_addr;
    args.udp_res = udp_res;
    args.port_x = port_x;
    args.port_y = port_y;
    args.config = &config;
    args.low_rst1_time = &low_rst1_time;
    args.low_rst2_time = &low_rst2_time;
    args.high_rst1_time = &high_rst1_time;
    args.high_rst2_time = &high_rst2_time;

    pthread_create(&capture_thread, NULL, capture_thread_function, &args);
    pthread_create(&send_thread, NULL, send_thread_function,&args);

//dest_addr.sin_addr.s_addr = inet_addr(dest_ip);
    //inet_pton(AF_INET, application_ip, &sin.sin_addr);
    pthread_join(capture_thread, NULL);
    pthread_join(send_thread, NULL);

    pthread_mutex_destroy(&lock);
    pthread_cond_destroy(&cond);

    long low_entropy_time = time_diff(low_rst1_time,  low_rst2_time);
    long high_entropy_time = time_diff(high_rst1_time, high_rst2_time);
    long diff = labs(high_entropy_time - low_entropy_time);

    syslog(LOG_INFO, "Low entropy time: %ld", low_entropy_time);
    syslog(LOG_INFO, "High entropy time: %ld", high_entropy_time);
    syslog(LOG_INFO, "Difference: %ld", diff);

    if(diff/1000 > 100){
        printf("Compression detected!\n"); 
    }
    else{ 
        printf("No Compression detected.\n");
    }

    close(udp_socket);
    close(tcp_raw_socket);
    return 0;
    

}


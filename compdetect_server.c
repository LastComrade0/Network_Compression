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

#define TCP_PORT "7777"
#define TCP_PORT_POST_PROBE "6666"
#define UDP_PORT "8765"
#define PACKET_SIZE 1000
#define NUM_PACKETS 6000
#define ID_EXTRACT sizeof(uint16_t)
#define INTER_MEASUREMENT_TIME 15
#define COMPRESSION_THRESHOLD 100000 //Threashold for 100ms
#define TIME_OUT 10
#define RECV_BUFFER 16777216;


volatile sig_atomic_t timeout_flag = 0;

int server_pre_probing_tcp(const char *server_port){
    int tcp_socket, new_fd;
    struct addrinfo hint, *res;
    int addr_info;//server_pro;
    struct sockaddr_storage client_addr;
    char buffer[2048];
    
    
    memset(&hint, 0, sizeof(hint)); //Fill hint addrinfo all 0

    hint.ai_family = AF_INET; //Set IPv4
    hint.ai_socktype = SOCK_STREAM; //Set TCP
    hint.ai_flags = AI_PASSIVE; //On server to enable bind()/listen()/accept() on returned address

    //Prepare server address info
    addr_info = getaddrinfo(NULL, server_port, &hint, &res);

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

    //Bind socket to this address
    int binder = bind(tcp_socket, res->ai_addr, res->ai_addrlen);

    if(binder == -1){
        fprintf(stderr, "Bind error %s\n", gai_strerror(binder));
        exit(1);
    }

    //Listen to client
    int listener = listen(tcp_socket, 10);

    if(listener == -1){
        fprintf(stderr, "Listen error %s\n", gai_strerror(listener));
        exit(1);
    }

    printf("Server listening to client TCP pre probing...\n");

    socklen_t addr_size = sizeof(client_addr);
    new_fd = accept(tcp_socket, (struct sockaddr*)&client_addr, &addr_size);

    if(new_fd== -1){
        perror("accept error");
        exit(1);
    }
    
    int bytes_recvd = recv(new_fd, buffer, sizeof(buffer), 0);

    if(bytes_recvd == -1){
        perror("Receive error");
        exit(1);
    }

    else if(bytes_recvd > 0){
        printf("Byte received: %d\n", bytes_recvd);
        buffer[bytes_recvd] = '\0';
        printf("Received buffer: %s\n", buffer);

        char response[1024];
        strcpy(response, "Configuration received");
        send(new_fd, buffer, sizeof(response), 0);
    }

    close(new_fd);
    //close(tcp_socket);

    //Free address info resolve
    freeaddrinfo(res);
    printf("Server accepted tcp: %d\n\n", tcp_socket);
    return tcp_socket;

}

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
    
    set_timeout = setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if(set_timeout < 0){
        fprintf(stderr, "UDP set timeout error %s\n", gai_strerror(udp_socket));
        exit(1);
    }


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

int recv_udp_pkt(int udp_socket){
    printf("Receiving packet train...\n");

    char buffer[PACKET_SIZE];
    struct sockaddr_storage client_info;
    socklen_t addr_len = sizeof(client_info);
    int packet_id = 0;
    int first_packet_id = -1;
    int last_packet_id = -1;
    int pkt_count = 0;

    struct timeval start, end;
    
    // Register SIGALRM handler
    //signal(SIGALRM, catch_alarm);

    // Start the collective timeout
    //alarm(TIME_OUT);
    
    
    ssize_t first_udp_receive = recvfrom(udp_socket, buffer, PACKET_SIZE, 0, (struct sockaddr*)&client_info, &addr_len);
    
    gettimeofday(&start, NULL);
    if(first_udp_receive == -1){
        perror("First UDP packet failed to receive");
        exit(1);
    }

    pkt_count += 1;

    //1st 16 bits are pkt id and rest is entropy data
    //So memcpy 1st 16 bits of buffer defined by 4
    memcpy(&packet_id, buffer, ID_EXTRACT); 

    first_packet_id = packet_id;
    last_packet_id = packet_id;

    for(int i = 0; i < NUM_PACKETS; i += 1){
        //printf("pkt: %d ", i);
        //printf("Pkt id receiving: %d\n", pkt_count);

        //gettimeofday(&current, NULL);
        
        ssize_t receiver = recvfrom(udp_socket, buffer, PACKET_SIZE, 0,  (struct sockaddr*)&client_info, &addr_len);

        if(receiver == -1){
            //fprintf(stderr, "UDP receive timeout, proceeding next step %s\n", gai_strerror(receiver));
            break;
        }

        //Extract subsequent packet and only record last packet id arriving
        else if(receiver > 0){
            //printf("Pkt count: %d get ", pkt_count);
            memcpy(&packet_id, buffer, ID_EXTRACT);
            packet_id = ntohs(packet_id);
            last_packet_id = packet_id;
            pkt_count += 1;
        }
        gettimeofday(&end, NULL);
        
    }

    printf("\nTotal pkt received: %d\n", last_packet_id);

    
    //gettimeofday(&end, NULL);

    printf("Received UDP packets from ID %d to %d\n", first_packet_id, last_packet_id);

    return calculate_delta_time(start, end);


}

void clear_udp_buffer(int udp_socket, struct addrinfo *server_info){
    char dummy[PACKET_SIZE];
    socklen_t addrlen = server_info->ai_addrlen;

    while(recvfrom(udp_socket, dummy, PACKET_SIZE, MSG_DONTWAIT, server_info->ai_addr, &addrlen) > 0){
        printf("Dropping old UDP pkt\n");
    }
}

int server_post_probing_tcp(const char *server_tcp_port, long delta_t){//const char *server_port
    
    int tcp_socket, return_fd;
    struct addrinfo hint, *res;
    int addr_info;//server_pro;
    struct sockaddr_storage client_addr;
    char buffer[1024];
    char result[64];
    
    
    memset(&hint, 0, sizeof(hint)); //Fill hint addrinfo all 0

    hint.ai_family = AF_INET; //Set IPv4
    hint.ai_socktype = SOCK_STREAM; //Set TCP
    hint.ai_flags = AI_PASSIVE; //On server to enable bind()/listen()/accept() on returned address

    //Prepare server address info
    addr_info = getaddrinfo(NULL, server_tcp_port, &hint, &res);

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

    //Bind socket to this address
    int binder = bind(tcp_socket, res->ai_addr, res->ai_addrlen);

    if(binder == -1){
        fprintf(stderr, "Bind error %s\n", gai_strerror(binder));
        exit(1);
    }

    //Listen to client
    int listener = listen(tcp_socket, 10);

    if(listener == -1){
        fprintf(stderr, "Listen error %s\n", gai_strerror(listener));
        exit(1);
    }

    printf("\nTCP post probing...\n");
    printf("Delta t: %ld\n", delta_t);
    if(delta_t > COMPRESSION_THRESHOLD){
        strcpy(result, "Compression detected!");
    }
    else{
        strcpy(result, "Compression not detected");
    }

    printf("Server listening to client TCP post probing...\n");

    socklen_t addr_size = sizeof(client_addr);
    return_fd = accept(tcp_socket, (struct sockaddr*)&client_addr, &addr_size);

    if(return_fd== -1){
        perror("accept error");
        exit(1);
    }
    
    int bytes_recvd = recv(return_fd, buffer, sizeof(buffer), 0);

    if(bytes_recvd == -1){
        perror("Receive error");
        close(return_fd);
        close(tcp_socket);
        exit(1);
    }

    buffer[bytes_recvd] = '\0';

    printf("Received post probe TCP from client: %s\n\n", buffer);

    printf("Sending result back to client: %s\n\n", result);

    int send_result = send(return_fd, result, strlen(result), 0);

    if(send_result == -1){
        perror("Send result error");
        close(return_fd);
        close(tcp_socket);
        exit(1);
    }

    close(return_fd);

    //Free address info resolve
    freeaddrinfo(res);
    printf("Server accepted tcp: %d\n", tcp_socket);

    return tcp_socket;
}

int main(int argc, char *argv[]){

    char result[64];
    int tcp_socket_pre_probe;
    int tcp_socket_post_probe;
    int udp_socket;

    printf("Server Start\n");
    printf("Waiting client connection: \n\n");

    tcp_socket_pre_probe = server_pre_probing_tcp(TCP_PORT);

    printf("TCP pre probe done\n\n");

    printf("Setting up UDP socket...\n");

    udp_socket = server_udp_probing(UDP_PORT);

    printf("Setting up UDP socket done\n\n");
        
    //Low entropy UDP train

    printf("Ready to receive UDP packets....\n");

    printf("Receiveing LOW Entropy UDP packet train\n");
    long low_entropy = recv_udp_pkt(udp_socket);

    printf("Low entropy time: %ld\n", low_entropy);
    

    //Wait
    sleep(INTER_MEASUREMENT_TIME);
        

    //High entropy UDP train
    printf("Receiveing High Entropy UDP packet train\n");
    long high_entropy = recv_udp_pkt(udp_socket);

    printf("High entropy time: %ld\n", high_entropy);

    long delta_t = high_entropy - low_entropy;

    printf("Post probing tcp to send result\n");

    tcp_socket_post_probe = server_post_probing_tcp(TCP_PORT_POST_PROBE, delta_t);    

    sleep(3);

    close(tcp_socket_pre_probe);
    //close(client_socket_post_probe);
    close(udp_socket);
    close(tcp_socket_post_probe);
    

    return 0;
}
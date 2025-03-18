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

#define TCP_PORT "7777"
#define TCP_PORT_POST_PROBE "6666"
#define UDP_PORT "8765"
#define PACKET_SIZE 1000
#define NUM_PACKETS 6000
#define ID_EXTRACT sizeof(uint16_t)
#define INTER_MEASUREMENT_TIME 15
#define COMPRESSION_THRESHOLD 100000 //Threashold for 100ms

int server_probing_tcp(const char *server_port){
    int tcp_socket;
    struct addrinfo hint, *res;
    int addr_info;
    
    
    memset(&hint, 0, sizeof(hint));

    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;

    addr_info = getaddrinfo(NULL, server_port, &hint, &res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    tcp_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(tcp_socket == -1){
        fprintf(stderr, "TCP socket error %s\n", gai_strerror(tcp_socket));
        exit(1);
    }

    int binder = bind(tcp_socket, res->ai_addr, res->ai_addrlen);

    if(binder == -1){
        fprintf(stderr, "Bind error %s\n", gai_strerror(binder));
        exit(1);
    }

    int listener = listen(tcp_socket, 5);

    if(listener == -1){
        fprintf(stderr, "Listen error %s\n", gai_strerror(listener));
        exit(1);
    }

    freeaddrinfo(res);
    return tcp_socket;

}

int server_udp_probing(const char *server_port, struct addrinfo **res){
    int udp_socket;
    struct addrinfo hints;
    int addr_info;

    memset(&hints, 0 , sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    addr_info = getaddrinfo(NULL, server_port, &hints, res);

    if(addr_info != 0){
        fprintf(stderr, "Get address info error %s\n", gai_strerror(addr_info));
        exit(1);
    }

    udp_socket = socket((*res)->ai_family, (*res)->ai_socktype, (*res)->ai_protocol);

    if(udp_socket == -1){
        fprintf(stderr, "UDP socket error %s\n", gai_strerror(udp_socket));
        exit(1);
    }

    int dont_fragment = IP_PMTUDISC_DO;
    if (setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) < 0) {
        perror("Failed to set Don't Fragment flag");
        exit(1);
    }

    int binder = bind(udp_socket, (*res)->ai_addr, (*res)->ai_addrlen);

    if(binder == -1){
        fprintf(stderr, "UDP Bind error %s\n", gai_strerror(binder));
        exit(1);
    }

    return udp_socket;
}

long calculate_delta_time(struct timeval start, struct timeval end){
    return ((end.tv_sec - start.tv_sec) * 1000000L) + (end.tv_usec - start.tv_usec);
}

int recv_udp_pkt(int udp_socket){
    struct timeval start, end, current, timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;

    char buffer[PACKET_SIZE];
    struct addrinfo *client_info;
    socklen_t addr_len;
    int packet_id = 0;
    int first_packet_id = -1;
    int last_packet_id = -1;
    int pkt_count = 0;
    
    setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    ssize_t first_udp_receive = recvfrom(udp_socket, buffer, PACKET_SIZE, 0, client_info->ai_addr, &addr_len);

    // if(first_udp_receive < 0){
    //     fprintf(stderr, "UDP Bind error %s\n", gai_strerror(first_udp_receive));
    //     exit(1);
    // }
    
    pkt_count += 1;

    //1st 16 bits are pkt id and rest is entropy data
    //So memcpy 1st 16 bits of buffer defined by 4
    memcpy(&packet_id, buffer, ID_EXTRACT); 
    gettimeofday(&start, NULL);

    first_packet_id = packet_id;
    last_packet_id = packet_id;

    while(1){
        printf("Pkt id receiving: %d\n", pkt_count);

        gettimeofday(&current, NULL);

        long elapsed_time = (current.tv_sec - start.tv_sec) * 1000000L + (current.tv_usec - start.tv_usec);

        if(elapsed_time >= timeout.tv_sec * 1000000L){
            //printf("Timeout, proceeding to next phase");
            break;
        }
        
        ssize_t receiver = recvfrom(udp_socket, buffer, PACKET_SIZE, 0, NULL, NULL);
        //Extract subsequent packet and only record last packet id arriving
        if(receiver > 0){
            printf("Pkt count: %d get\n", pkt_count);
            memcpy(&packet_id, buffer, ID_EXTRACT);
            packet_id = ntohs(packet_id);
            last_packet_id = packet_id;
            pkt_count += 1;
        }
        // else{
        //     printf("UDP packet [%d] lost, last packet ID ramains: %d\n", pkt_count, last_packet_id);
        // }
        
    }

    gettimeofday(&end, NULL);

    //printf("Received UDP packets from ID %d to %d\n", first_packet_id, last_packet_id);

    return calculate_delta_time(start, end);


}

void clear_udp_buffer(int udp_socket, struct addrinfo *server_info){
    char dummy[PACKET_SIZE];
    socklen_t addrlen = server_info->ai_addrlen;

    while(recvfrom(udp_socket, dummy, PACKET_SIZE, MSG_DONTWAIT, server_info->ai_addr, &addrlen) > 0){
        //printf("Dropping old UDP pkt");
    }
}

void post_probe(int client_socket_post_probe, long delta_t, char *result){
    printf("Delta t: %ld\n", delta_t);
    if(delta_t > COMPRESSION_THRESHOLD){
        strcpy(result, "Compression detected!");
    }
    else{
        strcpy(result, "Compression not detected");
    }

    send(client_socket_post_probe, result, strlen(result), 0);
    printf("Sent: %s\n", result);
    close(client_socket_post_probe);
}

int main(int argc, char *argv[]){

    printf("Server Start\n");

    int tcp_socket = server_probing_tcp(TCP_PORT);

    int tcp_socket_post_probe = server_probing_tcp(TCP_PORT_POST_PROBE);

    struct addrinfo *udp_res;

    int udp_socket = server_udp_probing(UDP_PORT, &udp_res);

    char result[64];

    printf("Ready to receive UDP packets....\n");

    while(1){
        printf("Waiting client connection: ");
        int client_socket = accept(tcp_socket, NULL, NULL);
        if(client_socket == -1){
            fprintf(stderr, "Client socket error %s\n", gai_strerror(client_socket));
            exit(1);
        }
        close(client_socket);
        
        //Low entropy UDP train
        printf("Receiveing LOW Entropy UDP packet train\n");
        long low_entropy = recv_udp_pkt(udp_socket);

        printf("Low entropy time: %ld\n", low_entropy);

        clear_udp_buffer(udp_socket, udp_res);//Clear UDP socket buffer
        //Wait
        sleep(INTER_MEASUREMENT_TIME);
        

        //High entropy UDP train
        printf("Receiveing High Entropy UDP packet train\n");
        long high_entropy = recv_udp_pkt(udp_socket);

        printf("High entropy time: %ld\n", high_entropy);

        long delta_t = high_entropy - low_entropy;

        int client_socket_post_probe = accept(tcp_socket_post_probe, NULL, NULL);
        if(client_socket_post_probe == -1){
            fprintf(stderr, "Client socket post probe error %s\n", gai_strerror(client_socket_post_probe));
            exit(1);
        }

        post_probe(client_socket_post_probe, delta_t, result);
        

    }

    close(tcp_socket);
    close(tcp_socket_post_probe);
    close(udp_socket);
    freeaddrinfo(udp_res);

    return 0;
}
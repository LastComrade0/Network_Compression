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

#define SERVER_IP "192.168.132.210"  // 192.168.132.210 or 192.168.64.15
#define TCP_PORT_PRE_PROBE "7777"
#define TCP_PORT_POST_PROBE "6666"
#define UDP_SRC_PORT "9876"
#define UDP_DEST_PORT "8765"
#define PACKET_SIZE 1000
#define NUM_PACKETS 6000
#define ID_EXTRACT sizeof(uint16_t)
#define INTER_MEASUREMENT_TIME 60

int client_tcp_pre_probing(const char *server_ip, const char *server_port){
    printf("TCP pre probing\n");
    int tcp_socket;
    struct addrinfo hint, *res;
    int addr_info;
    char msg[] = "Sending Configuration";
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
        fprintf(stderr, "Connect error pre probing %s\n", gai_strerror(connector));
        exit(1);
    }

    //Send message to server
    send(tcp_socket, msg, strlen(msg), 0);
    
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

int send_udp_pkt(int udp_socket, struct addrinfo *server_info, int entropy_type){
    char buffer[PACKET_SIZE];
    int packet_id;
    
    switch(entropy_type){
        case 0:
            memset(buffer, 0, PACKET_SIZE);

            printf("Sending low entropy train...\n");
            for(int i = 0; i < NUM_PACKETS; i += 1){
                //printf("Sending packet id: %d\n", i);
                packet_id = htons(i);
                memcpy(buffer, &packet_id, ID_EXTRACT);
                sendto(udp_socket, buffer, PACKET_SIZE, 0, server_info->ai_addr, server_info->ai_addrlen);
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

            for(int i = 0; i < NUM_PACKETS; i += 1){
                packet_id = htons(i);
                memcpy(buffer, &packet_id, ID_EXTRACT);

                ssize_t urandom_read = read(urandom_fd, buffer + ID_EXTRACT, PACKET_SIZE - ID_EXTRACT);
                
                // printf("Current bit: ");
                
                // printf("%s\n", buffer);

                if(urandom_read < 0){
                    perror("Error opening /dev/urandom");
                    close(urandom_fd);
                    exit(1);
                }
                
                ssize_t sent_udp = sendto(udp_socket, buffer, PACKET_SIZE, 0, server_info->ai_addr, server_info->ai_addrlen);
                
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

    freeaddrinfo(res);
    return tcp_socket;
}


int main(int argc, char *argv[]){
    int tcp_socket_pre_probe, tcp_socket_post_probe;
    int udp_socket;


    printf("Client");
    
    tcp_socket_pre_probe = client_tcp_pre_probing(SERVER_IP, TCP_PORT_PRE_PROBE);
    
    sleep(1);

    struct addrinfo *udp_res;
    udp_socket = client_udp_probing(SERVER_IP, UDP_SRC_PORT, UDP_DEST_PORT, &udp_res);

    send_udp_pkt(udp_socket, udp_res, 0);//Send Low entropy

    printf("Done sending low entropy UDP packet train\n");
    printf("Wait...\n\n");

    sleep(27);

    send_udp_pkt(udp_socket, udp_res, 1);//Send High entropy

    freeaddrinfo(udp_res);

    printf("Done sending high entropy UDP packet train\n");
    printf("Wait...\n\n");

    sleep(20);

    printf("Client: Reconnecting to server for result (Post-Probing Phase)...\n");
    tcp_socket_post_probe = client_tcp_post_probing(SERVER_IP, TCP_PORT_POST_PROBE);

    //char result[64];
    // recv(tcp_socket, result, sizeof(result), 0);
    // printf("Server response: %s\n", result);
    close(tcp_socket_pre_probe);

    close(udp_socket);

    close(tcp_socket_post_probe);
    

    return 0;
}
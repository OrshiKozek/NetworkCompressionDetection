/*

  Author: Orshi Kozek

  Server Application

  This program attempts to detect network compression through receiving
  two large UDP packet trains from a client application.

  To compile this program: gcc server.c
  To run this program: ./a.out

*/

#include <arpa/inet.h>
#include <dirent.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include<sys/wait.h>

volatile int exit_loop = 0;
volatile int exit_loop_2 = 0;

struct config_info{
	char server_ip[20];
	char s_port_udp[20];
	char d_port_udp[20];
	char d_port_tcp_head[20];
	char d_port_tcp_tail[20];
	char probing_port[20];
	char udp_payload_sz[20];
	char int_measu_time[20];
	char num_udp_packets[20];
	char udp_ttl[20];
	char packet_delay[20];
};

//handle timeout while waiting for low entropy packets
void alarm_handler(int sig)
{
  exit_loop = 1;
}

//handle timeout while waiting for high entropy packets
void alarm_handler_2(int sig)
{
  exit_loop_2 = 1;
}

//parse config info from the received string and store in config_info struct
struct config_info* parse_config(struct config_info* info, char *buf){
	char *str = buf;
	int i = 0;

	//set up tokenization of message
	char *token;
	token = strtok(str, " \t\n");

	//tokenizes str and stores corresponding token in config_info struct
	while(token != NULL){
		if(i == 0){
			sprintf(info->server_ip, "%s", token);
		}
		else if(i == 1){
			sprintf(info->s_port_udp, "%s", token);
		}
		else if(i == 2){
			sprintf(info->d_port_udp, "%s", token);
		}
		else if(i == 3){
			sprintf(info->d_port_tcp_head, "%s", token);
		}
		else if(i == 4){
			sprintf(info->d_port_tcp_tail, "%s", token);
		}
		else if(i == 5){
			sprintf(info->probing_port, "%s", token);
		}
		else if(i == 6){
			sprintf(info->udp_payload_sz, "%s", token);
		}
		else if(i == 7){
			sprintf(info->int_measu_time, "%s", token);
		}
		else if(i == 8){
			sprintf(info->num_udp_packets, "%s", token);
		}
		else if(i == 9){
			sprintf(info->udp_ttl, "%s", token);
		}
		else if(i == 10){
			sprintf(info->packet_delay, "%s", token);
		}

		i++;

		//create next token from leftover string
		token = strtok(NULL, " \t");
	}

	return info;
}

int main(void){

	printf("\nCommencing PRE-PROBIG Phase.\n\n");

	//create tcp socket
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	//checks for errors in creating socket
	if (socket_fd == -1) {
		perror("socket");
		return 1;
	}

	//Sets sockopt so we can reuse the port in post-probing
	int optval = 1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	//create and allocate memory for server sockaddr
	struct sockaddr_in addr;

	//set everything to 0
	memset(&addr, 0, sizeof addr);

	//set socket info
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(5000); //should match the tcp-port found in config info later

	//bind tcp socket to the port
	if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		perror("bind");
		return 1;
	}

	//listen on the port for a connection
	if (listen(socket_fd, 10) == -1) {
		perror("listen");
		return 1;
	}

	printf("Listening on port 5000\n");

	//allocate memory for config information
	struct config_info* info = (struct config_info*)malloc(sizeof(struct config_info));

	//create client info
	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof client_addr);
	socklen_t slen = sizeof(client_addr);

	//accept connection from client
	int client_fd = accept(socket_fd, (struct sockaddr *) &client_addr, &slen);

	if (client_fd == -1) {
		perror("accept");
		return 1;
	}

	//get more client informaiton
	char remote_host[INET_ADDRSTRLEN];
	inet_ntop(client_addr.sin_family, (void *) &((&client_addr)->sin_addr), remote_host, sizeof(remote_host));


	char buf[256]; //initialize buffer for config message

	//read in config info from client
	ssize_t res_bytes = read(client_fd, buf, 256);

	printf("Received config information from client.\n");

	//parse stringified config info and store in config_info struct
	info = parse_config(info, buf);

	//send response to client
	char *reply = "Received config information!";
	write(client_fd, reply, strlen(reply)+1);

	//close tcp socket connection
	close(socket_fd);


	//PROBING PHASE:
	printf("\nPRE-PROBING phase complete. Commencing PROBING phase.\n\n");

	//convert config information from string to int
	unsigned int s_port_udp = atoi(info->s_port_udp);
	unsigned int d_port_udp = atoi(info->d_port_udp);
	unsigned int udp_payload_sz = atoi(info->udp_payload_sz);
	unsigned int int_measu_time = atoi(info->int_measu_time);
	unsigned int num_udp_packets = atoi(info->num_udp_packets);

	//declare variables for timing for low and high entropy data
	clock_t low_start_t, low_end_t, high_start_t, high_end_t;
	double total_t, low_time, high_time = 0;

	//create udp socket
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if(socket_fd < -1){
		printf("failed creating new socket\n");
	}

	//update server addr struct with new port number
	addr.sin_port = htons(d_port_udp);

	printf("Accepting packets on port: %d\n", d_port_udp);

	//bind udp socket to port
	if(bind(socket_fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0){
		printf("bind didn't work\n");
	}

	//create client struct
	struct sockaddr_in cliaddr;
	memset(&cliaddr, 0, sizeof(cliaddr));

	int n;
	int len;
	len = sizeof(cliaddr);
	uint8_t pkt_payload[udp_payload_sz];

	//receive low entropy data
	int i = 0;
	while(i < num_udp_packets && exit_loop == 0){
		n = recvfrom(socket_fd, pkt_payload, udp_payload_sz, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
		if(i == 0 && n > 0){ //start clock once first packet is received
			low_start_t = clock();
			alarm(5); //if not all packets are received after 5 seconds, then don't keep waiting
			signal(SIGALRM, alarm_handler);
		}
		i++;
	}
	low_end_t = clock();


	//calculate time elapsed in seconds
	total_t = (((double)low_end_t) - ((double)low_start_t)) / ((double)CLOCKS_PER_SEC);
	low_time = total_t*1000; //convert seconds to milliseconds

	printf("Received low entropy data.\n");


	printf("\nWaiting %d seconds between tests.\n\n", atoi(info->int_measu_time));

	i = 0; //reset counter
	//receive high entropy data
	while(i < num_udp_packets && exit_loop_2 == 0){
		n = recvfrom(socket_fd, pkt_payload, udp_payload_sz, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
		if(i == 0 && n > 0){ //start clock once first packet is received
			high_start_t = clock();
			alarm(5); //if not all packets are received after 5 seconds, then don't keep waiting
			signal(SIGALRM, alarm_handler_2);
		}
		i++;
	}
	high_end_t = clock();

	//calculate time elapsed in seconds
	total_t = (((double)high_end_t) - ((double)high_start_t)) / ((double)CLOCKS_PER_SEC);
	high_time = total_t*1000; //convert seconds to milliseconds

	printf("Received high entropy data.\n");

	printf("\nLow entropy time: %f ms\nHigh entropy time: %f ms\n", low_time, high_time);

	printf("Time difference: %f ms\n", high_time - low_time);


	//Establish tcp connection to send results to client
	printf("\nPROBING phase complete. Commencing POST-PROBING phase.\n\n");

	//create post-probing tcp socket
	int post_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	//checks for errors in creating socket
	if (post_socket_fd == -1) {
		perror("socket");
		return 1;
	}

	//convert port number from string to int
	int port = atoi(info->probing_port);

	//set sockopt so we can reuse the port from the pre-probing phase
	setsockopt(post_socket_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	struct sockaddr_in new_addr;
	//set everything to 0
	memset(&new_addr, 0, sizeof new_addr);

	//set socket info
	new_addr.sin_family = AF_INET;
	new_addr.sin_addr.s_addr = INADDR_ANY;
	new_addr.sin_port = htons(port);

	//bind tcp socket to the port
	if (bind(post_socket_fd, (struct sockaddr *) &new_addr, sizeof(new_addr)) == -1) {
		perror("bind");
		return 1;
	}

	//listen on the port for a connection
	if (listen(post_socket_fd, 10) == -1) {
		perror("listen");
		return 1;
	}

	printf("Listening on port %d\n", port);

	//we can use the same client_addr struct because the information is the same
	int post_client_fd = accept(post_socket_fd, (struct sockaddr *) &client_addr, &slen);

	if (post_client_fd == -1) {
		perror("accept");
		return 1;
	}


	char result[256];

	//compare elapsed time to 100ms threshhold
	if((high_time - low_time) > 100){
		strcpy(result, "Compression detected!");
	}
	else{
		strcpy(result, "No compression was detected.");
	}

	printf("Diagnosis: %s\n", result);
	printf("Sending result to client.\n");

	//send result to client
	write(post_client_fd, result, strlen(result)+1);

	//read in confirmation reply from client
	char client_reply[256];
	ssize_t read_bytes = read(post_client_fd, client_reply, 256);
	printf("Message from client: %s\n\n", client_reply);


	//close tcp socket connection
	close(post_socket_fd);

	//free memory allocated to config info
	free(info);
	return 0;
}

/*

  Author: Orshi Kozek

  Client Application

  This program attempts to detect network compression through sending
  two large UDP packet trains to a server application.

  To compile this program: gcc client.c -ljson-c
  To run this program: ./a.out config_file.json

*/

#include <arpa/inet.h>
#include <json-c/json.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

//the struct that stores the parsed json values from config file
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


//reads in config information from the given file
struct config_info* read_config(char* file_name, struct config_info* info){

	//declare variables
	FILE *fp;
	char buffer[1024];

	struct json_object *parsed_json;
	struct json_object *host_ip;
	struct json_object *s_port;
	struct json_object *d_port;
	struct json_object *d_head;
	struct json_object *d_tail;
	struct json_object *tcp_port;
	struct json_object *pl_size;
	struct json_object *i_m_time;
	struct json_object *udp_num;
	struct json_object *ttl;
	struct json_object *p_delay;

	//open file for reading
	fp = fopen(file_name, "r");
	if(fp == NULL){
		perror("Couldn't open file in read_config\n");
		exit(-1);
	}

	//read file into buffer and close fd
	fread(buffer, 1024, 1, fp);
	fclose(fp);

	//parse the contents of the json file
	parsed_json = json_tokener_parse(buffer);

	//save each individual element of the json file to a json_object variable
	json_object_object_get_ex(parsed_json, "host_ip", &host_ip);
	json_object_object_get_ex(parsed_json, "s_port", &s_port);
	json_object_object_get_ex(parsed_json, "d_port", &d_port);
	json_object_object_get_ex(parsed_json, "d_head", &d_head);
	json_object_object_get_ex(parsed_json, "d_tail", &d_tail);
	json_object_object_get_ex(parsed_json, "tcp_port", &tcp_port);
	json_object_object_get_ex(parsed_json, "pl_size", &pl_size);
	json_object_object_get_ex(parsed_json, "i_m_time", &i_m_time);
	json_object_object_get_ex(parsed_json, "udp_num", &udp_num);
	json_object_object_get_ex(parsed_json, "ttl", &ttl);
	json_object_object_get_ex(parsed_json, "p_delay", &p_delay);

	//save parsed json elements into the config_info struct
	sprintf(info->server_ip, "%s", json_object_get_string(host_ip)); 
	sprintf(info->s_port_udp, "%s", json_object_get_string(s_port));
	sprintf(info->d_port_udp, "%s", json_object_get_string(d_port));
	sprintf(info->d_port_tcp_head, "%s", json_object_get_string(d_head));
	sprintf(info->d_port_tcp_tail, "%s", json_object_get_string(d_tail));
	sprintf(info->probing_port, "%s", json_object_get_string(tcp_port));
	sprintf(info->udp_payload_sz, "%s", json_object_get_string(pl_size));
	sprintf(info->int_measu_time, "%s", json_object_get_string(i_m_time));
	sprintf(info->num_udp_packets, "%s", json_object_get_string(udp_num));
	sprintf(info->udp_ttl, "%s", json_object_get_string(ttl));
	sprintf(info->packet_delay, "%s", json_object_get_string(p_delay));
}

//combine struct information to string
void strinfigy_config(struct config_info* info, char *buf){

	//sets buffer to all 0s
	bzero(buf, sizeof(buf));

	//concatenate all the config info into one string
	sprintf(buf, "%s\t", info->server_ip);
	strcat(buf, info->s_port_udp);
	strcat(buf, "\t");
	strcat(buf, info->d_port_udp);
	strcat(buf, "\t");
	strcat(buf, info->d_port_tcp_head);
	strcat(buf, "\t");
	strcat(buf, info->d_port_tcp_tail);
	strcat(buf, "\t");
	strcat(buf, info->probing_port);
	strcat(buf, "\t");
	strcat(buf, info->udp_payload_sz);
	strcat(buf, "\t");
	strcat(buf, info->int_measu_time);
	strcat(buf, "\t");
	strcat(buf, info->num_udp_packets);
	strcat(buf, "\t");
	strcat(buf, info->udp_ttl);
	strcat(buf, "\t");
	strcat(buf, info->packet_delay);
}

//sends pre-probing config information to server
int send_config_info(int socket_fd, char *buf){

	int buf_len = strlen(buf);

	//send config data to server
	if((write(socket_fd, buf, buf_len+1)) == -1) {
		perror("write");
		exit(1);
	}

	return 0;
}

int main(int argc, char *argv[]){

	//check for proper number of arguments
	if(argc != 2){
		printf("Usage: ./a.out config_file.json\n");
		return 0;
	}

	//PRE-PROBING PHASE:
	printf("\nCommencing PRE-PROBING phase.\n\n");

	struct config_info* info = (struct config_info*)malloc(sizeof(struct config_info));
	char *f_name = argv[1];
	char buffer[256];
	
	read_config(f_name, info);	//reads and parses config file
	strinfigy_config(info, buffer); //creates one string containing the config data

	//convert the given pre/post probing port from string to int
	int port = atoi(info->probing_port);

	//create tcp socket
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		perror("tcp socket 1");
		return 1;
	}

	//retrieve hostname information
	struct hostent *server = gethostbyname(info->server_ip);
	if (server == NULL) {
		fprintf(stderr, "Could not resolve host: %s\n", info->server_ip);
		return 1;
	}

	//add more socket info
	struct sockaddr_in serv_addr = { 0 };
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr = *((struct in_addr *) server->h_addr);

	//try to connect to server
	if (connect(socket_fd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in)) == -1) {
		perror("connect");
		exit(-1);
	}

	printf("Connected to server %s:%d\n", info->server_ip, port);

	//clear stdout and send string version of config information
	fflush(stdout);
	send_config_info(socket_fd, buffer);
	
	printf("Sent config information to server. Awaiting reply.\n");

	//wait for confirmation from server
	char reply[128];
	read(socket_fd, reply, 128);
	printf("Server replied: %s\n", reply);

	//close tcp connection with server
	close(socket_fd);



	//PROBING PHASE:
	printf("\nPRE-PROBING phase complete. Commencing PROBING phase.\n\n");


	//converting config info parameters to numbers
	unsigned int s_port_udp = atoi(info->s_port_udp);
	unsigned int d_port_udp = atoi(info->d_port_udp);
	unsigned int udp_payload_sz = atoi(info->udp_payload_sz);;
	unsigned int num_udp_packets = atoi(info->num_udp_packets);
	unsigned int packet_delay = atoi(info->packet_delay);

	//create new sockaddr_in for udp
	struct sockaddr_in addr, srcaddr;

	//create udp socket
	int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (udp_sockfd == -1) {
		perror("udp socket");
		exit(1);
	}

	//set up socket structs
	memset(&addr, 0, sizeof(addr)); //initialize memory to 0
	addr.sin_family = AF_INET; //set sin family
	inet_aton(info->server_ip, &addr.sin_addr); //set source adddress
	addr.sin_port = htons(d_port_udp); //set the destination port

	memset(&srcaddr, 0, sizeof(srcaddr)); //initialize memoryto 0
	srcaddr.sin_family = AF_INET; //set sin family
	srcaddr.sin_addr.s_addr = htonl(INADDR_ANY); //set home source address
    srcaddr.sin_port = htons(s_port_udp); //set the source port


	//set the don't fragment bit
	int value=IP_PMTUDISC_DO;

	if (setsockopt(udp_sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value))<0) {
		printf("unable to set DONT_FRAGMENT bit.\n");
		exit(1);
	}


	//bind socket to port
	if(bind(udp_sockfd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0){
		printf("bind failed\n");
		exit(1);
	}

	//calculate size of data
	int total_data_len = num_udp_packets * (udp_payload_sz);

	//allocate memory for data
	uint8_t *total_data = (uint8_t *)malloc(total_data_len * sizeof (uint8_t));

	//set all data bits to 0
	if (total_data != NULL) {
		memset(total_data, 0, total_data_len * sizeof (uint8_t));
	}
	else{
		printf("could not allocate memory for payload of size %d\n", udp_payload_sz);
	}

	//set the packet ids for each payload
	uint8_t *ptr = total_data;
	for(uint16_t i = 0; i < num_udp_packets; i++){
		ptr = total_data + (i * udp_payload_sz); //ptr points to the next payload section in the buffer
		*ptr++ = (uint8_t)(i >> 8); //writes the higher order byte
		*ptr = (uint8_t)(i & 0xff); //writes the lower order byte
	}

	//send to server
	printf("Sending %d packets of low entropy data to server.\n", num_udp_packets);

	uint8_t *send_ptr = total_data;
	 for(uint16_t j = 0; j < num_udp_packets; j++){

		usleep(packet_delay); //sleep for given # of microseconds to ensure enough time between sending two packets

		send_ptr = total_data + (j * udp_payload_sz); //send_ptr points to the next payload section in the buffer
		if((sendto(udp_sockfd, send_ptr, udp_payload_sz, MSG_CONFIRM, (const struct sockaddr *)&addr, sizeof(addr))) < 0){
			printf("sendto failed for index: %u\n", j);
		}
	}

	printf("Low entropy UDP packets sent.\n\n");

	//convert inter-measurement time to integer
	unsigned int int_measu_time = atoi(info->int_measu_time);


	printf("Waiting for %d seconds between tests.\n\n", int_measu_time);
	//sleep for inter-measurement time to avoid low entropy and high
	// entropy data packets from interfering with each other
	sleep(int_measu_time);


	//create high entropy data packets here and send them to server

	//generate random bits for whole stretch of data
	getrandom(total_data, total_data_len, 0);

	//write in packet id's for each stretch of payload data
	for(uint16_t i = 0; i < num_udp_packets; i++){
		ptr = total_data + (i * udp_payload_sz); //ptr points to the next payload section in the buffer
		*ptr++ = (uint8_t)(i >> 8); //writes the higher order byte
		*ptr = (uint8_t)(i & 0xff); //writes the lower order byte
	}

	printf("Sending %d packets of high entropy data to server.\n", num_udp_packets);

	//send high entropy data:
	uint8_t *send_high_ptr = total_data;
	for(uint16_t j = 0; j < num_udp_packets; j++){

		usleep(packet_delay); //sleep for given # of microseconds to ensure enough time between sending two packets

		send_high_ptr = total_data + (j * udp_payload_sz); //send_ptr points to the next payload section in the buffer
		if((sendto(udp_sockfd, send_high_ptr, udp_payload_sz, MSG_CONFIRM, (const struct sockaddr *)&addr, sizeof(addr))) < 0){
			printf("sendto failed for packet #%u\n", j);
		}
	}

	printf("High entropy UDP packets sent.\n");

 	//free memory allocated for udp packets
	free(total_data);


	//POST-PROBING PHASE
	//prepare TCP connection to receive result from server
	
	//sleep for 1 second to allow server program to set up tcp connection
	sleep(1);

	//create socket address iformation
	
	//create tcp socket
	int post_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (post_socket_fd == -1) {
		printf("tcp socket 1\n");
		return 1;
	}

	//create hostname information
	struct hostent *new_server = gethostbyname(info->server_ip);
	if (new_server == NULL) {
		fprintf(stderr, "Could not resolve host: %s\n", info->server_ip);
		return 1;
	}

	//add more socket info
	struct sockaddr_in new_serv_addr;
	memset(&new_serv_addr, 0, sizeof(new_serv_addr));
	new_serv_addr.sin_family = AF_INET;
	new_serv_addr.sin_port = htons(port);
	new_serv_addr.sin_addr = *((struct in_addr *) new_server->h_addr);

	//try to connect to server
	if (connect(post_socket_fd, (struct sockaddr *) &new_serv_addr, sizeof(struct sockaddr_in)) == -1) {
		fprintf(stderr, "connect\n");
		exit(-1);
	}	
	

	printf("\nCommencing POST-PROBING phase.\n\n");
	printf("Connected to server %s:%d\n", info->server_ip, port);


	//wait for confirmation from server
	char answer[128];
	read(post_socket_fd, answer, 128);
	printf("Diagnosis from server: %s\n\n", answer);


	//send confirmation response to server
	char confirm[] = "Diagnosis received.";
	if((write(post_socket_fd, confirm, strlen(confirm)+1)) == -1) {
		printf("write");
		return 1;
	}


	//close tcp socket
	close(post_socket_fd);

	//free allocated memory for config information
	free(info);
	return 0;
}



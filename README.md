Author: Orshi Kozek

CS 486: Network Security Fall 2020

---------------------

TABLE OF CONTENTS
=================

* [Project Overview](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#project-overview)
* [Requirements](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#requirements)
* [Configuration File](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#configuration-file)
* [Client-Server Application](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#client-server-application)
	* [Running the program](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#running-the-program)
	* [Pre-probing Phase](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#pre-probing-phase)
	* [Probing Phase](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#probing-phase)
	* [Post-probing Phase](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#post-probing-phase)
* [Standalone Application](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#standalone-application)
	* [Running the program](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#running-the-program-1)
	* [The Standalone program](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#the-standalone-program)


PROJECT OVERVIEW
================

Project Specification: http://cs486.cs.usfca.edu/v/projects/CS486_Fall_2020_Project.pdf

This project attempts to detect if there is network compression across a network, through the use of a client-server application, and a standalone application.

The client-server application operates on two machines, and communicate through sockets. The client sends data to the server, and the server detects the presence of network compression, or the lack thereof. More details can be found in the Client-Server Application section.

The standalone application operates on one machine, only requiring a running, but unresponsive machine. The client sends data to the unresponsive server and determines the presence of network compression based on the returning information, if any. More details can be found in the Standalone Application section.


REQUIREMENTS
============

A JSON parsing library and a packet capture library is necessary to compile and run the code. You can install the necessary packages on a Linux system with the following commands. When compiling the client application code, the -ljson-c flag must be included. When compiling the standalone application code, the flags -ljson-c and -lpcap must both be included. The server code does not require any additional flags to compile.

JSON-c: 
	```sudo apt install libjson-c-dev```
	
Pcap: 
	```sudo apt-get install -y libpcap-dev```


CONFIGURATION FILE
==================

The client application and the standalone application both take in a filename as a command line argument from which to read the configuration information. The program utilizes the JSON-C library to parse the information and store it in a custom struct. The client and server applications both use this information, as does the standalone application.

An example file (e.g. config_file.json) is shown below. The elements of the file are as follows, in order: host IP address, UDP source port, UDP destination port, TCP head SYN packet port, TCP tail SYN packet port, port used for TCP socket connections, packet payload size, inter-measurement time (in seconds), number of UDP packets, time to live length for UDP packets (in seconds), and packet delay before sending (in seconds).

	//Start of example file
	{
        "host_ip" : "192.168.111.157",
        "s_port" : "9876",
        "d_port" : "8765",
        "d_head" : "8000",
        "d_tail" : "8001",
        "tcp_port" : "5000",
        "pl_size" : "1000",
        "i_m_time": "15",
        "udp_num" : "6000",
        "ttl" : "255",
        "p_delay" : "1"
	}
	//End of example file


CLIENT-SERVER APPLICATION
=========================

This application is made up of a client host and a server host, which communicate through sockets in an attempt to check for network compression. There are three phases to this process: pre-probing, probing, and post-probing.

----------------
### Running the program

Note: The server program must be run first for the programs to work correctly.

The server application, server.c, is complied by the following command: gcc server.c
The applicationc an be run by executing this command: ./a.out

The client application, client.c, is compiled by the following command: gcc client.c -ljson-c
The application can be run by executing this command: ./a.out config_file.json

----------------
### Pre-probing Phase:

The server creates a TCP socket and binds to a port. The server application then listens for any client connections. Meanwhile, the client parses the information from the provided configuration file. The client then creates a socket and establishes a connection with the server. Once connected, the client sends the configuration information to the server, which parses the received information. This information is now accessible to both the client and the server application.

----------------
### Probing Phase:

The server sets up a UDP socket prepared to accept the specified number of UDP packets from the client. The client creates the specified number of UDP packets to send to the server. The client does this by creating an array of bytes that is populated with low entropy data (all 0s). Then the packet ID's are set for each section in the array. The dont-fragment bit is set on each packet before it is sent. Then these packets are sent back-to-back to the server application. The program waits for the given inter-measurement time "i_m_time" before repeating the process with high entropy data. This is achieved by populating the entire array with random data, setting the packet ID's again, and sending them back-to-back to the server again.

Meanwhile, the server is continually accepting packets from the client, first waiting for all the low-entropy data to arrive, then waiting for the high-entropy data to arrive. The server application calculates the amount of time between the start and end of the arrival of the low-entropy and high-entropy packet trains. The server calculates whether the difference in time (time of high enrtopy data - time of low entropy data) is greater or less than 100 milliseconds. If the result is greater than 100ms, network compression was detected. If not, no network compression was detected. 

----------------	
### Post-Probing Phase:

The client establishes a connection with the server, who, after accepting the connection from the client, sends back the information about network compression. The client displays the results of the investigation (whether network compression was detected or not) and both parties terminate the connection.



STANDALONE APPLICATION
======================

This application is made up of a client host which uses raw sockets and regular sockets in an attempt to check for network compression.

---------------------
### Running the program

To compile the program, the following command must be used: gcc standalone.c -ljson-c -lpcap
To run the program, the following command must be used: sudo ./a.out config_file.json

------------------------
### The Standalone Program

The goal of the standalone application is to detect network compression by sending custom TCP SYN packets to an unresponsive server, and measure the time between the server's responses (in the form of a TCP RST packets).

The standalone application uses a raw socket to send the TCP packets. Custom IP headers and TCP headers must be constructed in order to send each packet. The custom IP and TCP headers are populated with the relevant information from the configuration file. The checksum for both the IP header and the TCP header are calculated as well. The SYN flag in the TCP header is also set. Once this is complete, the standalone program sends the TCP packet to the server. Immediately following this, the program creates a UDP packet train of low entropy data, just as in the Client-Server Application, with the exception of also setting the UDP packet time to live to the given value from the configuration file. Once the last UDP packet is sent, a tail TCP packet is constructed, similarly to the first one. This packet is also sent to the server.

The program waits for inter-measurement time before repeating the above process with high entropy data: the head TCP packet is created and sent, the high entropy packets are constructed and sent, and the tail TCP packet is created and sent.

While these packets are being constructed and sent, a child process has been created and tasked with listening for returning TCP RST packets from the server. The child process does this by utilizing the pcap library. The program listens for packets that match a specific filter. The time between the arrival of each packet is calculated. The time between the return of the first RST packet and the second RST packet is calculated for both low and high entropy data. The difference in times is measured against the 100ms threshold, like in the Client-Server Application. The result of the calculation is displayed and the program terminates.

In the event where a timeout occurs, the application terminates due to insufficient information. A timeout could be caused when the server doesn't send a RST packet in a timely manner, or doesn't sent a RST packet at all.

### [Jump to Table of Contents](https://github.com/OrshiKozek/NetworkCompressionDetection/blob/main/README.md#table-of-contents)

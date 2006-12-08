/* $Id$ */
/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2005 Helmut Januschka - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */
/*
$Revision$
$Source$


$Log$
Revision 1.3  2006/12/08 22:36:07  hjanuschka
auto commit

Revision 1.6  2006/11/27 21:16:54  hjanuschka
auto commit

Revision 1.5  2006/11/25 12:31:56  hjanuschka
auto commit

Revision 1.4  2006/11/25 01:16:18  hjanuschka
auto commit



*/
#include <malloc.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>


#ifdef HAVE_SSL
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "bartlby_v2_dh.h"
#endif

#define PORTIER_SVCLIST_PACKET 1
#define PORTIER_RESULT_PACKET 2
#define PORTIER_REQUEST_PACKET 3

#define PORTIER_TIMEOUT 30

typedef struct port_packet_struct{

	u_int32_t crc32_value;
	int16_t   exit_code;
	int16_t   packet_type;
	char      output[2048];
	char      cmdline[2048];
	char      plugin[2048];
	char 	   perf_handler[1024];
	int32_t	   service_id;
	
	 
} portier_packet;


unsigned long crc32_table[256];

static int passive_server_or_service_id;
static int passive_action;
static int passive_exit_code;
static char passive_perf_output[2048];
static char passive_output[2048];
static int use_ssl=0;


static char * passive_host_ip;
static int passive_host_port;

int portier_my_connect(char *host_name,int port,int *sd,char *proto);
int portier_my_tcp_connect(char *host_name,int port,int *sd);
unsigned long agent_v2_calculate_crc32(char *buffer, int buffer_size);
void agent_v2_generate_crc32_table(void);
void agent_v2_randomize_buffer(char *buffer,int buffer_size);
int bartlby_tcp_recvall(int s, char *buf, int *len, int timeout);
int bartlby_tcp_sendall(int s, char *buf, int *len);
void parse_options(int argc, char **argv);


void dispHelp(void) {
	
	printf("-h   display help\n");	
	printf("-s   server or service ID\n");	
	printf("-L   get a list of service ID's\n");	
	printf("-P   get Plugin parameters\n");	
	printf("-R   submit a plugin result + exit_code\n");	
#ifdef HAVE_SSL
	printf("-S   USE SSL\n");	
#endif
	printf("-m   output of your plugin\n");	
	printf("-z   Perfline!\n");	
	printf("-e   EXIT code\n");	
	printf("-i   IP of the passive host\n");	
	printf("-p   Port of the passive host\n");	
	
	exit(1);
	
	
}

void parse_options(int argc, char **argv) {
	static struct option longopts[] = {
		{ "help",	0, NULL, 'h'},
		{ "sid",	0, NULL, 's'},
		{ "svclist",	0, NULL, 'L'},
		{ "plgparms",	0, NULL, 'P'},
		{ "plgreturn",	0, NULL, 'R'},
		{ "ssl",	0, NULL, 'S'},
		{ "message",	0, NULL, 'm'},
		{ "perfoutput",	1, NULL, 'p'},
		{ "exitcode",	1, NULL, 'e'},
		{ "ip",	1, NULL, 'i'},
		{ "zort",	1, NULL, 'z'},
		{ "action",	1, NULL, 'a'},
		
		{ NULL,		0, NULL, 0}
	};
	int c;

	for (;;) {
		c = getopt_long(argc, argv, "i:z:LPRhs:a:Sm:p:e:a:", longopts, (int *) 0);
		if (c == -1)
			break;
		switch (c) {
		case 'h':  /* --help */
			dispHelp();
		break;
		case 'a':
			if(strcmp(optarg, "get_services") == 0) {
				passive_action=PORTIER_SVCLIST_PACKET;	
			}
			if(strcmp(optarg, "get_passive") == 0) {
				passive_action=PORTIER_REQUEST_PACKET;	
			}
			if(strcmp(optarg, "set_passive") == 0) {
				passive_action=PORTIER_RESULT_PACKET;	
			}
			
		break;
		case 'i':
			passive_host_ip=optarg;
				
		break;
		case 'p':
			passive_host_port=atoi(optarg);
				
		break;
		case 's':
			passive_server_or_service_id=atoi(optarg);
		break;
		case 'L':
			passive_action=PORTIER_SVCLIST_PACKET;
		break;
		
		case 'P':
			passive_action=PORTIER_REQUEST_PACKET;
		break;
		
		case 'R':
			passive_action=PORTIER_RESULT_PACKET;
		break;
		
		case 'S':
			use_ssl=1;
		break;
		case 'm':
			snprintf(passive_output, 2048, "%s", optarg);
		break;
		
		case 'z':
			snprintf(passive_perf_output, 2048, "%s", optarg);
		break;
		
		case 'e':
			passive_exit_code=atoi(optarg);
		break;
		
		default:
			dispHelp();
		}
	}
	
	
	
}      

void cmd_alarm_handler(int sig){

        printf("TIMEOUT!!!");
        
        exit(2);
        
       
       
}

int main(int argc, char ** argv) {
	/*
	static int passive_server_or_service_id;
static int passive_action;
static int passive_exit_code;
static char passive_perf_output[2048];
static char passive_output[2048];

*/

	int sd;
	
#ifdef HAVE_SSL 
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
#endif     
	u_int32_t packet_crc32;
	u_int32_t calculated_crc32;
	int16_t result;
	int rc;
	portier_packet send_packet;
	portier_packet receive_packet;
	int bytes_to_send;
	int bytes_to_recv;
     
	signal(SIGALRM,cmd_alarm_handler);
      /* generate the CRC 32 table */
	agent_v2_generate_crc32_table();
	
	
	
	passive_server_or_service_id=0;
	passive_action=0;
	passive_exit_code=-1;
	passive_host_port=-1;
		
	
	sprintf(passive_perf_output, " ");
	passive_host_ip = NULL;
	sprintf(passive_output, " ");
	
	parse_options(argc, argv);
	
	
	if(passive_host_ip == NULL || passive_host_port == -1 || passive_server_or_service_id == 0) {
		printf("host (-i) and port (-p) must be set and server/serivce-id (-s)!! \n");
		exit(0);	
	}
	
	bzero(&send_packet,sizeof(send_packet));
	/* fill the packet with semi-random data */
     	agent_v2_randomize_buffer((char *)&send_packet,sizeof(send_packet));
	
	send_packet.service_id = (int32_t)passive_server_or_service_id;
	sprintf(send_packet.plugin, " ");
	sprintf(send_packet.cmdline, " ");
	sprintf(send_packet.perf_handler, " ");
	sprintf(send_packet.output, " ");
	
#ifdef HAVE_SSL
	SSL_library_init();
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
#endif
	
	switch(passive_action) {
		case PORTIER_SVCLIST_PACKET:
			send_packet.packet_type=(int16_t)htons(PORTIER_SVCLIST_PACKET);
			
		break;
		
		case PORTIER_RESULT_PACKET:
			send_packet.packet_type=(int16_t)htons(PORTIER_RESULT_PACKET);
			sprintf(send_packet.output, "%s", passive_output);
			sprintf(send_packet.perf_handler, "%s", passive_perf_output);
			send_packet.exit_code=(int16_t)passive_exit_code;
			printf("submitting check result\n");
		break;
		
		case PORTIER_REQUEST_PACKET:
			send_packet.packet_type=(int16_t)htons(PORTIER_REQUEST_PACKET);
			
		break;
		
		default:
			printf("no action set!!\n");
			exit(1);			
	}
	send_packet.crc32_value=(u_int32_t)0L;
	calculated_crc32=agent_v2_calculate_crc32((char *)&send_packet,sizeof(send_packet));
	send_packet.crc32_value=(u_int32_t)htonl(calculated_crc32);
	bytes_to_send=sizeof(send_packet);


#ifdef HAVE_SSL
	if(use_ssl == 1) {
		
		meth=SSLv23_client_method();
       	if((ctx=SSL_CTX_new(meth))==NULL){
			printf("%s", "AgentV2: Error - could not create SSL context.\n");
			exit(2);
		}
		/* use only TLSv1 protocol */
		SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	}
#endif

	alarm(PORTIER_TIMEOUT);
	result=portier_my_tcp_connect(passive_host_ip,passive_host_port,&sd);
	
	
	
#ifdef HAVE_SSL	
	if(use_ssl == 1) {
		/* do SSL handshake */
		if((ssl=SSL_new(ctx))!=NULL){
			SSL_CTX_set_cipher_list(ctx,"ADH");
			SSL_set_fd(ssl,sd);
			
			rc=SSL_connect(ssl);
			
			
			alarm(PORTIER_TIMEOUT);
				
			if(rc !=1){
				printf("CMD: Error - Could not complete SSL handshake.");
				exit(2);
			}
		} else {
			printf("CMD: Error - Could not create SSL connection structure."); 
			SSL_CTX_free(ctx);
			close(sd);
			exit(1);
		}
	} 
#endif
	
	
	alarm(PORTIER_TIMEOUT);
#ifdef HAVE_SSL
	if(use_ssl == 1) {
		rc=SSL_write(ssl,&send_packet,bytes_to_send);
	} else {
#endif
		
		rc=bartlby_tcp_sendall(sd,(char *)&send_packet,&bytes_to_send);
		
			
#ifdef HAVE_SSL
	}
#endif
	
	if(rc<0)
       	rc=-1;

	if(rc==-1){
		printf("CMD: Error sending to host");
		close(sd);
		exit(2);
	}
     	bytes_to_recv=sizeof(receive_packet);
	
	alarm(PORTIER_TIMEOUT);
	
#ifdef HAVE_SSL
	if(use_ssl == 1) {
		rc=SSL_read(ssl,&receive_packet,bytes_to_recv);
	} else {
#endif       
       
       rc=bartlby_tcp_recvall(sd,(char *)&receive_packet,&bytes_to_recv,PORTIER_TIMEOUT);
       
#ifdef HAVE_SSL       
	}
#endif
	alarm(0);

#ifdef HAVE_SSL 		
	if(use_ssl == 1) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}
#endif

	close(sd);
	
	if(rc<0){
		printf("CMD: Error receiving data from agent");
		exit(2);
	}else if(rc==0){
		printf("CMD: Received 0 bytes from agent");
		exit(2);
	}else if(bytes_to_recv<sizeof(receive_packet)){
		printf("CMD: Receive underflow - only %d bytes received (%ld expected).\n",bytes_to_recv,sizeof(receive_packet));
		exit(2);
	}
           
	packet_crc32=ntohl(receive_packet.crc32_value);
	receive_packet.crc32_value=0L;
	calculated_crc32=agent_v2_calculate_crc32((char *)&receive_packet,sizeof(receive_packet));
	if(packet_crc32!=calculated_crc32){
		printf("CMD: Response packet had invalid CRC32.");
		exit(2);
	}	
	
	
	//ntohs(receive_packet.packet_type)
	
	switch(ntohs(receive_packet.packet_type)) {
		
		case PORTIER_SVCLIST_PACKET:
			
			printf("%s", receive_packet.output);
			exit(1);
		break;
		
		case PORTIER_RESULT_PACKET:
			printf("Packet submitted\n");
			exit(2);
		break;
		
		case PORTIER_REQUEST_PACKET:
			printf("%s %s", receive_packet.plugin, receive_packet.cmdline);
			
			exit(2);
		break;
		
		default:
			printf("no packet type returned or either wrong packet type (%d)\n", ntohs(receive_packet.packet_type));
			exit(1);	
		
	}
	
	return 1;
		
}      
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       

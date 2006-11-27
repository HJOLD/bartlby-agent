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


#ifdef HAVE_SSL
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "bartlby_v2_dh.h"
#endif


static int use_ssl=1;
char * cfg_use_ssl;

static int connection_timed_out=0;

int bartlby_tcp_recvall(int s, char *buf, int *len, int timeout);
int bartlby_tcp_sendall(int s, char *buf, int *len);
static void agent_conn_timeout(int signo);
char * getConfigValue(char * key, char * fname);
unsigned long agent_v2_calculate_crc32(char *buffer, int buffer_size);
void agent_v2_generate_crc32_table(void);
void agent_v2_do_check(int sock, char * cfgfile);
void agent_v2_randomize_buffer(char *buffer,int buffer_size);

static unsigned long crc32_table[256];
typedef struct v2_packet_struct{

	u_int32_t crc32_value;
	int16_t   exit_code;
	int16_t   packet_type;
	char      output[2048];
	char      cmdline[2048];
	char      plugin[2048];
	char 	   perf_handler[1024];
	
	 
} agent_v2_packet;



#define AGENT_V2_SENT_PACKET 1
#define AGENT_V2_RETURN_PACKET 2
#define CONN_TIMEOUT 60

#ifdef HAVE_SSL
SSL_METHOD *meth;
SSL_CTX *ctx;
#endif


int main(int argc, char **argv){
		
#ifdef HAVE_SSL
	DH *dh;
#endif
	
	char seedfile[FILENAME_MAX];
	int i,c;
	
	
	/* open a connection to the syslog facility */
	openlog("bartlby_agent-v2-d",LOG_PID,LOG_DAEMON);
	/* generate the CRC 32 table */
	agent_v2_generate_crc32_table();
	
	cfg_use_ssl=getConfigValue("agent_use_ssl", argv[argc-1]);
	if(cfg_use_ssl == NULL) {
		use_ssl = 1;	
	} else {
		use_ssl=atoi(cfg_use_ssl);
		free(cfg_use_ssl);
	}
	syslog(LOG_ERR, "use_ssl: %d cfg_file: %s", use_ssl, argv[argc-1]);
	
#ifdef HAVE_SSL
	if(use_ssl == 1) {
		SSL_library_init();
		SSLeay_add_ssl_algorithms();
		meth=SSLv23_server_method();
		SSL_load_error_strings();
		
		/* use week random seed if necessary */
		if((RAND_status()==0)){
			if(RAND_file_name(seedfile,sizeof(seedfile)-1))
				if(RAND_load_file(seedfile,-1))
					RAND_write_file(seedfile);
		
			if(RAND_status()==0){
				syslog(LOG_ERR,"Warning: SSL/TLS uses a weak random seed which is highly discouraged");
				srand(time(NULL));
				for(i=0;i<500 && RAND_status()==0;i++){
					for(c=0;c<sizeof(seedfile);c+=sizeof(int)){
						*((int *)(seedfile+c))=rand();
					        }
					RAND_seed(seedfile,sizeof(seedfile));
					}
				}
			}
		
		if((ctx=SSL_CTX_new(meth))==NULL){
			syslog(LOG_ERR,"Error: could not create SSL context.\n");
			exit(2);
		}
		
		
		SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
		
		/* use anonymous DH ciphers */
		SSL_CTX_set_cipher_list(ctx,"ADH");
		dh=get_dh512();
		SSL_CTX_set_tmp_dh(ctx,dh);
		DH_free(dh);
	}
#endif
	
	//as we are running under inetd!!
	close(2);
	open("/dev/null",O_WRONLY);
	
	agent_v2_do_check(0, argv[argc-1]);

#ifdef HAVE_SSL
	SSL_CTX_free(ctx);
#endif
	return 0;
	
	
}

void agent_v2_do_check(int sock, char * cfgfile)  {
	u_int32_t calculated_crc32;
	agent_v2_packet send_packet;
	agent_v2_packet receive_packet;
	int bytes_to_send;
	int bytes_to_recv;
	int rc;
	
	char plugin_output[1024];
	int plugin_rtc;
	FILE * fplg;
	struct stat plg_stat;
	char  * plugin_path;
	char * plugin_dir;
	char * exec_str;
	struct sigaction act1, oact1;
	char * allowed_ip_list;
	char * token;
	struct sockaddr_in name;
	int namelen = sizeof(name);
	int ip_ok=-1;
	
	
	u_int32_t packet_crc32;

#ifdef HAVE_SSL
	SSL *ssl=NULL;
#endif
	
	allowed_ip_list=getConfigValue("allowed_ips", cfgfile);
	if(allowed_ip_list == NULL) {
        	syslog(LOG_ERR,"No allowed IP");
        	exit(1);
        	
        }
        
        
        token=strtok(allowed_ip_list,",");
        
        if (getpeername(0,(struct sockaddr *)&name, &namelen) < 0) {
   		syslog(LOG_ERR, "getpeername failed");
   		exit(1);
   	}
        
        while(token != NULL) {
        	if(strcmp(token, inet_ntoa(name.sin_addr)) == 0) {
        		ip_ok=0;	
        	}
        	token=strtok(NULL, ",");	
        }
        free(allowed_ip_list);
        
        if(ip_ok < 0) {
        	//sleep(1);
        	syslog(LOG_ERR, "ip blocked");
		exit(1);
        }
	
	
	plugin_dir=getConfigValue("agent_plugin_dir", cfgfile);
	if(plugin_dir == NULL) {
		syslog(LOG_ERR,"plugin dir failed");	
		exit(1);
	}
	
	act1.sa_handler = agent_conn_timeout;
	sigemptyset(&act1.sa_mask);
	act1.sa_flags=0;
	#ifdef SA_INTERRUPT
	act1.sa_flags |= SA_INTERRUPT;
	#endif
	if(sigaction(SIGALRM, &act1, &oact1) < 0) {
		
		syslog(LOG_ERR,"alarm setup error");
		exit(1);
		
	}
	
	
	
	
//	signal(SIGALRM,agent_v2_alarm_handler);
	bytes_to_recv=sizeof(receive_packet);
	
#ifdef HAVE_SSL
		if(use_ssl == 1) {
			if((ssl=SSL_new(ctx))==NULL){
				syslog(LOG_ERR,"SSL init error");	
				return;
			}
	       	
			SSL_set_fd(ssl,sock);
			/* keep attempting the request if needed */
			while(((rc=SSL_accept(ssl))!=1) && (SSL_get_error(ssl,rc)==SSL_ERROR_WANT_READ));
              	
			if(rc!=1){
				syslog(LOG_ERR,"Error: Could not complete SSL handshake. %d (%s)\n",SSL_get_error(ssl,rc), ERR_error_string(ERR_get_error(), NULL));
				return;
			}
			while(((rc=SSL_read(ssl,&receive_packet,bytes_to_recv))<=0) && (SSL_get_error(ssl,rc)==SSL_ERROR_WANT_READ));
		} else {
#endif
		
			rc=bartlby_tcp_recvall(sock,(char *)&receive_packet,&bytes_to_recv,CONN_TIMEOUT);
		
#ifdef HAVE_SSL
		}
#endif
		/* recv() error or client disconnect */
		if(rc<=0){
			/* log error to syslog facility */
			syslog(LOG_ERR,"Could not read request from client bye bye ...");
#ifdef HAVE_SSL			
			if(use_ssl == 1) {
				if(ssl){
					SSL_shutdown(ssl);
					SSL_free(ssl);
				}
			}
#endif
			return;
			
		}
		if(bytes_to_recv!=sizeof(receive_packet)){

	
			/* log error to syslog facility */
			syslog(LOG_ERR,"Data packet from client was too short, bye bye ...");
			
#ifdef HAVE_SSL			
			if(use_ssl == 1) {
				if(ssl){
					SSL_shutdown(ssl);
					SSL_free(ssl);
				}
			}
#endif
			
			return;		
			
		}
		packet_crc32=ntohl(receive_packet.crc32_value);
		receive_packet.crc32_value=0L;
		calculated_crc32=agent_v2_calculate_crc32((char *)&receive_packet,sizeof(receive_packet));
		if(packet_crc32!=calculated_crc32){
			syslog(LOG_ERR,"Error: Request packet had invalid CRC32.");
			return;
		}
		if(ntohs(receive_packet.packet_type)!=AGENT_V2_SENT_PACKET){
			syslog(LOG_ERR,"Error: WRONG packet type.");
			return;
		}
		
		receive_packet.cmdline[2048-1]='\0';
		receive_packet.plugin[2048-1]='\0';
		receive_packet.perf_handler[1024-1]='\0';
		receive_packet.output[2048-1]='\0';
		
		if(!strcmp(receive_packet.plugin,"")){
			syslog(LOG_ERR,"Error: no plugin supplied");
			return;	
		}
		
		//syslog(LOG_ERR,"Host is asking for command '%s - %s' to be run...",receive_packet.plugin, receive_packet.cmdline);
		
		/* clear the response packet buffer */
		bzero(&send_packet,sizeof(send_packet));
	
		/* fill the packet with semi-random data */
		agent_v2_randomize_buffer((char *)&send_packet,sizeof(send_packet));
				
		//Empty optional fields ;)
		sprintf(send_packet.perf_handler, " ");
		
		
		plugin_path=malloc(sizeof(char) * (strlen(plugin_dir)+strlen(receive_packet.plugin)+255));
		sprintf(plugin_path, "%s/%s", plugin_dir, receive_packet.plugin);
		
		if(stat(plugin_path,&plg_stat) < 0) {
			sprintf(send_packet.output, "plugin does not exist");
			send_packet.exit_code=(int16_t)2;
			goto sendit;
			
		}
		
		exec_str=malloc(sizeof(char) * (strlen(plugin_path)+strlen(receive_packet.cmdline)+255));
		sprintf(exec_str, "%s %s", plugin_path, receive_packet.cmdline);
		
		fplg=popen(exec_str, "r");
		if(fplg != NULL) {
			connection_timed_out=0;
			alarm(CONN_TIMEOUT);
			if(fgets(plugin_output, 1024, fplg) != NULL) {
				if(strncmp(plugin_output, "PERF: ", 6) == 0) {
					sprintf(send_packet.perf_handler,"%s", plugin_output);
					if(fgets(plugin_output, 1024, fplg) != NULL) {
						plugin_rtc=pclose(fplg);
						plugin_output[strlen(plugin_output)-1]='\0';
						
						send_packet.exit_code=(int16_t)WEXITSTATUS(plugin_rtc);
						sprintf(send_packet.output, "%s", plugin_output);
						goto sendit;
												
					} else {
						plugin_rtc=pclose(fplg);
						send_packet.exit_code=(int16_t)WEXITSTATUS(plugin_rtc);
						sprintf(send_packet.output, "not output (perf)");
							
					}
					
				} else {
					plugin_rtc=pclose(fplg);
					send_packet.exit_code=(int16_t)WEXITSTATUS(plugin_rtc);
					sprintf(send_packet.output, "%s", plugin_output);	
				}	
			} else {
				plugin_rtc=pclose(fplg);
				send_packet.exit_code=(int16_t)WEXITSTATUS(plugin_rtc);
				sprintf(send_packet.output, "not output (normal)");	
			}
		} else {
			sprintf(send_packet.output, "plugin open failed");
			send_packet.exit_code=(int16_t)2;	
			goto sendit;
		}
		if(connection_timed_out == 1) {
			sprintf(send_packet.output, "plugin timed out");
			send_packet.exit_code=(int16_t)2;		
		}
		connection_timed_out=0;
		alarm(0);
		
		
		
		
sendit:		
		
		
		/* initialize response packet data */
		send_packet.packet_type=(int16_t)htons(AGENT_V2_RETURN_PACKET);
		/* calculate the crc 32 value of the packet */
		send_packet.crc32_value=(u_int32_t)0L;
		calculated_crc32=agent_v2_calculate_crc32((char *)&send_packet,sizeof(send_packet));
		send_packet.crc32_value=(u_int32_t)htonl(calculated_crc32);
		
		
		
		bytes_to_send=sizeof(send_packet);

#ifdef HAVE_SSL		
		if(use_ssl == 1) {
			SSL_write(ssl,&send_packet,bytes_to_send);
			if(ssl){
				SSL_shutdown(ssl);
				SSL_free(ssl);
			}
		} else {
#endif
			bartlby_tcp_sendall(sock,(char *)&send_packet,&bytes_to_send);
			
#ifdef HAVE_SSL
		}
#endif
		
		
	
		
		
}


void agent_v2_randomize_buffer(char *buffer,int buffer_size){
	FILE *fp;
	int x;
	int seed;

	/**** FILL BUFFER WITH RANDOM ALPHA-NUMERIC CHARACTERS ****/

	/***************************************************************
	   Only use alpha-numeric characters becase plugins usually
	   only generate numbers and letters in their output.  We
	   want the buffer to contain the same set of characters as
	   plugins, so its harder to distinguish where the real output
	   ends and the rest of the buffer (padded randomly) starts.
	***************************************************************/

	/* try to get seed value from /dev/urandom, as its a better source of entropy */
	fp=fopen("/dev/urandom","r");
	if(fp!=NULL){
		seed=fgetc(fp);
		fclose(fp);
	        }

	/* else fallback to using the current time as the seed */
	else
		seed=(int)time(NULL);

	srand(seed);
	for(x=0;x<buffer_size;x++)
		buffer[x]=(int)'0'+(int)(72.0*rand()/(RAND_MAX+1.0));

	return;
        }
      

void agent_v2_generate_crc32_table(void){
	unsigned long crc, poly;
	int i, j;

	poly=0xEDB88320L;
	for(i=0;i<256;i++){
		crc=i;
		for(j=8;j>0;j--){
			if(crc & 1)
				crc=(crc>>1)^poly;
			else
				crc>>=1;
		        }
		crc32_table[i]=crc;
                }

	return;
}

/* calculates the CRC 32 value for a buffer */
unsigned long agent_v2_calculate_crc32(char *buffer, int buffer_size){
	register unsigned long crc;
	int this_char;
	int current_index;

	crc=0xFFFFFFFF;

	for(current_index=0;current_index<buffer_size;current_index++){
		this_char=(int)buffer[current_index];
		crc=((crc>>8) & 0x00FFFFFF) ^ crc32_table[(crc ^ this_char) & 0xFF];
	        }

	return (crc ^ 0xFFFFFFFF);
        }        
        
static void agent_conn_timeout(int signo) {
 	connection_timed_out = 1;
}



/* sends all data - thanks to Beej's Guide to Network Programming */
int bartlby_tcp_sendall(int s, char *buf, int *len){
	int total=0;
	int bytesleft=*len;
	int n=0;

	/* send all the data */
	while(total<*len){

		/* send some data */
		n=send(s,buf+total,bytesleft,0);

		/* break on error */
		if(n==-1)
			break;

		/* apply bytes we sent */
		total+=n;
		bytesleft-=n;
	        }

	/* return number of bytes actually send here */
	*len=total;

	/* return -1 on failure, 0 on success */
	return n==-1?-1:0;
        }


/* receives all data - modelled after sendall() */
int bartlby_tcp_recvall(int s, char *buf, int *len, int timeout){
	int total=0;
	int bytesleft=*len;
	int n=0;
	time_t start_time;
	time_t current_time;
	
	/* clear the receive buffer */
	bzero(buf,*len);

	time(&start_time);

	/* receive all data */
	while(total<*len){

		/* receive some data */
		n=recv(s,buf+total,bytesleft,0);

		/* no data has arrived yet (non-blocking socket) */
		if(n==-1 && errno==EAGAIN){
			time(&current_time);
			if(current_time-start_time>timeout)
				break;
			sleep(1);
			continue;
		        }

		/* receive error or client disconnect */
		else if(n<=0)
			break;

		/* apply bytes we received */
		total+=n;
		bytesleft-=n;
	        }

	/* return number of bytes actually received here */
	*len=total;

	/* return <=0 on failure, bytes received on success */
	return (n<=0)?n:total;
        }
        



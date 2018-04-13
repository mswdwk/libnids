/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "nids.h"
#include "flv.h"
#include "util.h"


#define LOG_MAX 100
#define SZLACZEK "\n--------------------------------------------------\n"

// data is used to locate flv stream 
int deal_with_flv_video(struct tcp_stream *a_tcp,FLV_FLOW_HEADER*h)
{
	struct half_stream*client = &a_tcp->client;
	char *data = (char*)client->data;;
	int data_len = client->count - client->offset;
	int discard_data_len = 0, remaind_data_len = data_len;
	int last_prev_tag_size = 0,last_need_data_len = 0, last_size = 15;
	
	//	printf("flv_flow_id %d tag_id %d data_len %d read %d bufsize %d rmem_alloc %d count %d lpts %d\n",h->flv_flow_id,
	//	h->tag_id,data_len,a_tcp->read,client->bufsize,client->rmem_alloc,client->count,last_prev_tag_size);
	if(!h->record_flv_header_ok){
		if(data_len - h->flv_offset >=  (int)sizeof(FLV_HEADER)) {
			data += h->flv_offset;
			fwrite(data,sizeof(FLV_HEADER),1,h->fp);
			h->record_flv_header_ok = 1;
			discard_data_len += (int)sizeof(FLV_HEADER) + h->flv_offset;
			remaind_data_len -= ((int)sizeof(FLV_HEADER) + h->flv_offset);
			data += sizeof(FLV_HEADER);
			h->last_need_data_len = 15;
		}else{
			goto discard_data;
		}
	}
	
	int get_data_len = 0, prev_tag_size = 0, tag_data_size = 0 ,new_need_data_len = 0,offset = 0;;
	FLV_TAG *ftag ;
	
	printf("flow_id %2d data_len %7d last_need_len %7d read %7d bufsize %7d remaind_data_len %7d\n",h->flv_flow_id,data_len,
		h->last_need_data_len,a_tcp->read,client->bufsize,remaind_data_len);

	while( remaind_data_len >= h->last_need_data_len ){
		ftag = (FLV_TAG*)(data + offset);
		prev_tag_size = ntohl(ftag->prev_tag_size);
		if(prev_tag_size != h->last_prev_tag_size){
			//printf("flv data error:tag_id %3d prev_tag_size %u !=  %u last_prev_tag_size. client->count_new %u count %8u offset %8u %8d\n",h->tag_id,prev_tag_size,h->last_prev_tag_size,client->count_new,client->count,client->offset,remaind_data_len);
			//dump_print("FLV_TAG_HEADER", 64, ftag);
			//ready to destructor 
			//flv_stream_destruct(h->flv_flow_id);
			
			if( remaind_data_len > offset ){
				//data++;
				offset++;
				discard_data_len++;
				continue;
			}
			
			nids_discard(a_tcp, discard_data_len);
			//exit(0);
			return -1;
		}else if(prev_tag_size == h->last_prev_tag_size && offset ){
			printf("flow_id %2d tag_id %d data_len %7d found offset %d \n",h->flv_flow_id,h->tag_id,data_len,offset);
		}
		
		GET_FLV_TAG_DATA_SIZE(tag_data_size,&ftag->tag_header);
		new_need_data_len = tag_data_size + 15;
		if(new_need_data_len > remaind_data_len){
			h->last_need_data_len = new_need_data_len;
			//discard_data_len += remaind_data_len;
			printf("tag_id %d need_data_len %u > remaind_data_len %u, discard_data_len %u\n",h->tag_id,new_need_data_len ,remaind_data_len ,
			discard_data_len);
			dump_print("FLV_TAG_HEADER", 64, ftag);
			goto discard_data;
		}
		
		//fwrite(&ftag->prev_tag_size,4,1,h->fp);
		fwrite(ftag,sizeof(FLV_TAG),1,h->fp);
		fwrite(ftag->tag_data,tag_data_size,1,h->fp);
			h->last_prev_tag_size = tag_data_size + 11;
		
		h->tag_id++;
		discard_data_len += new_need_data_len ;
		remaind_data_len -= new_need_data_len ;
		remaind_data_len -= offset ;
					data += new_need_data_len ;
		
		printf("tag_id %4u tag_data_size %8u discard_data_len %7d\n",h->tag_id, tag_data_size,discard_data_len);
		//printf("last_prev_tag_size %8u prev_tag_size %8u tag_id %4u tag_data_size %8u\n",h->last_prev_tag_size,prev_tag_size,h->tag_id, tag_data_size);
	
		tag_data_size = 0;
		h->last_need_data_len = 15;
	}
	
discard_data:	
	nids_discard(a_tcp,discard_data_len);
	return 0;
}

int get_tcp_stream_keyword(struct tcp_stream *a_tcp,struct keyword*key)
{
	int flv_strem_index = is_http_flv_stream( a_tcp );

	if( flv_strem_index != -1)	goto find_flv_video;
	else{
		int offset = find_flv_header(a_tcp->client.data, a_tcp->client.count_new);
		if( offset !=-1 ){
			flv_strem_index = process_http_flv_stream_header(a_tcp,offset);
			if(-1 != flv_strem_index )	goto find_flv_video;
		}
	}
	
	return INVAILD_KEYWORD;
	
find_flv_video:
	key->type = FLV_VIDEO;
	key->data = (void*)&flv_stream_table[flv_strem_index];
	return FLV_VIDEO;
}

int deal_with_tcp_stream_keyword(struct tcp_stream *a_tcp,struct keyword* keyword)
{	
	int type = keyword->type;
	switch(type){
	case FLV_VIDEO: deal_with_flv_video(a_tcp,keyword->data); break;
	default:break;
	}
	return 0;
}

void tcp_data_recognition(struct tcp_stream *a_tcp)
{
	struct keyword key;
	get_tcp_stream_keyword(a_tcp,&key);
	deal_with_tcp_stream_keyword(a_tcp,&key);
}

int logfd,client_logfd;
void
do_log (int f,char *data,int len)
{
  //write (logfd, adres_txt, strlen (adres_txt));
  write (f, data, len);
  //write (logfd, SZLACZEK, strlen (SZLACZEK));
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
  char buf[1024];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
    // connection described by a_tcp is established
    // here we decide, if we wish to follow this stream
    // sample condition: if (a_tcp->addr.dest!=23) return;
    // in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      a_tcp->server.collect_urg++; // we want urgent data received by a
                                   // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
      strcat (buf, " established\n");
	//do_log (buf);
	if(a_tcp->client.count_new)printf("client data %p count %d count_new %d\n",a_tcp->client.data,a_tcp->client.count,a_tcp->client.count_new);
	  //find_flv_header(a_tcp->client.data, a_tcp->client.count_new);

      return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE)
    {
      // connection has been closed normally
      //fprintf (stderr, "%s closing\n", buf);
	  strcat (buf, " closing\n");
	//do_log (buf);
	  
      return;
    }
  if (a_tcp->nids_state == NIDS_RESET)
    {
      // connection has been closed by RST
      //fprintf (stderr, "%s reset\n", buf);
	  strcat (buf, " reset\n");
	//do_log (buf);
      return;
    }

  if (a_tcp->nids_state == NIDS_DATA)
    {
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not

      struct half_stream *hlf;

      if (a_tcp->server.count_new_urg)
      {
        // new byte of urgent data has arrived 
        strcat(buf,"(urgent->)");
        buf[strlen(buf)+1]=0;
        buf[strlen(buf)]=a_tcp->server.urgdata;
        write(1,buf,strlen(buf));
        return;
      }
      // We don't have to check if urgent data to client has arrived,
      // because we haven't increased a_tcp->client.collect_urg variable.
      // So, we have some normal data to take care of.
      if (a_tcp->client.count_new)
	{
          // new data for client
	  hlf = &a_tcp->client; // from now on, we will deal with hlf var,
                                // which will point to client side of conn
	  strcat (buf, "(<-)"); // symbolic direction of data
	}
      else
	{
	  hlf = &a_tcp->server; // analogical
	  strcat (buf, "(->)");
	}
    //fprintf(stderr,"%s\n",buf); // we print the connection parameters
                              // (saddr, daddr, sport, dport) accompanied
                              // by data flow direction (-> or <-)

   //write(2,hlf->data,hlf->count_new); // we print the newly arrived data
	
	//printf("%d\n",hlf->count_new);
	if(a_tcp->server.count_new)do_log(logfd,a_tcp->server.data,a_tcp->server.count_new);
	if(a_tcp->client.count_new && a_tcp->client.data){
		//do_log(client_logfd,a_tcp->client.data,a_tcp->client.count_new);
		tcp_data_recognition(a_tcp);
	}
      memset(buf,0,sizeof(buf));
  	}
  return ;
}

int 
main ()
{
	logfd = open ("./logfile", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (logfd < 0)
	  {
		perror ("opening ./logfile:");
		exit (1);
	  }
	client_logfd = open ("./client_logfile", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (client_logfd < 0)
	  {
		perror ("opening ./client_logfile:");
		exit (1);
	  }

  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;
  nids_params.filename = "test.pcap";
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  
  memset(flv_stream_table,0,sizeof(flv_stream_table));
  
  nids_register_tcp (tcp_callback);
  //nids_register_udp ();
  nids_run ();
  return 0;
}


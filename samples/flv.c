#include <stdio.h>
#include "flv.h"
#include "pcap_parse.h"
#include "rte_jhash.h"
#include "ring_buffer.h"
#include "nids.h"
#include "util.h"

FLV_FLOW_HEADER flv_stream_table[MAX_FLV_STREAM_NUM];

// flag means is or not flv header
inline int record_flv_data(FLV_FLOW_HEADER*h,FLV_TAG*tag,int data_size)
{
	if(!h||!tag || data_size < 0)return -1;
	FILE*fp = h->fp;
	fwrite(&tag->prev_tag_size,sizeof(int),1,fp);
	fwrite(&tag->tag_header,sizeof(FLV_TAG_HEADER),1,fp);
	fwrite(tag->tag_data,data_size,1,fp);
	//h->flvfp.prev_tag_id = tag->tag_id;
	h->flvfp.prev_tag_size = data_size + sizeof(FLV_TAG_HEADER);
	return 0;
}

void * consumer_proc(void *arg)
{
#if 0
	if(!arg){
		printf("error thread arg\n");
		return NULL;
	}
	FLV_FLOW_HEADER*h = (FLV_FLOW_HEADER*)arg;
    struct ring_buffer *ring_buf = h->ring_buf;
    FLV_TAG ftag;
    //FLV_TAG_HEADER *ftagheader;
	uint get_data_len = 0, need_data_len = 0;
	int tag_data_size = 0;
	unsigned int last_prev_tag_size = h->flvfp.prev_tag_size;
	unsigned int prev_tag_size = sizeof(FLV_TAG_HEADER); // current tag size
	unsigned int last_tag_size = 0;//ring_data_buf_len = 0;
	//int offset = 0;
	
	#if 1
	char *tag_data_buf= calloc(1,RING_BUFFER_SIZE);
	h->thread_run = 1;
    while(ring_buf != NULL && h->thread_run )
    {
        //printf("get a flv stream info from ring buffer.\n");
		get_data_len = 0;
		need_data_len = sizeof(int) + sizeof(FLV_TAG_HEADER);
		while((ring_data_len(ring_buf) < need_data_len) &&  ! h->stream_last_packet)usleep(100);
		get_data_len = ring_buffer_get(ring_buf, (void *)&ftag, need_data_len);
		if(get_data_len != need_data_len)goto end;
		prev_tag_size = ntohl(ftag.prev_tag_size);
		GET_FLV_TAG_DATA_SIZE(tag_data_size,&ftag.tag_header);
		need_data_len = tag_data_size;
		if(tag_data_size >= RING_BUFFER_SIZE){
			printf("tag_data_size %u is >= RING_BUFFER_SIZE %u\n",tag_data_size ,RING_BUFFER_SIZE);
			break;
		}
		if(prev_tag_size != last_tag_size){
			printf("flv data error:prev_tag_size %u !=  %u last_tag_size. ring_data_len %u\n",
				prev_tag_size,last_tag_size,ring_data_len(ring_buf));
			dump_print("FLV_TAG_HEADER", get_data_len, &ftag);
			#if 0
			FLV_FLOW_ITEM*item = (FLV_FLOW_ITEM*)queue_peek(h->flv_pkt_queue);
			if(item){
				//printf("queue_size %u queue_peek pkt_id %5u seqno %10u\n",queue_size(h->flv_pkt_queue),item->pkt_id,ntohl(item->tcpflow.tcph->SeqNO));
			}
			//dump_print("ring_buf", , ring_buf->buffer);
			#endif
			break;
		}
		
		while((ring_data_len(ring_buf) < need_data_len) && ! h->stream_last_packet)usleep(100);
		get_data_len = ring_buffer_get(ring_buf,( void*)tag_data_buf, need_data_len);
		if(get_data_len != need_data_len)goto end;
		ftag.tag_data = tag_data_buf;
		//ftag.tag_id = h->flvfp.prev_tag_id + 1;
		record_flv_data(h,&ftag,tag_data_size);
		//printf("last_prev_tag_size %8u prev_tag_size %8u tag_id %4u tag_data_size %8u\n",last_prev_tag_size,prev_tag_size,ftag.tag_id, tag_data_size);
		
		last_prev_tag_size = prev_tag_size;
		last_tag_size = tag_data_size + sizeof(FLV_TAG_HEADER);
		tag_data_size = 0;
    }
	#else
	//queue_dequeue(h->flv_pkt_queue, &item);
	#endif
end:
	if(tag_data_buf)free(tag_data_buf);
	tag_data_buf = NULL;
	printf("thread_id %zu quit\n",pthread_self());
	pthread_detach(pthread_self());
    return (void *)ring_buf;
#endif	
}

pthread_t consumer_thread(void *arg)
{
    int err;
    pthread_t tid;
    err = pthread_create(&tid, NULL, consumer_proc, arg);
    if (err != 0)
    {
        fprintf(stderr, "Failed to create consumer thread.errno:%u, reason:%s\n",
            errno, strerror(errno));
        return -1;
    }
    printf("consumer thread id %zu\n",tid);
    return tid;
}

int find_flv_header(void*data,int len)
{
    unsigned char *ch = (unsigned char*)data;
    //char *flv_val = flv_val_header.val;
    int i ;
	int flv_ver_flag = htonl(0x464C5601);
    for( i = 0; i < len - 3 ; ++i){
        if( *(int*)ch == flv_ver_flag){
			FLV_HEADER*flv_head = (FLV_HEADER*)ch;
			if((flv_head->Flags&0xfa) != 0x00)	continue;
			if(flv_head->Headersize != htonl(9))	continue;
			int previous_tag_size = *(int*)(flv_head + 1);
			if( 0 == previous_tag_size )
			{
				printf("find 0x464C5601 offset %u\n",i);
				return i; // maybe return 0 ? may cause problem. Attention!!!
			}else{
				printf("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
					*(ch+4),*(ch+5),*(ch+6),
					flv_header_data[4],flv_header_data[5],flv_header_data[6]);
			}
        }
        ch++;
    }
    
    return -1;
}

int ip_flow_hash(IP_FLOW*flow)
{
	int hash = 0;
	if(!flow)
		return -1;
	int c = (flow->high_port<<16)|flow->low_port;
	hash = rte_jhash_3words(flow->high_ip, flow->low_ip, c,hash);
	flow->hash = hash;
	return hash;
}

void FLV_FLOW_FREE(void*data)
{
	if(!data)return;
	FLV_FLOW_ITEM*flow = (FLV_FLOW_ITEM*)data;
	
	if(flow->tcpflow.data)free(flow->tcpflow.data);
	if(flow->tcpflow.tcph)free(flow->tcpflow.tcph);
	
	// release this node
	if(flow->prev){
		flow->prev->next = flow->next;
	}
	if(flow->next)
		flow->next->prev = flow->prev;
	//flow->refcnt--;
	if(flow)free(flow);
}

/*
** @return ,return the stream id.
*/

int is_http_flv_stream(struct tcp_stream*a_tcp)
{
	// search flv stream table;
	int i ;
	for(i = 0; i < MAX_FLV_STREAM_NUM; ++i){
		if ( a_tcp && flv_stream_table[i].tcp_stream == a_tcp){
			return i;
		}
	}
	
	return -1;
}

int flv_stream_construct(int i,struct tcp_stream*a_tcp,int offset)
//IP_FLOW *flv,TCPHeader_t*tcph,void*data,int len,int flv_offset,int pkt_id;
{
	flv_stream_table[i].tcp_stream = (void*)a_tcp;
	flv_stream_table[i].flv_flow_id = i;
	flv_stream_table[i].flv_offset = offset;

	FLV_FLOW_HEADER *h = &flv_stream_table[i];

	char file_name[256];
	int ret = sprintf(file_name,"%s_%d.flv",adres2(a_tcp->addr),i);
	h->fp = fopen(file_name,"wb");
	
	ret = sprintf(file_name,"tcp_stream_%u_recombine.log",i);
	file_name[ret] = 0;
	h->tcp_log = fopen(file_name,"w+");////maybe error
	
	ret = sprintf(file_name,"ring_%u.log",i);
	file_name[ret] = 0;
	h->ring_log = fopen(file_name,"w+");
	//fprintf(h->ring_log,"pkt %5u put %u \n",pkt_id,len - flv_offset);
	if(!h->fp|| !h->tcp_log || !h->ring_log) return -1;

#if 0	
	memcpy(&flv_stream_table[i].tcpflow,flv,sizeof(IP_FLOW));
	flv_stream_table[i].tcpflow.tcph = calloc(1,sizeof(TCPHeader_t));
	memcpy(flv_stream_table[i].tcpflow.tcph,tcph,sizeof(TCPHeader_t));
	flv_stream_table[i].tcpflow.data = calloc(1,len);
	memcpy(flv_stream_table[i].tcpflow.data,data,len);
	
	flv_stream_table[i].flv_offset = flv_offset;
	flv_stream_table[i].tail = NULL;
	flv_stream_table[i].head = NULL;
	printf("stream %d sport %d dport %d\n",i,ntohs(h->tcpflow.tcph->SrcPort),ntohs(h->tcpflow.tcph->DstPort));
#if 1
	flv_stream_table[i].last = calloc(1,sizeof(FLV_FLOW_ITEM));
	if(flv_stream_table[i].last){
		memcpy(&flv_stream_table[i].last->tcpflow,flv,sizeof(IP_FLOW) );
		flv_stream_table[i].last->tcpflow.tcph = calloc(1,sizeof(TCPHeader_t));
		flv_stream_table[i].last->tcpflow.data = calloc(1,1500);
		flv_stream_table[i].last->pkt_id = pkt_id;
		if(flv_stream_table[i].last->tcpflow.tcph)
			memcpy(flv_stream_table[i].last->tcpflow.tcph,tcph,sizeof(TCPHeader_t) );
	}
#endif
	char*ch = (void*)data;
	flv_stream_table[i].recv_data_len = len ;
	flv_stream_table[i].pkt_id = pkt_id;
	flv_stream_table[i].last_seqno = ntohl(tcph->SeqNO);
	printf("tcp stream %2u pkt_id %6u seq %10u ack %10u len %4u flag 0x%02x cache_num %3u\n",
		i,pkt_id,ntohl(tcph->SeqNO),ntohl(tcph->AckNO),len,tcph->Flags,flv_stream_table[i].cache_num);
	
	struct ring_buffer *ring_buf = NULL;
	pthread_t consumer_pid;

	void * buffer = (void *)malloc(RING_BUFFER_SIZE);
	if (!buffer){
		fprintf(stderr, "Failed to malloc memory.\n");
		return -1;
	}
	ring_buf = ring_buffer_init(buffer, RING_BUFFER_SIZE);
	if (!ring_buf){
		fprintf(stderr, "Failed to init ring buffer.\n");
		return -1;
	}
	flv_stream_table[i].flv_pkt_queue = malloc(sizeof(Queue));
	if (!flv_stream_table[i].flv_pkt_queue){
		fprintf(stderr, "Failed to init Queue.\n");
		return -1;
	}
	queue_init(flv_stream_table[i].flv_pkt_queue,FLV_FLOW_FREE);
	
	flv_stream_table[i].ring_buf = ring_buf;
	flv_stream_table[i].flvfp.prev_tag_size = 0;
	flv_stream_table[i].flvfp.prev_tag_id = 0;
	flv_stream_table[i].flvfp.tag_list.size = 0;
	
	//queue_enqueue(flv_stream_table[i].flv_pkt_queue, * data);
	FLV_FLOW_HEADER*fh = &flv_stream_table[i];
	consumer_pid = consumer_thread((void*)fh);
	
	flv_stream_table[i].consumer_id = consumer_pid;
	flv_offset += sizeof(FLV_HEADER);
	ring_buffer_put(ring_buf,ch + flv_offset,len - flv_offset);
#endif	
	return 0;
}

int flv_stream_destruct(int i)
{
	FLV_FLOW_HEADER*h = &flv_stream_table[i];
	
	if(h->fp)fclose(h->fp);
	if(h->ring_log)fclose(h->ring_log);
	if(h->tcp_log)fclose(h->tcp_log);
#if 0	
	//PTHREAD_LOCK(h->lock);
	if(h->tcpflow.tcph)free(h->tcpflow.tcph);

	if(h->last){
		if(h->last->tcpflow.tcph)free(h->last->tcpflow.tcph);
		//h->last->tcpflow.tcph = NULL;
		if(h->last->tcpflow.data)free(h->last->tcpflow.data);
		if(h->last )free(h->last);
	}
	
	if (h->ring_buf){
		ring_buffer_free(h->ring_buf);
		h->ring_buf = NULL;
	}

	if(h->flv_pkt_queue){
		queue_destroy(h->flv_pkt_queue);
		//free(h->flv_pkt_queue);
		h->flv_pkt_queue = NULL;
	}

	FLV_FLOW_ITEM*tmp = h->head;
	while(tmp){
		FLV_FLOW_FREE(tmp);
		tmp = tmp->next;
	}
	//PTHREAD_UNLOCK(h->lock);
#endif
	memset(h,0,sizeof(FLV_FLOW_HEADER));
	return 0;
}

/*
** @param flv_offset ,flv tage data or header offset from tcp data;
*/

int process_http_flv_stream_header(struct tcp_stream *a_tcp,int offset)
{
	int i;
	for( i = 0; i < MAX_FLV_STREAM_NUM; ++i ){
		if (flv_stream_table[i].tcp_stream == NULL && a_tcp){
			//// !!!!!!! may cause  memory leak!!!!!!!
			flv_stream_construct(i,a_tcp,offset);
			return i;
		}
	}
	return -1;
}


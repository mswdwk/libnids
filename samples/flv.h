#ifndef _FLV_H
#define _FLV_H

#include "list.h"
#include "queue.h"
#include "pcap_parse.h"

enum{
	INVAILD_KEYWORD = -2,
	VIDEO_INVAILD = -1,
	FLV_VIDEO,
	FLV_VIDEO_SUBTITLE,// sub title
};

//Important!
#pragma pack(1)
#define TAG_TYPE_SCRIPT 18
#define TAG_TYPE_AUDIO  8
#define TAG_TYPE_VIDEO  9
typedef unsigned char byte;
typedef unsigned int uint;
typedef struct {
	byte Signature[3];
	byte Version;
	byte Flags;
	uint Headersize; // Headersize
} FLV_HEADER;        // 9
// int prev_tag_size;// 4
typedef struct {
	byte TagType;
	byte DataSize[3];
	byte Timestamp[3];
	uint Reserved;
} FLV_TAG_HEADER;    //11

typedef struct{
	unsigned int prev_tag_size ; // previous tag size
	FLV_TAG_HEADER tag_header;
	// below two fields do not exist in real data;
	//void*tag_data;
	//unsigned int tag_id ;
	char tag_data[0];
}FLV_TAG;

typedef struct FLV_FILE{
	FLV_HEADER flvh;
	unsigned int prev_tag_size ;
	unsigned int prev_tag_id;
	FLV_TAG prev_tag;
	List tag_list;
	//FLV_BODY body;
}FLV_FILE;

typedef struct flv_val
{
	char *val;
	int len;
} flv_val;

//flv的header+previoustagsize
//static unsigned char flv_header_data[] = { 0x46,0x4C,0x56,0x01,0x05,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x00 };
  static unsigned char flv_header_data[] = { 0x46,0x4C,0x56,0x01,0x00,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x00 };

//static flv_val flv_val_header = { (char*)flv_header_data ,13 };

typedef struct{
	int high_ip,low_ip;
	short int high_port,low_port;
	char protocol;
	int stream_id;
	int hash;
	void* data;
	uint data_len;
	uint counter;
	void(*process)(void*);
	TCPHeader_t*tcph;
}IP_FLOW;

#define MAX_FLV_STREAM_NUM 32


#define GET_FLV_TAG_DATA_SIZE(tag_data_size,ftagheader) do{ \
		tag_data_size  = (ftagheader)->DataSize[0];\
		tag_data_size<<=8;\
		tag_data_size += (ftagheader)->DataSize[1];\
		tag_data_size<<=8;\
		tag_data_size += (ftagheader)->DataSize[2];}while(0)
		
#define IP_PORT_HEADER2FLV_HIGH_LOW(flv,iph,tcph)		\
	do{													\
		if( (iph)->DstIP > (iph)->SrcIP ) {				\
			(flv).high_ip = (iph)->DstIP;				\
			(flv).low_ip = (iph)->SrcIP;				\
		}else{											\
			(flv).high_ip = (iph)->SrcIP;				\
			(flv).low_ip = (iph)->DstIP;				\
		}												\
		\
		if( (tcph)->DstPort > (tcph)->SrcPort ){		\
			(flv).high_port = (tcph)->DstPort;			\
			(flv).low_port = (tcph)->SrcPort;			\
		}else{											\
			(flv).high_port = (tcph)->SrcPort;			\
			(flv).low_port = (tcph)->DstPort;			\
		} 												\
	}while(0)



// flv stream list length must less than this
#define MAX_PKT_CACHE_NUM_IN_FLV_STREAM   2048

typedef struct FLV_FLOW_ITEM{
	IP_FLOW tcpflow;
	int flv_offset;
	int pkt_id;
	unsigned char state; // 
	struct FLV_FLOW_ITEM *next;
	struct FLV_FLOW_ITEM *prev;
	int ref_counter ; // reference counter
}FLV_FLOW_ITEM;

typedef   pthread_mutex_t LOCK_T;

typedef struct FLV_FLOW_HEADER{
	LOCK_T *lock;
	IP_FLOW tcpflow;
	//char flv_header_flag;
	unsigned int pkt_id;
	FLV_FLOW_ITEM *head;
	FLV_FLOW_ITEM *tail;
	FLV_FLOW_ITEM *last;
	uint last_seqno;
	int flv_flow_pkt_num;
	int cache_num;
	int recv_data_len; // total receive tcp data len
	void(*process)(void*);
	Queue *flv_pkt_queue; // ordered pakcet queue which are used to prepared  for flv tag data analysis.
	FLV_FILE flvfp;
	struct ring_buffer *ring_buf; // store flv tag data buffer
	pthread_t consumer_id ;
	
	FILE*tcp_log; // record tcp_stream_recombine log 
	FILE*fp; // record flv file data
	FILE*ring_log; 

//below fields used for libnids
	int flv_offset;
	int tag_id;
	int flv_flow_id;
	char thread_run:1; // control thread run or not
	char stream_last_packet:1;// stream last packet
	char record_flv_header_ok:1;
	char record_flv_prev_tag_size_ok:1;//
	char record_flv_tag_header_ok:1;//
	char record_flv_data_turn:1; // time to record flv data
	int last_prev_tag_size;
	int last_need_data_len;
	void*tcp_stream;
}FLV_FLOW_HEADER;

struct keyword{
	int type;
	void*data;
};

int find_flv_header(void*data,int len);
int ip_flow_hash(IP_FLOW*flow);

extern FLV_FLOW_HEADER flv_stream_table[MAX_FLV_STREAM_NUM];

#endif



/**@brief as linux kfifo ring buffer
* ring_buffer.h
 * */

#ifndef _ALGO_KFIFO_HEADER_H 
#define _ALGO_KFIFO_HEADER_H

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
//判断x是否是2的次方
#define is_power_of_2(x) ((x) != 0 && (((x) & ((x) - 1)) == 0))
//取a和b中最小值
#define min(a, b) (((a) < (b)) ? (a) : (b))

/*
**      
**     case 1 : ring_buffer_len = in - out
**     this means vaild data buffer len
**
**     |<--------ring buffer size--------------->|
**     -------------------------------------------
**     |        |///vaild///data///buffer///|    |
**     -------------------------------------------
**     |       out                          in   |
**
**		case 2 :ring_buffer_len = in - out
**	
**     |<--------ring buffer size--------------->|
**     -------------------------------------------
**     |////////|     free buffer space     |////|
**     -------------------------------------------
**     |       in                          out   |
**     beacuse ring_buffer_size is 2^n, so unsigned int in minus out
**     can get the ring buffer len.
*/
struct ring_buffer
{
    void         *buffer;     //缓冲区
    uint32_t     size;       //大小
    uint32_t     in;         //入口位置
    uint32_t       out;        //出口位置
    pthread_mutex_t *f_lock;    //互斥锁
};
//初始化缓冲区
struct ring_buffer* ring_buffer_init(void *buffer, uint32_t size);

//释放缓冲区
void ring_buffer_free(struct ring_buffer *ring_buf);

//缓冲区的长度
uint32_t __ring_buffer_len(const struct ring_buffer *ring_buf);

//从缓冲区中取数据
uint32_t __ring_buffer_get(struct ring_buffer *ring_buf, void * buffer, uint32_t size);
//向缓冲区中存放数据
uint32_t __ring_buffer_put(struct ring_buffer *ring_buf, void *buffer, uint32_t size);

uint32_t ring_buffer_len(const struct ring_buffer *ring_buf);
/*
** @return vaild data buf len
*/
uint32_t ring_data_len(const struct ring_buffer *ring_buf);

uint32_t ring_buffer_get(struct ring_buffer *ring_buf, void *buffer, uint32_t size);

uint32_t ring_buffer_put(struct ring_buffer *ring_buf, void *buffer, uint32_t size);

#define RING_BUFFER_SIZE  (16*1024*1024)

#endif




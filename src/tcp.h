/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/
#ifndef _NIDS_TCP_H
#define _NIDS_TCP_H
#include <sys/time.h>


struct skbuff {
  struct skbuff *next;
  struct skbuff *prev;

  void *data;
  u_int len;
  u_int truesize;
  u_int urg_ptr;
  
  char fin;
  char urg;
  u_int seq;
  u_int ack;
};



int tcp_init(int);
void tcp_exit(int);
void process_tcp(u_char *, int,int);
void process_icmp(u_char *,int);
void tcp_check_timeouts(struct timeval *,int);


int myhash(u_char * data);

#define S_FIFO_max_size 10000
#define FIFO_max_num 8
#define CACHELINE_SIZE 8
struct FIFO_node
{
	u_char * data;
	int skblen;
        int need_free;
};
struct HP_Params_node
{
    struct tcp_stream **tcp_stream_table;
    struct tcp_stream *streams_pool;
    int tcp_num;
    int tcp_stream_table_size;
    int max_stream;
    struct tcp_stream *tcp_latest ;
    struct tcp_stream *tcp_oldest ;
    struct tcp_stream *free_streams;
    struct ip *ugly_iphdr;
 //   struct tcp_timeout *nids_tcp_timeoutsg;
};
struct HP_Params_node HP_params[FIFO_max_num];

int head[FIFO_max_num];
int tail[FIFO_max_num];
int cpu_num;

struct FIFO_node the_FIFO[FIFO_max_num][S_FIFO_max_size];
time_t timestp[FIFO_max_num];
struct FIFO_node cBuffer[FIFO_max_num][CACHELINE_SIZE];
int current[FIFO_max_num];

#endif /* _NIDS_TCP_H */

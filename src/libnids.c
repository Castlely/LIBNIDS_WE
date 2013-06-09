/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/


#include <pthread.h>
#include <config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <alloca.h>
#include <pcap.h>
#include <errno.h>
#include <config.h>

#include <unistd.h>
#include <stdio.h>

//#define _GNU_SOURCE

#include "checksum.h"
#include "ip_fragment.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"
#ifdef HAVE_LIBGTHREAD_2_0
#include <glib.h>
#endif


#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
extern int ip_options_compile(unsigned char *);
extern int raw_init();
static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);

static struct proc_node *ip_frag_procs;
static struct proc_node *ip_procs;
static struct proc_node *udp_procs;

struct proc_node *tcp_procs;
static int linktype;
static pcap_t *desc = NULL;
#define HAVE_LIBGTHREAD_2_0 
#ifdef HAVE_LIBGTHREAD_2_0

/* async queue for multiprocessing - mcree */
static GAsyncQueue *cap_queue;

/* items in the queue */
struct cap_queue_item {
     void *data;
     bpf_u_int32 caplen;
};

/* marks end of queue */
static struct cap_queue_item EOF_item;

/* error buffer for glib calls */
static GError *gerror = NULL;

#endif
//----------------------------------------------------
FILE *myfphash;
extern int test[8];
extern int testinput;
//---------------------------------------------------
char nids_errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr * nids_last_pcap_header = NULL;
u_char *nids_last_pcap_data = NULL;
u_int nids_linkoffset = 0;

char *nids_warnings[] = {
    "Murphy - you never should see this message !",
    "Oversized IP packet",
    "Invalid IP fragment list: fragment over size",
    "Overlapping IP fragments",
    "Invalid IP header",
    "Source routed IP frame",
    "Max number of TCP streams reached",
    "Invalid TCP header",
    "Too much data in TCP receive queue",
    "Invalid TCP flags"
};

struct nids_prm nids_params = {
    1040,			/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
    NULL,			/* filename */
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    LOG_ALERT,			/* syslog_level */
    256,			/* scan_num_hosts */
    3000,			/* scan_delay */
    10,				/* scan_num_ports */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024,			/* pcap_timeout */
    0,				/* multiproc */
    20000,			/* queue_limit */
    0,				/* tcp_workarounds */
    NULL			/* pcap_desc */
};

//----------------------------------------
/*
#define S_FIFO_max_size 10000
#define FIFO_max_num 8

struct FIFO_node
{
	u_char * data;
	int skblen;
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
    //tcp_timeout *nids_tcp_timeouts = 0;
};
struct HP_Params_node HP_params[FIFO_max_num];

int head[FIFO_max_num];
int tail[FIFO_max_num];
int cpu_num;

struct FIFO_node the_FIFO[FIFO_max_num][S_FIFO_max_size];
*/



//----------------------------------------


int FIFO_init()
{
	int i,j;
	//œ«fifoÊý×é³õÊŒ»¯È«null

	for(i=0;i<FIFO_max_num;i++)
	{
		for(j=0;j<S_FIFO_max_size;j++)
		{
			the_FIFO[i][j].data=NULL;
			the_FIFO[i][j].skblen=0;
                        the_FIFO[i][j].need_free=0;
		}
                for(j=0;j<CACHELINE_SIZE;j++)
                {
                    cBuffer[i][j].data=NULL;
                    cBuffer[i][j].need_free=0;
                    cBuffer[i][j].skblen=0;
                }
		head[i]=0;
		tail[i]=0;
                timestp[i]=0;
        
                current[i]=0;
	}
  //ŒÆËãcpuÊýÄ¿ £¬ŽýŒÆËã
}

int enqueue(struct FIFO_node data,struct FIFO_node *FIFO_instance,int *head)
{
    /*
    if(the_FIFO[FIFO_NO][head[FIFO_NO]].data!=NULL)
        return 1;
    if(current[FIFO_NO]==0)
        timestp[FIFO_NO]=time((time_t*)NULL);
    cBuffer[FIFO_NO][current[FIFO_NO]]=data;
    current[FIFO_NO]++;
    if((current==CACHELINE_SIZE)||(time((time_t*)NULL)-timestp[FIFO_NO]>10))
    {
        
    }*/
    
    if(FIFO_instance[*head].data!=NULL)
    {
            return 1;//¶ÓÁÐÂú£¬Ö±œÓ¶ª°ü£¿»òÕß·¢ËÍicmpÏûÏ¢£¿
    }
    //fprintf(stderr,"enqueue%d\n",*head);
    FIFO_instance[*head]=data;
    *head=(*head+1)%S_FIFO_max_size;

    return 0;
     
}
int dequeue(struct FIFO_node *pnode,struct FIFO_node *FIFO_instance,int *tail)
{
	*pnode=FIFO_instance[*tail];//optimaized out 咋办？
	if((*pnode).data==NULL)
	{
		return 1;//¶ÓÁÐ¿Õ£¬sleepÒ»ÏÂ£¿
	}
        //fprintf(stderr,"dequeue%d\n",*tail);
	FIFO_instance[*tail].data=NULL;
	*tail=(*tail+1)%S_FIFO_max_size;
	return 0;
}

int myhash(u_char * data)
{
	struct ip *this_iphdr = (struct ip *)data;
        struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
        u_int16_t temp[6],hash;
        int *ptr;
        int i;
        ptr=temp;
        *ptr++=this_iphdr->ip_src.s_addr;
        *ptr++=this_iphdr->ip_dst.s_addr;
        temp[4]=this_tcphdr->th_sport;
        temp[5]=this_tcphdr->th_dport;
        for(i=1,hash=temp[0];i<6;i++)
        {
            hash^=temp[i];
        }	
	//this_iphdr->ip_src.s_addr; this_iphdr->ip_dst.s_addr;  32Î»µØÖ·
	//this_tcphdr->source; this_tcphdr->dest; 16Î»¶Ë¿ÚºÅ + this_tcphdr->source + this_tcphdr->dest
	//hash=(htonl(this_iphdr->ip_src.s_addr) + htonl(this_iphdr->ip_dst.s_addr) )%cpu_num;

	return ((int)hash)%(cpu_num-1);
}


//kernal
//----------------------------------------------------------------------------------------
//interface
//Õâžöº¯ÊýÔÚÖžÅÉµÄÊ±ºòœ«³ýÁËtcpµÄ°üÖ±œÓÖžÅÉµœÁíÒ»¶ÓÁÐ£¿È»ºóÈÃÒ»žöÏß³ÌÈ¥ŽŠÀí³ýtcpÖ®ÍâµÄ°ü£¿


int input_dispatcher ()
{
    int status;
        pcap_loop(desc, -1, (pcap_handler) nids_pcap_handler, 0);
    //Õâ²¿·Ö×öµœtcp·ÖÆ¬ÖØ×éÎªÖ¹
		
    return 0;
}
//µœ·ÖÆ¬ÖØ×éÎªÖ¹µÄ»°£¬ÔÚÖØ×éºóÈë¶ÓÐèÒªÐÞžÄÕâžöº¯Êý

int highlevel_process(int num)
{
	struct FIFO_node this_node;
	int process_num=num;
        struct proc_node *i;	
        int j,temp;
   
      //  fprintf(stderr,"队列%d空，睡一秒？",process_num);
	while(1)
	{
            //testinput++;
            //fprintf(stderr,"dequeue %d ",testinput);
		switch(dequeue(&this_node,the_FIFO[process_num],&tail[process_num]))
		{
			case 0://¶ÓÁÐÕý³£µ¯³öÊýŸÝ
				//printf("ok1");
                            for (i = ip_procs; i; i = i->next)
                                        (i->item) (this_node.data, this_node.skblen,process_num);
				break;
			case 1://¶ÓÁÐ¿Õ
				//printf("ok2");
                            for(j=0,temp=0;j<8;j++)
                            {
                                temp+=test[j];
                            }
                            fprintf(stderr,"%d ",temp);
                            //fprintf(stderr,"队列%d空，睡一秒？",process_num);
                          // sleep(0);
                         
				break;
			case 2://other ¡­¡
				//printf("ok3");
				break;
			default:
                //printf("ok4");
                            break;
			//±šŽí
		}
                if(this_node.need_free)
                    free(this_node.data);
	}
    return 0;
}

static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[20], daddr[20];
    char buf[1024];
    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR) {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    syslog(nids_params.syslog_level,
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	} else
	    syslog(nids_params.syslog_level, "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    syslog(nids_params.syslog_level,
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    syslog(nids_params.syslog_level, "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;

    case NIDS_WARN_SCAN:
	this_host = (struct host *) data;
	sprintf(buf, "Scan from %s. Scanned ports: ",
		int_ntoa(this_host->addr));
	for (i = 0; i < this_host->n_packets; i++) {
	    strcat(buf, int_ntoa(this_host->packets[i].addr));
	    sprintf(buf + strlen(buf), ":%hu,",
		    this_host->packets[i].port);
	    flagsand &= this_host->packets[i].flags;
	    flagsor |= this_host->packets[i].flags;
	}
	if (flagsand == flagsor) {
	    i = flagsand;
	    switch (flagsand) {
	    case 2:
		strcat(buf, "scan type: SYN");
		break;
	    case 0:
		strcat(buf, "scan type: NULL");
		break;
	    case 1:
		strcat(buf, "scan type: FIN");
		break;
	    default:
		sprintf(buf + strlen(buf), "flags=0x%x", i);
	    }
	} else
	    strcat(buf, "various flags");
	syslog(nids_params.syslog_level, "%s", buf);
	break;

    default:
	syslog(nids_params.syslog_level, "Unknown warning number ?\n");
    }
}

/* called either directly from pcap_hand() or from cap_queue_process_thread()
 * depending on the value of nids_params.multiproc - mcree
 */
static void call_ip_frag_procs(void *data,bpf_u_int32 caplen)
{
    struct proc_node *i;
    for (i = ip_frag_procs; i; i = i->next)
	(i->item) (data, caplen);
}


/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

void nids_pcap_handler(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{
    u_char *data_aligned;
#ifdef HAVE_LIBGTHREAD_2_0
    struct cap_queue_item *qitem;
#endif
#ifdef DLT_IEEE802_11
    unsigned short fc;
    int linkoffset_tweaked_by_prism_code = 0;
    int linkoffset_tweaked_by_radio_code = 0;
#endif
    int j;
    /*
     * Check for savagely closed TCP connections. Might
     * happen only when nids_params.tcp_workarounds is non-zero;
     * otherwise nids_tcp_timeouts is always NULL.
     */
    for(j=0;j<cpu_num;j++)
    {
        if (NULL != nids_tcp_timeouts[j])
          tcp_check_timeouts(&hdr->ts,j);
    }
    nids_last_pcap_header = hdr;
    nids_last_pcap_data = data;
    (void)par; /* warnings... */
    switch (linktype) {
    case DLT_EN10MB:
	if (hdr->caplen < 14)
	    return;
	/* Only handle IP packets and 802.1Q VLAN tagged packets below. */
	if (data[12] == 8 && data[13] == 0) {
	    /* Regular ethernet */
	    nids_linkoffset = 14;
	} else if (data[12] == 0x81 && data[13] == 0) {
	    /* Skip 802.1Q VLAN and priority information */
	    nids_linkoffset = 18;
	} else
	    /* non-ip frame */
	    return;
	break;
#ifdef DLT_PRISM_HEADER
#ifndef DLT_IEEE802_11
#error DLT_PRISM_HEADER is defined, but DLT_IEEE802_11 is not ???
#endif
    case DLT_PRISM_HEADER:
	nids_linkoffset = 144; //sizeof(prism2_hdr);
	linkoffset_tweaked_by_prism_code = 1;
        //now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11_RADIO
    case DLT_IEEE802_11_RADIO:
        // just get rid of the radio tap header
        if (!linkoffset_tweaked_by_prism_code) {
          nids_linkoffset = EXTRACT_LE_16BITS(data + 2); // skip radiotap header
          linkoffset_tweaked_by_radio_code = 1;
        }
        //now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11
    case DLT_IEEE802_11:
	/* I don't know why frame control is always little endian, but it 
	 * works for tcpdump, so who am I to complain? (wam)
	 */
	if (!linkoffset_tweaked_by_prism_code && !linkoffset_tweaked_by_radio_code)
		nids_linkoffset = 0;
	fc = EXTRACT_LE_16BITS(data + nids_linkoffset);
	if (FC_TYPE(fc) != T_DATA || FC_WEP(fc)) {
	    return;
	}
	if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	    /* a wireless distribution system packet will have another
	     * MAC addr in the frame
	     */
	    nids_linkoffset += 30;
	} else {
	    nids_linkoffset += 24;
	}
	if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
	  nids_linkoffset += 2;
	if (hdr->len < nids_linkoffset + LLC_FRAME_SIZE)
	    return;
	if (ETHERTYPE_IP !=
	    EXTRACT_16BITS(data + nids_linkoffset + LLC_OFFSET_TO_TYPE_FIELD)) {
	    /* EAP, LEAP, and other 802.11 enhancements can be 
	     * encapsulated within a data packet too.  Look only at
	     * encapsulated IP packets (Type field of the LLC frame).
	     */
	    return;
	}
	nids_linkoffset += LLC_FRAME_SIZE;
	break;
#endif
    default:;
    }
    if (hdr->caplen < nids_linkoffset)
	return;

/*
* sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too. 
* Anyway, libpcap tries to ensure proper layer 3 alignment (look for
* handle->offset in pcap sources), so memcpy should not be called.
*/
#ifdef LBL_ALIGN
    if ((unsigned long) (data + nids_linkoffset) & 0x3) {
	data_aligned = alloca(hdr->caplen - nids_linkoffset + 4);
	data_aligned -= (unsigned long) data_aligned % 4;
	memcpy(data_aligned, data + nids_linkoffset, hdr->caplen - nids_linkoffset);
    } else 
#endif

    //data_aligned=malloc(hdr->caplen - nids_linkoffset);
    //memcpy(data_aligned,data + nids_linkoffset,hdr->caplen - nids_linkoffset);
    data_aligned = data + nids_linkoffset;

 #ifdef HAVE_LIBGTHREAD_2_0
     if(nids_params.multiproc) { 
        /* 
         * Insert received fragment into the async capture queue.
         * We hope that the overhead of memcpy 
         * will be saturated by the benefits of SMP - mcree
         */
        qitem=malloc(sizeof(struct cap_queue_item));
        if (qitem && (qitem->data=malloc(hdr->caplen - nids_linkoffset))) {
          qitem->caplen=hdr->caplen - nids_linkoffset;
          memcpy(qitem->data,data_aligned,qitem->caplen);
          g_async_queue_lock(cap_queue);
          /* ensure queue does not overflow */
          if(g_async_queue_length_unlocked(cap_queue) > nids_params.queue_limit) {
	    /* queue limit reached: drop packet - should we notify user via syslog? */
	    free(qitem->data);
	    free(qitem);
	    } else {
	    /* insert packet to queue */
	    g_async_queue_push_unlocked(cap_queue,qitem);
          }
          g_async_queue_unlock(cap_queue);
	}
     } else { /* user requested simple passthru - no threading */
        call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
     }
 #else
     call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
 #endif
}


static void gen_ip_frag_proc(u_char * data, int len)
{
    struct proc_node *i;
    struct ip *iph = (struct ip *) data;
    int need_free = 0;
    int skblen;
    int FIFO_NO;
    struct FIFO_node temp;
    temp.data=data;
   
    void (*glibc_syslog_h_workaround)(int, int, struct ip *, void*)=
        nids_params.syslog;

    if (!nids_params.ip_filter(iph, len))
	return;

    if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
	ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
	len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
	glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
	return;
    }
    if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
	glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
	return;
    }
    switch (ip_defrag_stub((struct ip *) data, &iph)) {
    case IPF_ISF:
	return;
    case IPF_NOTF:
	need_free = 0;
	iph = (struct ip *) data;
	break;
    case IPF_NEW:
	need_free = 1;
	break;
    default:;
    }
    skblen = ntohs(iph->ip_len) + 16;
    if (!need_free)
	skblen += nids_params.dev_addon;
    skblen = (skblen + 15) & ~15;
    skblen += nids_params.sk_buff_size;
    
    temp.skblen=skblen;
    temp.need_free=need_free;
    FIFO_NO=myhash(data);
    //_----------------------------------
    
   // fprintf(myfphash, "%d ", FIFO_NO); 
   // fflush(myfphash);
    //-----------------------------------------
    //testinput++;
   // fprintf(stderr,"input %d ",testinput);
    if(enqueue(temp,the_FIFO[FIFO_NO],&head[FIFO_NO]))
    {
        fprintf(stderr,"队列%d满，直接丢包",FIFO_NO);
        //sleep(0);
    }
  //  
  //  if (need_free)
//	free(iph);
}

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	return;
    /* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
    if (udph->uh_sum && my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    while (ipp) {
	ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		  ulen - sizeof(struct udphdr), data);
	ipp = ipp->next;
    }
}
static void gen_ip_proc(u_char * data, int skblen,int process_num)
{
    
    switch (((struct ip *) data)->ip_p) 
		{
			case IPPROTO_TCP:
				process_tcp(data, skblen,process_num);
				break;
			//ºó±ßµÄÏÈ²»¹ÜÁË
			case IPPROTO_UDP:
				//process_udp((char *)data);
				break;
				
			case IPPROTO_ICMP:
				//if (nids_params.n_tcp_streams)
					//process_icmp(data);
				break;
				
			default:
				break;
    }
}
static void init_procs()
{
    ip_frag_procs = mknew(struct proc_node);
    ip_frag_procs->item = gen_ip_frag_proc;
    ip_frag_procs->next = 0;
    ip_procs = mknew(struct proc_node);
    ip_procs->item = gen_ip_proc;
    ip_procs->next = 0;
    tcp_procs = 0;
    udp_procs = 0;
}

void nids_register_udp(void (*x))
{
    register_callback(&udp_procs, x);
}

void nids_unregister_udp(void (*x))
{
    unregister_callback(&udp_procs, x);
}

void nids_register_ip(void (*x))
{
    register_callback(&ip_procs, x);
}

void nids_unregister_ip(void (*x))
{
    unregister_callback(&ip_procs, x);
}

void nids_register_ip_frag(void (*x))
{
    register_callback(&ip_frag_procs, x);
}

void nids_unregister_ip_frag(void (*x))
{
    unregister_callback(&ip_frag_procs, x);
}

static int open_live()
{
    char *device;
    int promisc = 0;

    if (nids_params.device == NULL)
	nids_params.device = pcap_lookupdev(nids_errbuf);
    if (nids_params.device == NULL)
	return 0;

    device = nids_params.device;
    if (!strcmp(device, "all"))
	device = "any";
    else
	promisc = (nids_params.promisc != 0);

    if ((desc = pcap_open_live(device, 16384, promisc,
			       nids_params.pcap_timeout, nids_errbuf)) == NULL)
	return 0;
#ifdef __linux__
    if (!strcmp(device, "any") && nids_params.promisc
	&& !set_all_promisc()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
#endif
    if (!raw_init()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
    return 1;
}

#ifdef HAVE_LIBGTHREAD_2_0

#define START_CAP_QUEUE_PROCESS_THREAD() \
    if(nids_params.multiproc) { /* threading... */ \
	 if(!(g_thread_create_full((GThreadFunc)cap_queue_process_thread,NULL,0,FALSE,TRUE,G_THREAD_PRIORITY_LOW,&gerror))) { \
	    strcpy(nids_errbuf, "thread: "); \
	    strncat(nids_errbuf, gerror->message, sizeof(nids_errbuf) - 8); \
	    return 0; \
	 }; \
    }

#define STOP_CAP_QUEUE_PROCESS_THREAD() \
    if(nids_params.multiproc) { /* stop the capture process thread */ \
	 g_async_queue_push(cap_queue,&EOF_item); \
    }


/* thread entry point 
 * pops capture queue items and feeds them to
 * the ip fragment processors - mcree
 */
static void cap_queue_process_thread()
{
     struct cap_queue_item *qitem;
     
     while(1) { /* loop "forever" */
	  qitem=g_async_queue_pop(cap_queue);
	  if (qitem==&EOF_item) break; /* EOF item received: we should exit */
	  call_ip_frag_procs(qitem->data,qitem->caplen);
	  free(qitem->data);
	  free(qitem);
     }
     g_thread_exit(NULL);
}

#else

#define START_CAP_QUEUE_PROCESS_THREAD()
#define STOP_CAP_QUEUE_PROCESS_THREAD()

#endif

int nids_init()
{
    cpu_num=sysconf(_SC_NPROCESSORS_CONF);
    /* free resources that previous usages might have allocated */
    nids_exit();
    FIFO_init();
    if (nids_params.pcap_desc)
        desc = nids_params.pcap_desc;
    else if (nids_params.filename) {
	if ((desc = pcap_open_offline(nids_params.filename,
				      nids_errbuf)) == NULL)
	    return 0;
    } else if (!open_live())
	return 0;

    if (nids_params.pcap_filter != NULL) {
		u_int mask = 0;
		struct bpf_program fcode;

		if (pcap_compile(desc, &fcode, nids_params.pcap_filter, 1, mask) <
			0) return 0;
		if (pcap_setfilter(desc, &fcode) == -1)
			return 0;
    }
    switch ((linktype = pcap_datalink(desc))) {
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
    case DLT_PRISM_HEADER:
#endif
#ifdef DLT_IEEE802_11_RADIO
    case DLT_IEEE802_11_RADIO:
#endif
    case DLT_IEEE802_11:
	/* wireless, need to calculate offset per frame */
	break;
#endif
#ifdef DLT_NULL
    case DLT_NULL:
        nids_linkoffset = 4;
        break;
#endif        
    case DLT_EN10MB:
	nids_linkoffset = 14;
	break;
    case DLT_PPP:
	nids_linkoffset = 4;
	break;
	/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
    case DLT_IEEE802:
	nids_linkoffset = 22;
	break;

    case DLT_RAW:
    case DLT_SLIP:
	nids_linkoffset = 0;
	break;
#define DLT_LINUX_SLL   113
    case DLT_LINUX_SLL:
	nids_linkoffset = 16;
	break;
#ifdef DLT_FDDI
    case DLT_FDDI:
        nids_linkoffset = 21;
        break;
#endif        
#ifdef DLT_PPP_SERIAL 
    case DLT_PPP_SERIAL:
        nids_linkoffset = 4;
        break;
#endif        
    default:
	strcpy(nids_errbuf, "link type unknown");
	return 0;
    }
    if (nids_params.dev_addon == -1) {
		if (linktype == DLT_EN10MB)
			nids_params.dev_addon = 16;
		else
			nids_params.dev_addon = 0;
    }
    if (nids_params.syslog == nids_syslog)
	openlog("libnids", 0, LOG_LOCAL0);

    init_procs();
    tcp_init(nids_params.n_tcp_streams);
    ip_frag_init(nids_params.n_hosts);
    scan_init();

    if(nids_params.multiproc) {
#ifdef HAVE_LIBGTHREAD_2_0
	 g_thread_init(NULL);
	 cap_queue=g_async_queue_new();
#else
	 strcpy(nids_errbuf, "libnids was compiled without threads support");
	 return 0;        
#endif
    }

    return 1;
}

int nids_run()
{
    int i;
    cpu_set_t mask;
    cpu_set_t get;
    pthread_t tip_id,tap_id[8];
    int err;
  //----------------------------------------------  
    if(!(myfphash=fopen("hashtest.txt","w+")))
        fprintf(stderr,"打开文件错误\n");
   
  //----------------------------------------------  
    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return 0;
    }
    
    CPU_ZERO(&mask);
    CPU_SET(cpu_num-1, &mask);
    //在核绑定的时候把序号最大的核绑定给ip，待做
    err=pthread_create(&tip_id,NULL,input_dispatcher,NULL);
    //input_dispatcher();
    //highlevel_process(0);
    //sleep(3);
    if(err!=0)
        printf("create false in dispatcher.");
    if (pthread_setaffinity_np(tip_id, sizeof(mask), &mask) < 0) {
                fprintf(stderr, "set thread affinity failed\n");
            }
      
    //ÔÚÆô¶¯highlevel_processµÄÏß³ÌÖ®Ç°¿ÉÒÔÊÊµ±ÈÃÖ÷Ïß³ÌsleepÒ»ÏÂ

    //žùŸÝºËµÄÊýÄ¿œøÐÐhignlevelÏß³ÌµÄÆô¶¯
    //低序号的i和核绑定ap
    
    err=pthread_create(&tip_id,NULL,input_dispatcher,NULL);
    
       START_CAP_QUEUE_PROCESS_THREAD();
       
    for(i=0;i<cpu_num-1;i++)
    {
        int temp=i;
            err=pthread_create(&tap_id[temp],NULL,highlevel_process,(void *)temp);
            if(err!=0)
                    printf("create false in dispatcher.");
        
        CPU_ZERO(&mask);
        CPU_SET(i, &mask);
        if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) 
        {
            fprintf(stderr, "set thread %d affinity failed\n",i);
        }
         
    }
    pthread_join(tap_id[0],NULL);
    
 /* threading... */
     //  highlevel_process(1);
  
    /* FIXME: will this code ever be called? Don't think so - mcree */
    STOP_CAP_QUEUE_PROCESS_THREAD(); 
    
    nids_exit();
    
    
    fclose(myfphash);
    
    
    return 0;
}

void nids_exit()
{
    int i;
    if (!desc)
        {
        strcpy(nids_errbuf, "Libnids not initialized");
	return;
        }
#ifdef HAVE_LIBGTHREAD_2_0
    if (nids_params.multiproc) 
        {
            /* I have no portable sys_sched_yield,
               and I don't want to add more synchronization...
            */
              while (g_async_queue_length(cap_queue)>0) 
                usleep(100000);
         }
#endif
    for(i=0;i<cpu_num;i++)
        tcp_exit(i);
    ip_frag_exit();
    scan_exit();
    strcpy(nids_errbuf, "loop: ");
    strncat(nids_errbuf, pcap_geterr(desc), sizeof nids_errbuf - 7);
    if (!nids_params.pcap_desc)
        pcap_close(desc);
    desc = NULL;

    free(ip_procs);
    free(ip_frag_procs);
}

int nids_getfd()
{
    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return -1;
    }
    return pcap_get_selectable_fd(desc);
}

int nids_next()
{
    struct pcap_pkthdr h;
    char *data;

    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return 0;
    }
    if (!(data = (char *) pcap_next(desc, &h))) {
	strcpy(nids_errbuf, "next: ");
	strncat(nids_errbuf, pcap_geterr(desc), sizeof(nids_errbuf) - 7);
	return 0;
    }
    /* threading is quite useless (harmful) in this case - should we do an API change?  */
    START_CAP_QUEUE_PROCESS_THREAD();
    nids_pcap_handler(0, &h, (u_char *)data);
    STOP_CAP_QUEUE_PROCESS_THREAD();
    return 1;
}

int nids_dispatch(int cnt)
{
    int r;

    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return -1;
    }
    START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
    if ((r = pcap_dispatch(desc, cnt, (pcap_handler) nids_pcap_handler,
                                    NULL)) == -1) {
	strcpy(nids_errbuf, "dispatch: ");
	strncat(nids_errbuf, pcap_geterr(desc), sizeof(nids_errbuf) - 11);
    }
    STOP_CAP_QUEUE_PROCESS_THREAD(); 
    return r;
}



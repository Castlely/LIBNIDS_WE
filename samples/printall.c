/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.


#define _GNU_SOURCE
#include <stdio.h>
 * 
#include <unistd.h>

#include <sched.h>

*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>

#include "nids.h"
/*
#define __USE_GNU 
#include <unistd.h>
#include <sched.h>  */
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
#define __USE_GNU
#include <unistd.h>
#include <sched.h> 
#include <stdio.h>
// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
//---------------------------------------------------------------------------------
 FILE *myfp[8];
// FILE *myfp100;
 char mystrtest[10]="hashtest ";
 int test[8];
 int testinput;
//---------------------------------------------------------------------------------
 
char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed,int FIFO_NO)
{
  char buf[1024];
  test[FIFO_NO]++;
  int i=0,j=0;
  
  char t[100001]="thisstringisveryverylongdgdsfsdfgdsfgdsfhawrhtyueyueryrtywertewrt";
	char s[100001]="jghjklsfeegdfgdfkjhsfefsdfsrghiuduhgidurigurhkgdfhasgkjfgdjfhgry";
	char *pt=t,*ps=s;
	t[0]=0;
	s[0]=0;

        for(i=0,pt=t,ps=s;i<100000000;i++)
            while(*ps!='\0')
            {
                    while(*pt!='\0')
                    {
                            if(*pt==*ps)
                                    {
                                            ps++;
                                            pt++;
                                            break;
                                    }
                            pt++;
                    }
                    if(*pt=='\0')
                            break;
            }
  
  /*for(;i<1000000000;i++)
  {
      j=j&i;
  }*/
  
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
      //fprintf (myfp[FIFO_NO], "%s established\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE)
    {
      // connection has been closed normally
      //fprintf (myfp[FIFO_NO], "%s closing\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_RESET)
    {
      // connection has been closed by RST
      //fprintf (myfp[FIFO_NO], "%s reset\n", buf);
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
        //buf[strlen(buf)]=a_tcp->server.urgdata;
        //write(1,buf,strlen(buf));
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
    //fprintf(myfp[FIFO_NO],"%s\n",buf); // we print the connection parameters
                              // (saddr, daddr, sport, dport) accompanied
                              // by data flow direction (-> or <-)

   //write(2,hlf->data,hlf->count_new); // we print the newly arrived data
      
    }
  return ;
}

int 
main ()
{
    int i;
   testinput=0;
        for(i=0;i<8;i++)
       {
            test[i]=0;
            myfp[i]=NULL;
           mystrtest[8]=i+'0';
           if(!(myfp[i]=fopen(mystrtest,"w+")))
               fprintf(stderr,"打开文件错误\n");
       }
   // if(!(myfp100=fopen("test100","w+")))
   //            fprintf(stderr,"打开文件错误\n");
      
        //nids_params.device="lo";
        nids_params.device="lo";
	struct nids_chksum_ctl ct1;
	ct1.netaddr=000000;
	ct1.mask=0;
	ct1.action=1;
	nids_register_chksum_ctl(&ct1,1);
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (tcp_callback);
  nids_run ();
   for(i=0;i<8;i++)
       {
           fclose(myfp[i]);
       }
     
  return 0;
}

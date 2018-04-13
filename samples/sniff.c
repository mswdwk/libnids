/*
   Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
   See the file COPYING for license details.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "nids.h"
#include "flv.h"
#include "util.h"

#define LOG_MAX 100
#define SZLACZEK "\n--------------------------------------------------\n"


int logfd;
void
do_log (char *adres_txt, char *data, int ile)
{
  write (logfd, adres_txt, strlen (adres_txt));
  write (logfd, data, ile);
  write (logfd, SZLACZEK, strlen (SZLACZEK));
}



void
sniff_callback (struct tcp_stream *a_tcp, void **this_time_not_needed)
{
  int dest;
  char buf[1024];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  //printf("state %d hash_index 0x%08x,server state %x cient state %x\n",a_tcp->nids_state,
  //a_tcp->hash_index,a_tcp->server.state,a_tcp->client.state);
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
      dest = a_tcp->addr.dest;
      if (dest == 21 || dest == 23 || dest == 110 || dest == 143 || dest == 513||dest==80)
	a_tcp->server.collect++;
	  a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      printf ("%s established\n", buf);
      return;
    }
  if (a_tcp->nids_state != NIDS_DATA)
    {
      // seems the stream is closing, log as much as possible
      do_log (adres (a_tcp->addr), a_tcp->server.data,
	      a_tcp->server.count - a_tcp->server.offset);
      return;
    }
  if (a_tcp->server.count - a_tcp->server.offset < LOG_MAX)
    {
      // we haven't got enough data yet; keep all of it
      nids_discard (a_tcp, 0);
      return;
    }
    
  // enough data  
  find_flv_header(a_tcp->server.data,a_tcp->server.count_new);
  //do_log (adres (a_tcp->addr), a_tcp->server.data, LOG_MAX);

  // Now procedure sniff_callback doesn't want to see this stream anymore.
  // So, we decrease all the "collect" fields we have previously increased.
  // If there were other callbacks following a_tcp stream, they would still
  // receive data
  a_tcp->server.collect--;
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
  nids_params.filename = "test.pcap";
  if (!nids_init ())
    {
      fprintf (stderr, "%s\n", nids_errbuf);
      exit (1);
    }
  nids_register_tcp (sniff_callback);
  nids_run ();
  return 0;
}

#include <siphon.h>
#include <pkt.h>

/* function proto's here for each of the subthreads */
   /* os check */
   /* port mapping bull-jazz */
   /* DNS shizza */

int packet_split (struct ip_header *, char *, int, char *, int);

void *parse (void *data)
{
   struct pt_info_parse *pti = (struct pt_info_parse *) data;
   char buf[1024], hdr[512];

   struct ip_header pk_ip;
   struct parse2log p2l_data;

   union pk_misc
   {
      struct udp_header pk_udp;
      struct tcp_header pk_tcp;
   }
    *pk = (union pk_misc *) hdr;

   for (;;) {

      bzero (&p2l_data, sizeof (p2l_data));

      /* wait for a packet from sniff */
      if (read (pti->pti_read, buf, sizeof (buf)) == -1) {
	 perror ("parse() : read()");
      }

      switch (packet_split (&pk_ip, hdr, sizeof (hdr), buf, sizeof (buf))) {

      case IPPROTO_TCP:

	 /* SYN/ACK? : target is src. */
	 if ((pk->pk_tcp.th_flags & ~TH_URG) == (TH_SYN | TH_ACK)) {
	    p2l_data.p2l_proto = IPPROTO_TCP;      /* store protocol */
	    p2l_data.p2l_flags = P2L_OPEN; /* open port */
	    p2l_data.p2l_port = ntohs (pk->pk_tcp.th_sport);	/* port */
	    memcpy (&p2l_data.p2l_addr, &pk_ip.ip_src, sizeof (struct in_addr));	
				

	    p2l_data.p2l_flags |= P2L_OS;
	    p2l_data.p2l_os.os_win = ntohs(pk->pk_tcp.th_win);	/* tcp window */
	    p2l_data.p2l_os.os_flags = pk->pk_tcp.th_flags;	/* tcp flags */
	    p2l_data.p2l_os.os_ttl = pk_ip.ip_ttl;
	    p2l_data.p2l_os.os_df = htons(pk_ip.ip_off);
	 } else continue;

	 break;

      case IPPROTO_UDP:

	 /* port mapping */

	 /* DNS ? */
	 /* who fucking knows, maybe passive DNS zone mapping */
	 /* other protocols embedded into single udps so hey. */


         /* fall thru */
         
      case IPPROTO_ICMP:

	 /* check icmp type */
	 /* filtered port */

	 /* closed port */

         /* fall thru */

      case -1:			/* error */
	 continue;
	 break;

      default:			/* un-supported protocol */
	 continue;
	 break;

      }

      if (write (pti->pti_write, &p2l_data, sizeof (p2l_data)) !=
	  sizeof (p2l_data)) {
	 perror ("parse() : write()");
      }

   }

   /* i dont really close up the descriptors or anything, let main handle
      that shit */

   return (NULL);		/* wtf, maybe you want to know my status on
				   completion */
}

/* split buffer up into IP packet and packet header, return protocol num. */
int
packet_split (struct ip_header *pk_ip, char *hdr, int hdrlen, char *buf,
int buflen)
{
   if (sizeof (struct ip_header) > buflen)
      return (-1);		/* make sure our buffer is big enuf */
   memcpy (pk_ip, buf, sizeof (struct ip_header));	/* copy ip header */

   if (hdrlen + pk_ip->ip_hl * 4 > buflen)
      return (-1);		/* once again */
   memcpy (hdr, buf + pk_ip->ip_hl * 4, hdrlen);	/* copy header of
							   packet */

   return (pk_ip->ip_p);	/* return protocol */
}

#include <siphon.h>

void *sniff_network (void *pipe)
{
   char errbuf[256];
   pcap_t *pcapd;
   struct pcap_pkthdr pcap_h;
   char *pkt;

   if(!(pcapd = pcap_open_live (device, 128, 1, 250, errbuf))) {
      perror ("pcap_open_live");
      exit (-1);
   }

   for(;;)
   {
      if(!(pkt = (char *)pcap_next(pcapd, &pcap_h))) continue;
      if(write (*(int *)pipe,pkt + 14, 53) != 53) {
         perror("write()");
      } else usleep(10);
   }
}

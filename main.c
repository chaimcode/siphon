/*
 ** The Siphon Project: The Passive Network Mapping Tool
 ** Copyright (c) 2000 Subterrain Security Group
 **
 ** Siphon Homepage: http://www.subterrain.net/projects/siphon/
 ** 
 ** Author Contacts:
 **  bind	<bind@subterrain.net>
 **  aempirei	<aempirei@subterrain.net>
 **
*/

#include <siphon.h>

void usage (char *);
void title(void);

void sighandler(int sig) {
  printf("\nSignal Recieved...exiting cleanly\n");
  exit(0);
}

int main (int argc, char **argv)
{
  char errbuf[256];
   struct pt_info_parse {
      int pti_pd[2];		
   }
   pti_parse;

   int pd_sniff2parse[2], pd_parse2log[2], opt;
   pthread_t sniff_thread, parse_thread, log_thread;
   extern char *optarg;
   extern int opterr;
   struct utsname hinfo;

   verbose = back =  0;
   title();

   if (argc < 2)
      usage (argv[0]);

   opterr = 0;
   while ((opt = getopt (argc, argv, "Vvo:bi:")) != EOF) {
      switch (opt) {
      case 'v': 
         verbose = 1;
         break;
      case 'o':
	 logfile = optarg;
         break;
      case 'b':
	 back = 1;
	 break;
      case 'l':
	 logfile = optarg;
	 break;
      case 'i':
	 device = optarg;
	 break;
      case 'V': puts(VERSION); exit(0);
         break;
      case '?':
      default:
	 usage (argv[0]);
	 break;
      }
   }

   if(geteuid()) {
     printf("User '%s' needs euid of 0.\n",getlogin());
     exit(-1);
   }

   if (logfile == NULL)
      usage (argv[0]);

   uname (&hinfo);

   printf ("\nRunning on: '%s' running %s %s on a(n) %s\n\n",
             hinfo.nodename, hinfo.sysname, hinfo.release,
             hinfo.machine);

   if(device == NULL) 
    device = pcap_lookupdev(errbuf);
   if(device == NULL) { 
     printf("Error: Unable to lookup device.\n");
     exit(-1);
   }
   printf("Using Device: %s\n",device);

   if (pipe (pd_sniff2parse) || pipe (pd_parse2log)) {
      perror ("pipe()");
      exit (-1);
   }

   pti_parse.pti_pd[0] = pd_sniff2parse[0];
   pti_parse.pti_pd[1] = pd_parse2log[1];

   pthread_create (&parse_thread, NULL, (void *) parse, &pti_parse);
   pthread_create(&log_thread,NULL,(void *)log, (void *)pd_parse2log[0]);
   pthread_create (&sniff_thread, NULL, (void *) sniff_network,
		   &pd_sniff2parse[1]);

   signal(SIGINT,&sighandler);

   
   pthread_join (sniff_thread, NULL);

   return 0;
}

void
usage (char *arg)
{
   printf ("Usage:\n"
	   "  %s [options] [-o <logfile>]\n\n"
	   "Options:\n"
	   "  [ -v Verbose mode ]\n"
//	   "  [ -b Run in background ]\n" 
           "  [ -i <device> ]\n"
           "  [ -V Show version and exit ]\n\n",arg);

   exit (-1);
}

void title(void)
{
  printf("\n\t [ The Siphon Project: The Passive Network Mapping Tool ]\n"
	 "\t     [ Copyright (c) 2000 Subterrain Security Group ]\n\n");
}


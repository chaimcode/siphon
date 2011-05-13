#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>


#define VERSION "Version 0.666beta\n"

#define bzero(a,b) memset(a,0,b)

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

struct pt_info_parse
{
#define pti_read pti_pd[0]
#define pti_write pti_pd[1]
   int pti_pd[2];		/* flip/flop for parse */
};

/* os information */
struct os_info
{
   u_short os_win;
   u_short os_flags;
   u_short os_ttl;
   u_short os_df;
};

/* parse to log ipc structure */
struct parse2log
{
   int p2l_proto;
   struct in_addr p2l_addr;
   u_short p2l_port;
   struct os_info p2l_os;
   u_short p2l_flags;
#define P2L_OPEN	0x01
#define P2L_CLOSED	0x02
#define P2L_FILTERED	0x04
#define P2L_OS		0x08
};

void *sniff_network (void *);
void *parse (void *);
void *log(void *);

char *device, *logfile;
int verbose, back;

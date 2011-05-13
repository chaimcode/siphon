#include <siphon.h>
#include <arpa/inet.h>

#define HASHSIZE 1000

struct nlist {
  struct nlist *next;
  char *name;
  unsigned hashval;
};

static struct nlist *hashtab[HASHSIZE];
unsigned hash(char *);

char *oslookup(int,int,int);

struct nlist *lookup(char *);
struct nlist *install(char *);

int tag = 0;

void *log(void *pipe)
{
  struct parse2log *info;
  char hashed[100], buf[1024], *os, *proto = NULL, *df;
  FILE *output;

  output = fopen(logfile,"w");

  if(verbose == 1) {
    fprintf(output,"Host\t\t\tPort\tTTL\tDF\tOperating System\n\n");
    printf("\nHost\t\t\tPort\tTTL\tDF\tOperating System\n\n");
  }
  else {
    fprintf(output,"Host\t\t\tPort\t\tOperating System\n\n");
    printf("\nHost\t\t\tPort\t\tOperating System\n\n");
  }

  for(;;) {

    tag = 0;

    bzero(&info,sizeof(info));

      if(read((int)pipe,buf,sizeof(buf)) == -1) 
        perror("read");

    info = (struct parse2log *)(buf);

    if(info->p2l_port > 0 && info->p2l_port < 1024) 
    {
      switch(info->p2l_proto) {
        case 6: proto = "TCP"; break;
        case 17: proto = "UDP"; break;
      }

      os = oslookup(info->p2l_os.os_win,info->p2l_os.os_ttl,
                      info->p2l_os.os_df);

      snprintf(hashed,100,"%s:%d:%d:%x\n",inet_ntoa(info->p2l_addr),
                                          info->p2l_port,
                                          info->p2l_proto,
           		  	          info->p2l_os.os_win);
      install(hashed);
 
      if(tag != 1) 
      {
        if(verbose == 1)
        {
          if(info->p2l_os.os_df == 0x4000) df = "ON";
          else df = "OFF";
          fprintf(output,"%s\t\t%d\t%d\t%s\t%s\n",
                                  inet_ntoa(info->p2l_addr),
                                  info->p2l_port, info->p2l_os.os_ttl,df,os);
        printf("%s\t\t%d\t%d\t%s\t%s\t\t\n",
                  inet_ntoa(info->p2l_addr),info->p2l_port,
                  info->p2l_os.os_ttl,df,os);
        fflush(output);
        }
        else
        {
          fprintf(output,"%s\t\t%d\t\t%s\n",
                                  inet_ntoa(info->p2l_addr),
                                  info->p2l_port, os);
        printf("%s\t\t%d\t\t%s\n",
                  inet_ntoa(info->p2l_addr),info->p2l_port,os);
        fflush(output);
        }

      }
    }
  }
}

unsigned hash(char *s)
{
  unsigned hashval;

  for(hashval = 0;*s != '\0'; s++)
    hashval = *s + 31 * hashval;

  return hashval % HASHSIZE;
}

struct nlist *lookup(char *s)
{
  struct nlist *np;

  for(np = hashtab[hash(s)]; np != NULL; np = np->next)
    if(strcmp(s,np->name) == 0) {
      tag = 1;
      return np;
    }
  return NULL;
}

struct nlist *install(char *name)
{
  struct nlist *np;
  unsigned hashval;

  if((np = lookup(name)) ==NULL) {
    np = (struct nlist *)malloc(sizeof(*np));
    if(np == NULL || (np->name = strdup(name)) == NULL) 
      return NULL;

    hashval = hash(name);
    np->hashval = hashval;
    np->next = hashtab[hashval];
    hashtab[hashval] = np;
  }
  return np;
}

char *oslookup(int window, int ttl, int df)
{
  FILE *osprints;
  static char line[80], *oswin, *osttl, *osdf, *os, hexed[10];
  static int check = 0;
  osprints = fopen("osprints.conf","r");

  if(!osprints) {
    perror("Unable to find osprints.conf\n");
    return "Unknown";
  }

  snprintf(hexed,10,"%04X",window);

  for(;;) {
    check = 0;
    fgets(line,80,osprints);
  
    if(feof(osprints)) 
      break;
    
    oswin = strtok(line,":");
    osttl = strtok(NULL,":");
    osdf = strtok(NULL,":");
    os = strtok(NULL,"\n");

    if(!os) continue;
 
    if(strstr(oswin, hexed) != NULL) 
    {
      if(atoi(osttl) == 64 && ttl <= 64 && ttl > 32) {
        if(df == 0x4000 && atoi(osdf) == 1)
          check = 1;
        if(df == 0x0 && atoi(osdf) == 0)
          check = 1;
      }          
      if(atoi(osttl) == 255 && ttl <= 255 && ttl > 128) {
        if(df == 0x4000 && atoi(osdf) == 1)
          check = 1;
        if(df == 0x0 && atoi(osdf) == 0)
          check = 1;
      }

      if(atoi(osttl) == 128 && ttl <= 128 && ttl > 64) {
        if(df == 0x4000 && atoi(osdf) == 1)
        check = 1;
        if(df == 0x0 && atoi(osdf) == 0)
          check = 1; 
      }

      if(check == 1) {
        fclose(osprints);
        return os; 
      } 
      continue;
    }

  }
  fclose(osprints);
  return hexed;
}

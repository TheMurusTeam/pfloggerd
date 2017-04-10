//
//  main.c
//  pfloggerd
//
//  Created by The Murus Team
//  www.murusfirewall.com
//  Original code by Davide Feroldi
//  05/04/2017.
//

#include <pcap.h>
#include <pcap/dlt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#define SNAP_LEN 116
pcap_t *hpcap;

static int snaplen = SNAP_LEN;
char *filterizing = NULL;
char errbuf[PCAP_ERRBUF_SIZE];

static struct timeval mytime ;

struct tok {
    u_int v;		/* value */
    const char *s;		/* string */
};
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define        IP_HL(x)        (x)->ip_hl

static const struct tok pf_reasons[] = {
    { 0,	"0(match)" },
    { 1,	"1(bad-offset)" },
    { 2,	"2(fragment)" },
    { 3,	"3(short)" },
    { 4,	"4(normalize)" },
    { 5,	"5(memory)" },
    { 6,	"6(bad-timestamp)" },
    { 7,	"7(congestion)" },
    { 8,	"8(ip-option)" },
    { 9,	"9(proto-cksum)" },
    { 10,	"10(state-mismatch)" },
    { 11,	"11(state-insert)" },
    { 12,	"12(state-limit)" },
    { 13,	"13(src-limit)" },
    { 14,	"14(synproxy)" },
    { 0,	NULL }
};


static const struct tok pf_actions[] = {
    { 0,		"pass" },
    { 1,		"block" },
    { 2,		"scrub" },
    { 3,		"nat" },
    { 4,		"nat" },
    { 5,		"binat" },
    { 6,		"binat" },
    { 7,		"rdr" },
    { 8,		"rdr" },
    { 9,	"synproxy-drop" },
    { 0,			NULL }
};

static const struct tok pf_directions[] = {
    { 0,	"in/out" },
    { 1,	"in" },
    { 2,	"out" },
    { 0,		NULL }
};


struct pfloghdr {
    u_int8_t	length;
    sa_family_t	af;
    u_int8_t	action;
    u_int8_t	reason;
    char		ifname[16];
    char		ruleset[16];
    u_int32_t	rulenr;
    u_int32_t	subrulenr;
    uid_t		uid;
    pid_t		pid;
    uid_t		rule_uid;
    pid_t		rule_pid;
    u_int8_t	dir;
    u_int8_t	pad[3];
};



#define TOKBUFSIZE 128
const char *
tok2strbuf(register const struct tok *lp, register const char *fmt,
           register u_int v, char *buf, size_t bufsize)
{
    if (lp != NULL) {
        while (lp->s != NULL) {
            if (lp->v == v)
                return (lp->s);
            ++lp;
        }
    }
    if (fmt == NULL)
        fmt = "#%d";
    
    (void)snprintf(buf, bufsize, fmt, v);
    return (const char *)buf;
}

const char *
tok2str(register const struct tok *lp, register const char *fmt,
        register u_int v)
{
    static char buf[4][TOKBUFSIZE];
    static int idx = 0;
    char *ret;
    
    ret = buf[idx];
    idx = (idx+1) & 3;
    return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}



typedef struct {
    uint32_t	val;
} __attribute__((packed)) unaligned_uint32_t;
static inline uint32_t
EXTRACT_32BITS(const void *p)
{
    return ((uint32_t)ntohl(((const unaligned_uint32_t *)(p))->val));
}

static inline u_int16_t
EXTRACT_16BITS(const void *p)
{
    return ((u_int16_t)ntohs(((const unaligned_uint32_t *)(p))->val));
}



struct ip_print_demux_state {
    const struct ip *ip;
    const u_char *cp;
    u_int   len, off;
    u_char  nh;
    int     advance;
};




FILE  *fp;
char outputFilename[] = "/var/log/pffirewall.log";
char input[4000];
char date[100];
char textoutput[4101];
char hostname[1024];

char buf[2028];

void dump_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    
    
    
    struct timeval newtime ;
    gettimeofday(&newtime, NULL);
    
    time_t  mytmptime = newtime.tv_sec - mytime.tv_sec;
    uint32_t nanosec = (newtime.tv_usec - mytime.tv_usec);
    int hr = (mytmptime / 3600) % 24;  /* ### My problem. */
    int mi = (mytmptime / 60) % 60;
    int se = mytmptime % 60;
    snprintf(buf+strlen(buf), sizeof( buf),"%.2d:%.2d:%.2d.%05u ",hr,mi,se,nanosec);
    
    mytime = newtime;
    
    u_int length = h->len;
    u_int hdrlen;
    // u_int caplen = h->caplen;
    const struct pfloghdr *mystruct;
    
    mystruct = (struct pfloghdr*)(sp );
    if (mystruct->subrulenr == (uint32_t)-1){
        snprintf(buf+strlen(buf), sizeof( buf),"rule %u/",EXTRACT_32BITS( &mystruct->rulenr));
    }else{
        snprintf(buf+strlen(buf), sizeof( buf),"rule %u.%s.%u/", EXTRACT_32BITS( &mystruct->rulenr), mystruct->ruleset, EXTRACT_32BITS( &mystruct->subrulenr));
    }
    
    snprintf(buf+strlen(buf), sizeof( buf),"%s: %s %s on %s: ",tok2str(pf_reasons, "unkn(%u)", mystruct->reason),tok2str(pf_actions, "unkn(%u)", mystruct->action),tok2str(pf_directions, "unkn(%u)", mystruct->dir) ,mystruct->ifname);
    
    struct ip *ip;
    
    hdrlen = BPF_WORDALIGN(mystruct->length);
    
    length -= hdrlen;
    sp += hdrlen ;
    ip = (struct ip *)sp;
    
    
    
    struct ip_print_demux_state  ipd;
    struct ip_print_demux_state *ipds=&ipd;
    
    
    
    const u_char *ipend;
    
    u_int hlen;
    ipds->ip = (const struct ip *)sp;
    
    hlen = IP_HL(ipds->ip) * 4;
    
    ipds->len = EXTRACT_16BITS(&ipds->ip->ip_len);
    
    
    ipend = sp + ipds->len;
    ipds->len -= hlen;
    ipds->off = EXTRACT_16BITS(&ipds->ip->ip_off);
    
    ipds->cp = (const u_char *)ipds->ip + hlen;
    
    u_int16_t sport = 0, dport = 0;
    
    
    if (ip->ip_v == 4) {
        
        struct protoent myprotoent =  *(struct protoent *)getprotobynumber(ipds->ip->ip_p);
        
        if (myprotoent.p_proto == 6) {
            struct tcphdr *tp;
            
            tp = (struct tcphdr *)ipds->cp;
            
            sport = EXTRACT_16BITS(&tp->th_sport);
            dport = EXTRACT_16BITS(&tp->th_dport);
        }
        if (myprotoent.p_proto == 17) {
            const struct udphdr *up = (const struct udphdr *)ipds->cp;
            sport = EXTRACT_16BITS(&up->uh_sport);
            dport = EXTRACT_16BITS(&up->uh_dport);
        }
        
        
        snprintf(buf+strlen(buf), sizeof( buf), "%s.%u > ",  inet_ntoa(ipds->ip->ip_src),sport);
        snprintf(buf+strlen(buf), sizeof( buf),"%s.%u:",  inet_ntoa(ipds->ip->ip_dst ),dport);
        
        if (getprotobynumber(ipds->ip->ip_p) != NULL)
            snprintf(buf+strlen(buf), sizeof( buf), " %s\n", ((struct protoent *)getprotobynumber(ipds->ip->ip_p))->p_name);
        else
            snprintf(buf+strlen(buf), sizeof( buf), " unknown\n");
    }
    if (ip->ip_v == 6) {
        
        struct ip6_hdr *ip6;
        char ip6addr[INET6_ADDRSTRLEN];
        int sizeip6dr = sizeof(struct ip6_hdr);
        ip6 = ( struct ip6_hdr *)sp;
        int  nh = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        
        const u_char *cp = sp + sizeip6dr;
        if (nh == 6) {
            const struct tcphdr *up;
            
            up = (struct tcphdr *)cp;
            sport = EXTRACT_16BITS(&up->th_sport);
            dport = EXTRACT_16BITS(&up->th_dport);
            
            
            
        }
        if (nh ==  17) {
            const struct udphdr *up;
            
            up = (struct udphdr *)cp;
            sport = EXTRACT_16BITS(&up->uh_sport);
            dport = EXTRACT_16BITS(&up->uh_dport);
            
            
            
        }
        snprintf(buf+strlen(buf), sizeof( buf), "%s.%u > ", inet_ntop(AF_INET6, &ip6->ip6_src, ip6addr, INET6_ADDRSTRLEN),sport);
        snprintf(buf+strlen(buf), sizeof( buf), "%s.%u:", inet_ntop(AF_INET6, &ip6->ip6_dst, ip6addr, INET6_ADDRSTRLEN),dport);
        if (getprotobynumber(nh) != NULL)
            snprintf(buf+strlen(buf), sizeof( buf), " %s\n", ((struct protoent *)getprotobynumber(nh))->p_name);
        else
            snprintf(buf+strlen(buf), sizeof( buf)," unknown\n");
        
    }
    
    
    //printf("%s", buf);
    
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(date, sizeof(date)-1, "%m %d %H:%M:%S ", t);
    fp = fopen(outputFilename, "a");
    
    strcpy(textoutput, date);
    strcat(textoutput, hostname);
    strcat(textoutput, " pf ");
    strcat(textoutput, buf);
    
    fputs(textoutput, fp);
    fflush(fp);
    fclose(fp);
    
    
    memset(buf, 0, sizeof(buf));
    
    buf[0] = '\0';
}




int main(int argc, const char * argv[]) {

    gethostname(hostname, 1023);
    gettimeofday(&mytime, NULL);
    
    hpcap = pcap_open_live("pflog0", 500, 1, 500, errbuf);
    if (hpcap == NULL) {
        printf( "Failed to initialize:\n");
        return (-1);
    }
    
    if (pcap_datalink(hpcap) != DLT_PFLOG) {
        printf( "Invalid datalink type");
        pcap_close(hpcap);
        hpcap = NULL;
        return (-1);
    }
    
    
    struct bpf_program bprog;
    
    if (pcap_compile(hpcap, &bprog, filterizing, 1, 0) < 0)
        printf( "%s", pcap_geterr(hpcap));
    else {
        if (pcap_setfilter(hpcap, &bprog) < 0)
            printf( "%s", pcap_geterr(hpcap));
        pcap_freecode(&bprog);
    }
    
    snaplen = pcap_snapshot(hpcap);

    pcap_loop(hpcap, -1, dump_packet, NULL);
    

    
    
    return 0;
}

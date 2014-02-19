#ifndef DNS_PARSE_H
#define DNS_PARSE_H

#include <time.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PKT_DATA_OOB            20              /* 12bytes + 7bytes + 1bytes */
#define UDP_HEADLEN             8
#define DOMAIN_LEN              256
#define QUESTIONS_COUNT_LIMIT          10
#define ANSWERS_COUNT_LIMIT           100 

#define DNS_PATH                "/opt/"

typedef unsigned long long __u64;
typedef unsigned int       __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

#ifndef NIPQUAD
#define NIPQUAD( _addr_ ) \
    ((unsigned char *)&( _addr_ ) )[0], \
    ((unsigned char *)&( _addr_ ) )[1], \
    ((unsigned char *)&( _addr_ ) )[2], \
    ((unsigned char *)&( _addr_ ) )[3]
#endif

struct cap_header {                     
    __u32 magic;                         /* 0xa1b2c3d4 */
    short version_major;
    short version_minor;
    int zone;                                   /* gmt to local correct */
    int timestamps;                             /* accuracy of time tamps */
    int snaplen;                                /* max length saved portion of pkt */
    int linktype;                               /* LINKTYPE_* */
};

struct cap_item {                           
    int sec;                                    /* time stamp */
    int usec;                                   /* time stamp */
    int cap_len;                                /* present length */
    int wire_len;                               /* wire length */
};

struct dns_header{
    __u16 id;
    __u16 qr;                                    /*specifies whether this message is a query (0), or a response (1).*/
    __u16 question_cnt;
    __u16 answer_cnt;
};

struct dns_question{
    char qname[DOMAIN_LEN];
    short qtype;
    short qclass;
};

struct dns_answer{
    char name[DOMAIN_LEN];
    short type;
    short class;
    __u32 ttl;
    __u16 rdlength;
    union{
        __u32 host;
        char cname[DOMAIN_LEN];
        char ns[DOMAIN_LEN];
    }rdata;
};

struct dns_desc_item{
    int timestamps;
    int ip_src;
    int ip_dst;
    struct dns_header dh; 
    struct dns_question dq[QUESTIONS_COUNT_LIMIT];
    struct dns_answer da[ANSWERS_COUNT_LIMIT];
};

typedef struct _udp_header_s
{
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
}_udp_header_t;

enum cmd_para{
	PARA_CAP_FILE = 1,
	PARA_COUNT,
	PARA_MAX
};

/*
 * TYPE            value and meaning
 * A               1 a host address
 * NS              2 an authoritative name server
 * MD              3 a mail destination (Obsolete - use MX)
 * MF              4 a mail forwarder (Obsolete - use MX)
 * CNAME           5 the canonical name for an alias
 * SOA             6 marks the start of a zone of authority
 * MB              7 a mailbox domain name (EXPERIMENTAL)
 * MG              8 a mail group member (EXPERIMENTAL)
 * MR              9 a mail rename domain name (EXPERIMENTAL)
 * NULL            10 a null RR (EXPERIMENTAL)
 * WKS             11 a well known service description
 * PTR             12 a domain name pointer
 * HINFO           13 host information
 * MINFO           14 mailbox or mail list information
 * MX              15 mail exchange
 * TXT             16 text strings
 *
 * QTYPE fields appear in the question part of a query.  QTYPES are a
 * superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
 * following QTYPEs are defined:
 * AXFR            252 A request for a transfer of an entire zone
 * MAILB           253 A request for mailbox-related records (MB, MG or MR)
 * MAILA           254 A request for mail agent RRs (Obsolete - see MX)
 * *               255 A request for all records
 * */

enum dns_rr_type{
	DNS_RR_TYPE_A = 1,
	DNS_RR_TYPE_NS,
	DNS_RR_TYPE_MD,
	DNS_RR_TYPE_MF,
	DNS_RR_TYPE_CNAME,
	DNS_RR_TYPE_SOA,
	DNS_RR_TYPE_MB,
	DNS_RR_TYPE_MG,
	DNS_RR_TYPE_MR,
	DNS_RR_TYPE_NULL,
	DNS_RR_TYPE_WKS,
	DNS_RR_TYPE_PTR,
	DNS_RR_TYPE_HINFO,
	DNS_RR_TYPE_MINFO,
	DNS_RR_TYPE_MX,
	DNS_RR_TYPE_TXT,
	DNS_RR_TYPE_AXFR = 252,
	DNS_RR_TYPE_MAILB,
	DNS_RR_TYPE_MAILA,
	DNS_RR_TYPE_ANY,
};

struct dns_statistics{
    __u64 dns_query;
    __u64 dns_response;
    __u64 non_ip;
    __u64 non_udp;
    __u64 non_dns;
    __u64 error;
    __u64 cnt_error;
};
#endif

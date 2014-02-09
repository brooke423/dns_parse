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
#define QUESTION_LIMIT          10

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

struct dns_desc_item{
    int timestamps;
    int ip_src;
    int ip_dst;
    struct dns_header dh; 
    struct dns_question dq[QUESTION_LIMIT];
    char request[DOMAIN_LEN]; 
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
	PARA_INTERVAL,
	PARA_COUNT,
	PARA_MAX
};

void show_packet(__u8 *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (i && (i & 15) == 0)
            printf("\n");
        printf("%02x ", data[i]);
    }
    printf("\n");
    return;
}


int record_dns_desc(struct dns_desc_item * item){
    time_t ctime=time(NULL);
    FILE *fp=fopen("/root/dns.log","a+");
    if(!fp){
        printf("error to open file:%s\n","/root/dns.log");
        return -1;
    }

    int i;
    

    fprintf(fp,"time=%d dstip=%u.%u.%u.%u srcip=%u.%u.%u.%u type=%s questions=",\
            (int)ctime,NIPQUAD(item->ip_dst),NIPQUAD(item->ip_src),item->dh.qr==0?"query":"response");
    for(i = 0; i < item->dh.question_cnt; i++){
        fprintf(fp,"%s,",item->dq[i].qname); 
    }
    fprintf(fp,"\n");


    fclose(fp);
    return 0;
}

/*
 *parse dns format to domain  
 * hex  ----->  string
 *03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 ----->  www.baidu.com
 * */
int pkt_parse_domain(__u8 *pdomain, char *result)
{
    __u8 c = 0;
    __u16 read = 0;
    while(1){
        c = *pdomain++;
        if(c <= 63 && c != 0){
            strncpy(result+read,(const char *)pdomain, (size_t)c);
            strcat((char *)result+read+c,"." );
            read += (c + 1);
            pdomain += c;
            //printf("read=%d  c=%d %02x\n",read,c,*pdomain);
        }else{ /*end*/
            result[read-1] = '\0';
            break;
        }
    }
    return 0;
}

int pkt_parse_dns(struct dns_desc_item *item, char *buf, __u16 len)
{
    __u16 *ptransid=(__u16 *)buf;
    item->dh.id = *ptransid;
    __u16 *cnt = ptransid + 2;
    item->dh.question_cnt = (ntohs)(*cnt);
    cnt = ptransid + 3;
    item->dh.answer_cnt = (ntohs)(*cnt);

    __u8 cQA  = *(__u8 *)(ptransid + 1);
    __u8 *pquestion = (__u8 *)(ptransid + 6); /*header len is 12bytes*/
    len -= 12;
    int i = 0;
    if ((cQA & 0x80) == 0 ){/*dns request*/
        for(i = 0; i < item->dh.question_cnt; i++){
            pkt_parse_domain(pquestion,item->dq[i].qname);
            pquestion += strlen(item->dq[i].qname) + 2;
            item->dq[i].qtype = (ntohs)(*(__u16 *)pquestion);
            pquestion += 2;
            item->dq[i].qclass = (ntohs)(*(__u16 *)pquestion);
            pquestion += 2;
        }
        record_dns_desc(item);
    }else{/*response*/
        //todo
    }
    return 0;
}

int pkt_parse_head(struct dns_desc_item *item, char *pkt, int len)
{
    char ip_type, *l3_hdr = pkt + 14;
    __u16 l3_type = ntohs(*(short *)(void *)(pkt + 12));

    memset(item,0,sizeof(struct dns_desc_item));
 
    if(l3_type < 0x05dc) {            /* 802.3 type */
        l3_hdr = pkt + 22; 
        l3_type = ntohs(*(short *)(void *)(pkt + 20));
    }   

    if(l3_type == 0x0800){              /* IP type */
        item->ip_src = *(__u32 *)(void *)(l3_hdr + 12);  /*network byte order*/
        item->ip_dst = *(__u32 *)(void *)(l3_hdr + 16);
        ip_type = *(l3_hdr + 9);
        
        if(ip_type == 0x11){               /* UDP type */
            char ip_len = *(__u8 *)l3_hdr << 2 & 0x3f;
            _udp_header_t *l4_hdr = (_udp_header_t *)(l3_hdr + ip_len);
            char * l7_hdr = (char *)(l4_hdr + 1) ;
            __u16 l7_len = ntohs(l4_hdr->len) - sizeof(_udp_header_t);
            if(ntohs(l4_hdr->dest) == 53 || ntohs(l4_hdr->source) == 53){
                pkt_parse_dns(item, l7_hdr, l7_len); 
            }else{
                //todo non-dns
            }
        }else{
            //todo non-udp 
        }
    }else{
        //todo non-ip
    }
    return 0;
}

int main(int argc, char *argv[])
{
	char buf[2048];
	FILE *cap_file;
	long speed, times;
	int *input = (void*)buf;
	struct cap_header file_head = {0,};
	struct cap_item item_head = {0,};
	
	if(argc != PARA_MAX)
		return printf("Userage ./user_drv <cap file> <interval(ms)> <count>\n");
	if(NULL == (cap_file = fopen(argv[PARA_CAP_FILE], "rb")))
		return printf("Error: open %s error.\n", argv[PARA_CAP_FILE]);
	(void)fread(&file_head, 1, sizeof(file_head), cap_file);
	if(file_head.magic != 0xa1b2c3d4 || file_head.version_major != 2 || file_head.version_minor != 4)
		return printf("Error: invalid version of %s.\n", argv[PARA_CAP_FILE]);

	speed = atoi(argv[PARA_INTERVAL]) * 1000;
	times = atoi(argv[PARA_COUNT]);
    
    int count=0;
    struct dns_desc_item mitem;

	do{
		(void)fseek(cap_file, sizeof(file_head), SEEK_SET);
		while(sizeof(item_head) == fread(&item_head, 1, sizeof(item_head), cap_file)){
			bzero(buf, sizeof(buf));
			(void)fread(buf + sizeof(int), 1, item_head.cap_len, cap_file);
			input[0] = item_head.wire_len;
		
            count++;
            show_packet((__u8 *)buf+sizeof(int),input[0]);
            pkt_parse_head(&mitem,(char *)buf+sizeof(int),input[0]);
            printf("------------------------------------------------------------\n\n");
            if(count >= times){
                break;
            }
            usleep(speed);
		}
	}while(count < times);	/* ÏÞÊ± */
	fclose(cap_file);
    return 0;
}

#include "dns_parse.h"

struct dns_statistics g_dns_statistics = {0,};
char g_dns_parse_result_path[256];
char g_dns_parse_statistics[256];
FILE *g_fp;
FILE *flog;

/*
 * @return value
 * 1  -- change new file (per hour)
 * 0  -- use old file
 * */
int new_logfile(time_t tim){
    struct tm  *ptm;
    int    y,m,d,h;
    static int oldh = 0;
    static int non_first_run = 0;

    ptm = localtime(&tim);
    y = ptm->tm_year+1900;
    m = ptm->tm_mon+1; 
    d = ptm->tm_mday;
    h = ptm->tm_hour;

    if(oldh != h && non_first_run){
        snprintf(g_dns_parse_result_path,256,DNS_PATH"%04d%02d%02d%02d.log",y,m,d,h);
        oldh = h;
        return 1;
    }else if(non_first_run){
        return 0;
    }else{
        /*first run,change to new path*/
        snprintf(g_dns_parse_result_path,256,DNS_PATH"%04d%02d%02d%02d.log",y,m,d,h);
        non_first_run = 1;
        return 1;
    }
}

int record_dns_statistics(){
    if(!flog){
        printf("error to open file:%s\n",g_dns_parse_statistics);
        return -1;
    }
    fprintf(flog,"--last dns_query=%llu dns_response=%llu non_ip=%llu non_udp=%llu non_dns=%llu error=%llu cnt_error=%llu\n",\
            g_dns_statistics.dns_query,g_dns_statistics.dns_response,\
            g_dns_statistics.non_ip,g_dns_statistics.non_udp,g_dns_statistics.non_dns,\
            g_dns_statistics.error,g_dns_statistics.cnt_error);
    fclose(flog);
    return 0;
}

static inline char dec2hex(__u8 i)
{
    switch (i) 
    {   

        case 0 ... 9:
            return (char)(i + '0');
            break;

        case 10 ... 15: 
            return (char)(i - 10 + 'a');
            break;

        default:
            printf("Problem in dec2hex:%c\n",i);
            return '\0';
    }   

}

/* domain_print
 * convert special byte to hex mode
 * */
static inline void domain_print(FILE *fp, __u8 *s, int g_len)
{
    /*resize a byte to 5 bytes for hex_print,max size*/
    int len = g_len;
    int i;

    for(i = 0; i < len; i++)
    {   
        /*They must start with a letter, end with a letter or digit, 
         *and have as interior characters only letters, digits, and hyphen.
         **/
        if((s[i] >= 'a' && s[i] <= 'z') || \
                (s[i] >= 'A' && s[i] <= 'Z') || \
                (s[i] >= '0' && s[i] <= '9') || \
                s[i] == '-' || s[i] == '.'){
            fprintf(fp,"%c",s[i]);
        }else{
            fprintf(fp,"\\x%c%c",dec2hex(s[i]/16)?:'0',dec2hex(s[i]%16)?:'0');
        }   
    }   
    return;
}

int record_dns_desc(struct dns_desc_item * item){
    int i;
    time_t ctime=time(NULL);

    if(new_logfile(ctime)){
        if(!flog){
            printf("error to open file:%s\n",g_dns_parse_statistics);
            return -1;
        }
        fprintf(flog,"file=%s dns_query=%lludns_response=%llu non_ip=%llu non_udp=%llu non_dns=%llu error=%llu\n",\
                g_dns_parse_result_path,g_dns_statistics.dns_query,g_dns_statistics.dns_response,\
                g_dns_statistics.non_ip,g_dns_statistics.non_udp,g_dns_statistics.non_dns,\
                g_dns_statistics.error);

        /*change new file or first run,basicly unless first run at 0:00*/
        fclose(g_fp);
        g_fp=fopen(g_dns_parse_result_path,"a+");
        if(!g_fp){
            printf("error to open file:%s\n",g_dns_parse_result_path);
            fprintf(flog,"error to open file:%s\n",g_dns_parse_result_path);
            return -1;
        }
    }

    //printf("%s\n",g_dns_parse_result_path);

    fprintf(g_fp,"time=%d dstip=%u.%u.%u.%u srcip=%u.%u.%u.%u type=%s dns_id=%x questions=",\
            (int)ctime,NIPQUAD(item->ip_dst),NIPQUAD(item->ip_src),\
            item->dh.qr==0?"query":"response",item->dh.id);
    for(i = 0; i < item->dh.question_cnt; i++){
        domain_print(g_fp,(__u8 *)item->dq[i].qname,strlen(item->dq[i].qname));
        fprintf(g_fp,",");
    }
    
    /*answer*/
    fprintf(g_fp," answers=");
    for(i = 0; i < item->dh.answer_cnt; i++){
        switch(item->da[i].type){
            case DNS_ANSWER_TYPE_A:
                domain_print(g_fp,(__u8 *)item->da[i].name,strlen(item->da[i].name));
                fprintf(g_fp,":HOST:%u.%u.%u.%u,",NIPQUAD(item->da[i].rdata.host));
                break;
            case DNS_ANSWER_TYPE_CNAME:
                domain_print(g_fp,(__u8 *)item->da[i].name,strlen(item->da[i].name));
                fprintf(g_fp,":CNAME:");
                domain_print(g_fp,(__u8 *)item->da[i].rdata.cname,strlen(item->da[i].rdata.cname));
                fprintf(g_fp,",");
                break;
            default:
                break;
        }
    }
    fprintf(g_fp,"\n");

    return 0;
}

/*@fuction
 * int __pkt_parse_domain(__u8 *pdomain, char *result)
 *
 *@description
 *  parse dns format to domain without compression 
 *  hex  ----->  string
 *  03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 ----->  www.baidu.com
 *  
 *  __u8 *pdomain -- pointer to dns domain
 *  char *result  -- pointer to dns_desc_item dq or da
 *  int *sz     -- the count of bytes parse 
 *
 *@return value 
 *  0             -- sucess 
 *  1             -- compression mode,pointer need parse later
 * */
static inline int __pkt_parse_domain(__u8 *pdomain, char *result, int *sz)
{
    __u8 c = 0;
    __u16 read = 0;
    while(1){
        c = *pdomain++;
        if(c <= 63 && c != 0){
            memcpy(result+read,(const char *)pdomain, (size_t)c);
            result[read+c] = '.';
            read += (c + 1);
            pdomain += c;
            //printf("read=%d  c=%d %02x\n",read,c,*pdomain);
        }else if(c > 63){
            /*compression pointer, non end*/
            *sz = read;
            return 1;
        }else if(c == 0){ 
            /*end,return read size with one byte plus('\0')*/
            if(read > 1){
                result[read-1] = '\0';
            }
            *sz = read + 1;
            return 0;
        }else{
            //unknown
            printf("unknown byte!!!\n");
            *sz = read;
            break;
        }
    }
    return 0;
}



/*@fuction
 * int pkt_parse_domain(__u8 *pdomain, char *result,char *l7_hdr)
 *
 *@description
 *  parse dns format to domain with compression 
 *   The compression scheme allows a domain name in a message to be
 *   represented as either:
 *   - a sequence of labels ending in a zero octet
 *   - a pointer
 *   - a sequence of labels ending with a pointer
 *
 * */
int pkt_parse_domain(__u8 *pdomain, char *result, char *l7_hdr)
{
    int sz = 0;
    int total_sz = 0;  /*must use first value*/
    __u8 *pcur = pdomain;
    char *pres = result;

    __u16 offset;

    while(__pkt_parse_domain(pcur,pres,&sz)){
        if(sz){
            /* - a sequence of labels ending with a pointer */
            pcur += sz;
            pres += sz;
            if(0 == total_sz){
                total_sz = sz + 2; /*sz  plus sizeof(offset)*/
            }
        }else{
            /* - a pointer */
            if(0 == total_sz){
                total_sz = 2; /*sz  plus sizeof(offset)*/
            }
        }
        offset = (ntohs(*(__u16 *)pcur)) & 0x3fff;   /*pointer offset*/
        pcur = (__u8 *)l7_hdr + offset;
    }

    if(0 == total_sz){
        /* - a sequence of labels ending in a zero octet */
        total_sz = sz;
    }

    return total_sz ;
}

int pkt_parse_dns(struct dns_desc_item *item, char *l7_hdr, __u16 len)
{
    __u16 *ptransid=(__u16 *)l7_hdr;
    item->dh.id = *ptransid;
    __u16 *cnt = ptransid + 2;
    item->dh.question_cnt = ntohs(*cnt);
    cnt = ptransid + 3;
    item->dh.answer_cnt = ntohs(*cnt);

    if((item->dh.question_cnt > QUESTIONS_COUNT_LIMIT) || \
            (item->dh.answer_cnt > ANSWERS_COUNT_LIMIT) ){
        g_dns_statistics.cnt_error++;
        return -1;
    }

    __u8 cQA  = *(__u8 *)(ptransid + 1);
    __u8 *pquestion = (__u8 *)(ptransid + 6); /*header len is 12bytes*/
    len -= 12;
    int i = 0;
    if ((cQA & 0x80) == 0 ){/*dns request*/
        item->dh.qr = 0;
        for(i = 0; i < item->dh.question_cnt; i++){
            pquestion += pkt_parse_domain(pquestion,item->dq[i].qname,l7_hdr);
            item->dq[i].qtype = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
            item->dq[i].qclass = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
        }
        g_dns_statistics.dns_query++;
        record_dns_desc(item);
    }else{/*response*/
        item->dh.qr = 1;
        for(i = 0; i < item->dh.question_cnt; i++){
            pquestion += pkt_parse_domain(pquestion,item->dq[i].qname,l7_hdr);
            item->dq[i].qtype = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
            item->dq[i].qclass = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
        }
        for(i = 0; i < item->dh.answer_cnt; i++){
            pquestion += pkt_parse_domain(pquestion,item->da[i].name,l7_hdr);
            item->da[i].type = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
            item->da[i].class = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
            item->da[i].ttl = (ntohl)(*(__u32 *)pquestion);
            pquestion += 4;
            item->da[i].rdlength = ntohs(*(__u16 *)pquestion);
            pquestion += 2;
            switch(item->da[i].type){
                case DNS_ANSWER_TYPE_A:
                    item->da[i].rdata.host = *(__u32 *)pquestion;
                    pquestion += 4;
                    break;
                case DNS_ANSWER_TYPE_CNAME:
                    pquestion += pkt_parse_domain(pquestion,item->da[i].rdata.cname,l7_hdr);
                    break;
                default:
                    printf("Error:unsupport answer type!!!\n");
                    g_dns_statistics.error++;
                    return -1;
            }
        }
        g_dns_statistics.dns_response++;
        record_dns_desc(item);
    }
    return 0;
}

int pkt_parse_head(struct dns_desc_item *item, char *pkt, int len)
{
    char ip_type, *l3_hdr = pkt + 14;
    __u16 l3_type = ntohs(*(short *)(void *)(pkt + 12));

    /*performance optimization*/
    //memset(item,0,sizeof(struct dns_desc_item));

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
                g_dns_statistics.non_dns++;
            }
        }else{
            g_dns_statistics.non_udp++;
        }
    }else{
        g_dns_statistics.non_ip++;
    }
    return 0;
}

int main(int argc, char *argv[])
{
	char buf[2048];
	FILE *cap_file;
	long times;
	int *input = (void*)buf;
	struct cap_header file_head = {0,};
	struct cap_item item_head = {0,};
	
	if(argc != PARA_MAX)
		return printf("Userage ./user_drv <cap file> <count>\n");
	if(NULL == (cap_file = fopen(argv[PARA_CAP_FILE], "rb")))
		return printf("Error: open %s error.\n", argv[PARA_CAP_FILE]);
	(void)fread(&file_head, 1, sizeof(file_head), cap_file);
	if(file_head.magic != 0xa1b2c3d4 || file_head.version_major != 2 || file_head.version_minor != 4)
		return printf("Error: invalid version of %s.\n", argv[PARA_CAP_FILE]);

	times = atoi(argv[PARA_COUNT]);
    strncpy(g_dns_parse_result_path,"/opt/dns_parse_result.log",255);
    strncpy(g_dns_parse_statistics,DNS_PATH"g_dns_parse_statistics.log",255);

    int count=0;
    struct dns_desc_item* pitem = (struct dns_desc_item *)calloc(sizeof(struct dns_desc_item),1);
    if(!pitem){
        printf("Error: malloc pitem\n");
        return -1;
    }

    g_fp=fopen("/opt/g_file.log","a+");
    flog = fopen(g_dns_parse_statistics,"a+");
	do{
		(void)fseek(cap_file, sizeof(file_head), SEEK_SET);
		while(sizeof(item_head) == fread(&item_head, 1, sizeof(item_head), cap_file)){
			bzero(buf, sizeof(buf));
			(void)fread(buf + sizeof(int), 1, item_head.cap_len, cap_file);
			input[0] = item_head.wire_len;
		
            count++;
            pkt_parse_head(pitem,(char *)buf+sizeof(int),input[0]);
            if(count >= times){
                break;
            }
            //usleep(1);
		}
	}while(count < times);
	fclose(cap_file);
    record_dns_statistics();
    fclose(g_fp);
    return 0;
}

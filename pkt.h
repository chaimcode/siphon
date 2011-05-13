typedef u_int32_t tcp_seq;
 
struct tcp_header {
	u_int16_t th_sport;		/* source port */
	u_int16_t th_dport;		/* destination port */
	tcp_seq	  th_seq;		/* sequence number */
	tcp_seq	  th_ack;		/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t  th_x2:4,		/* (unused) */
		  th_off:4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int8_t  th_off:4,		/* data offset */
		  th_x2:4;		/* (unused) */
#endif
	u_int8_t  th_flags;
#define	TH_FIN	  0x01
#define	TH_SYN	  0x02
#define	TH_RST	  0x04
#define	TH_PUSH	  0x08
#define	TH_ACK	  0x10
#define	TH_URG	  0x20
	u_int16_t th_win;			/* window */
	u_int16_t th_sum;			/* checksum */
	u_int16_t th_urp;			/* urgent pointer */
};

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t  ip_hl:4,		/* header length */
		  ip_v:4;		/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int8_t  ip_v:4,		/* version */
		  ip_hl:4;		/* header length */
#endif
	u_int8_t  ip_tos;		/* type of service */
	u_int16_t ip_len;		/* total length */
	u_int16_t ip_id;		/* identification */
	u_int16_t ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t  ip_ttl;		/* time to live */
	u_int8_t  ip_p;			/* protocol */
	u_int16_t ip_sum;		/* checksum */
	struct	  in_addr ip_src, ip_dst; /* source and dest address */
};

struct udp_header {
	u_int16_t uh_sport;		/* source port */
	u_int16_t uh_dport;		/* destination port */
	u_int16_t uh_ulen;		/* udp length */
	u_int16_t uh_sum;		/* udp checksum */
};



/* header auto-generated by pidl */

#ifndef _PIDL_HEADER_dns
#define _PIDL_HEADER_dns

#include <stdint.h>

#include "libcli/util/ntstatus.h"

#include "librpc/gen_ndr/misc.h"
#include "librpc/gen_ndr/dnsp.h"
#ifndef _HEADER_dns
#define _HEADER_dns

#define DNS_SERVICE_PORT	( 53 )
#define DNS_MAX_LABELS	( 127 )
#define DNS_MAX_DOMAIN_LENGTH	( 253 )
#define DNS_MAX_LABEL_LENGTH	( 63 )
/* bitmap dns_operation */
#define DNS_RCODE ( 0x000F )
#define DNS_FLAG_BROADCAST ( 0x0010 )
#define DNS_FLAG_RECURSION_AVAIL ( 0x0080 )
#define DNS_FLAG_RECURSION_DESIRED ( 0x0100 )
#define DNS_FLAG_TRUNCATION ( 0x0200 )
#define DNS_FLAG_AUTHORITATIVE ( 0x0400 )
#define DNS_OPCODE ( 0x7800 )
#define DNS_FLAG_REPLY ( 0x8000 )

enum dns_opcode
#ifndef USE_UINT_ENUMS
 {
	DNS_OPCODE_QUERY=(int)((0x0<<11)),
	DNS_OPCODE_IQUERY=(int)((0x1<<11)),
	DNS_OPCODE_STATUS=(int)((0x2<<11)),
	DNS_OPCODE_UPDATE=(int)((0x5<<11)),
	DNS_OPCODE_RELEASE=(int)((0x6<<11)),
	DNS_OPCODE_WACK=(int)((0x7<<11)),
	DNS_OPCODE_REFRESH=(int)((0x8<<11)),
	DNS_OPCODE_REFRESH2=(int)((0x9<<11)),
	DNS_OPCODE_MULTI_HOME_REG=(int)((0xf<<11))
}
#else
 { __do_not_use_enum_dns_opcode=0x7FFFFFFF}
#define DNS_OPCODE_QUERY ( (0x0<<11) )
#define DNS_OPCODE_IQUERY ( (0x1<<11) )
#define DNS_OPCODE_STATUS ( (0x2<<11) )
#define DNS_OPCODE_UPDATE ( (0x5<<11) )
#define DNS_OPCODE_RELEASE ( (0x6<<11) )
#define DNS_OPCODE_WACK ( (0x7<<11) )
#define DNS_OPCODE_REFRESH ( (0x8<<11) )
#define DNS_OPCODE_REFRESH2 ( (0x9<<11) )
#define DNS_OPCODE_MULTI_HOME_REG ( (0xf<<11) )
#endif
;

enum dns_rcode
#ifndef USE_UINT_ENUMS
 {
	DNS_RCODE_OK=(int)(0x00),
	DNS_RCODE_FORMERR=(int)(0x01),
	DNS_RCODE_SERVFAIL=(int)(0x02),
	DNS_RCODE_NXDOMAIN=(int)(0x03),
	DNS_RCODE_NOTIMP=(int)(0x04),
	DNS_RCODE_REFUSED=(int)(0x05),
	DNS_RCODE_YXDOMAIN=(int)(0x06),
	DNS_RCODE_YXRRSET=(int)(0x07),
	DNS_RCODE_NXRRSET=(int)(0x08),
	DNS_RCODE_NOTAUTH=(int)(0x09),
	DNS_RCODE_NOTZONE=(int)(0x0A),
	DNS_RCODE_BADSIG=(int)(0x10),
	DNS_RCODE_BADKEY=(int)(0x11),
	DNS_RCODE_BADTIME=(int)(0x12),
	DNS_RCODE_BADMODE=(int)(0x13),
	DNS_RCODE_BADNAME=(int)(0x14),
	DNS_RCODE_BADALG=(int)(0x15)
}
#else
 { __do_not_use_enum_dns_rcode=0x7FFFFFFF}
#define DNS_RCODE_OK ( 0x00 )
#define DNS_RCODE_FORMERR ( 0x01 )
#define DNS_RCODE_SERVFAIL ( 0x02 )
#define DNS_RCODE_NXDOMAIN ( 0x03 )
#define DNS_RCODE_NOTIMP ( 0x04 )
#define DNS_RCODE_REFUSED ( 0x05 )
#define DNS_RCODE_YXDOMAIN ( 0x06 )
#define DNS_RCODE_YXRRSET ( 0x07 )
#define DNS_RCODE_NXRRSET ( 0x08 )
#define DNS_RCODE_NOTAUTH ( 0x09 )
#define DNS_RCODE_NOTZONE ( 0x0A )
#define DNS_RCODE_BADSIG ( 0x10 )
#define DNS_RCODE_BADKEY ( 0x11 )
#define DNS_RCODE_BADTIME ( 0x12 )
#define DNS_RCODE_BADMODE ( 0x13 )
#define DNS_RCODE_BADNAME ( 0x14 )
#define DNS_RCODE_BADALG ( 0x15 )
#endif
;

enum dns_qclass
#ifndef USE_UINT_ENUMS
 {
	DNS_QCLASS_IN=(int)(0x0001),
	DNS_QCLASS_NONE=(int)(0x00FE),
	DNS_QCLASS_ANY=(int)(0x00FF)
}
#else
 { __do_not_use_enum_dns_qclass=0x7FFFFFFF}
#define DNS_QCLASS_IN ( 0x0001 )
#define DNS_QCLASS_NONE ( 0x00FE )
#define DNS_QCLASS_ANY ( 0x00FF )
#endif
;

enum dns_qtype
#ifndef USE_UINT_ENUMS
 {
	DNS_QTYPE_ZERO=(int)(0x0000),
	DNS_QTYPE_A=(int)(0x0001),
	DNS_QTYPE_NS=(int)(0x0002),
	DNS_QTYPE_MD=(int)(0x0003),
	DNS_QTYPE_MF=(int)(0x0004),
	DNS_QTYPE_CNAME=(int)(0x0005),
	DNS_QTYPE_SOA=(int)(0x0006),
	DNS_QTYPE_MB=(int)(0x0007),
	DNS_QTYPE_MG=(int)(0x0008),
	DNS_QTYPE_MR=(int)(0x0009),
	DNS_QTYPE_NULL=(int)(0x000A),
	DNS_QTYPE_WKS=(int)(0x000B),
	DNS_QTYPE_PTR=(int)(0x000C),
	DNS_QTYPE_HINFO=(int)(0x000D),
	DNS_QTYPE_MINFO=(int)(0x000E),
	DNS_QTYPE_MX=(int)(0x000F),
	DNS_QTYPE_TXT=(int)(0x0010),
	DNS_QTYPE_RP=(int)(0x0011),
	DNS_QTYPE_AFSDB=(int)(0x0012),
	DNS_QTYPE_X25=(int)(0x0013),
	DNS_QTYPE_ISDN=(int)(0x0014),
	DNS_QTYPE_RT=(int)(0x0015),
	DNS_QTYPE_SIG=(int)(0x0018),
	DNS_QTYPE_KEY=(int)(0x0019),
	DNS_QTYPE_AAAA=(int)(0x001C),
	DNS_QTYPE_LOC=(int)(0x001D),
	DNS_QTYPE_NXT=(int)(0x001E),
	DNS_QTYPE_NETBIOS=(int)(0x0020),
	DNS_QTYPE_SRV=(int)(0x0021),
	DNS_QTYPE_ATMA=(int)(0x0022),
	DNS_QTYPE_NAPTR=(int)(0x0023),
	DNS_QTYPE_DNAME=(int)(0x0027),
	DNS_QTYPE_OPT=(int)(0x0029),
	DNS_QTYPE_DS=(int)(0x002B),
	DNS_QTYPE_RRSIG=(int)(0x002E),
	DNS_QTYPE_NSEC=(int)(0x002F),
	DNS_QTYPE_DNSKEY=(int)(0x0030),
	DNS_QTYPE_DHCID=(int)(0x0031),
	DNS_QTYPE_TKEY=(int)(0x00F9),
	DNS_QTYPE_TSIG=(int)(0x00FA),
	DNS_QTYPE_AXFR=(int)(0x00FC),
	DNS_QTYPE_MAILB=(int)(0x00FD),
	DNS_QTYPE_MAILA=(int)(0x00FE),
	DNS_QTYPE_ALL=(int)(0x00FF)
}
#else
 { __do_not_use_enum_dns_qtype=0x7FFFFFFF}
#define DNS_QTYPE_ZERO ( 0x0000 )
#define DNS_QTYPE_A ( 0x0001 )
#define DNS_QTYPE_NS ( 0x0002 )
#define DNS_QTYPE_MD ( 0x0003 )
#define DNS_QTYPE_MF ( 0x0004 )
#define DNS_QTYPE_CNAME ( 0x0005 )
#define DNS_QTYPE_SOA ( 0x0006 )
#define DNS_QTYPE_MB ( 0x0007 )
#define DNS_QTYPE_MG ( 0x0008 )
#define DNS_QTYPE_MR ( 0x0009 )
#define DNS_QTYPE_NULL ( 0x000A )
#define DNS_QTYPE_WKS ( 0x000B )
#define DNS_QTYPE_PTR ( 0x000C )
#define DNS_QTYPE_HINFO ( 0x000D )
#define DNS_QTYPE_MINFO ( 0x000E )
#define DNS_QTYPE_MX ( 0x000F )
#define DNS_QTYPE_TXT ( 0x0010 )
#define DNS_QTYPE_RP ( 0x0011 )
#define DNS_QTYPE_AFSDB ( 0x0012 )
#define DNS_QTYPE_X25 ( 0x0013 )
#define DNS_QTYPE_ISDN ( 0x0014 )
#define DNS_QTYPE_RT ( 0x0015 )
#define DNS_QTYPE_SIG ( 0x0018 )
#define DNS_QTYPE_KEY ( 0x0019 )
#define DNS_QTYPE_AAAA ( 0x001C )
#define DNS_QTYPE_LOC ( 0x001D )
#define DNS_QTYPE_NXT ( 0x001E )
#define DNS_QTYPE_NETBIOS ( 0x0020 )
#define DNS_QTYPE_SRV ( 0x0021 )
#define DNS_QTYPE_ATMA ( 0x0022 )
#define DNS_QTYPE_NAPTR ( 0x0023 )
#define DNS_QTYPE_DNAME ( 0x0027 )
#define DNS_QTYPE_OPT ( 0x0029 )
#define DNS_QTYPE_DS ( 0x002B )
#define DNS_QTYPE_RRSIG ( 0x002E )
#define DNS_QTYPE_NSEC ( 0x002F )
#define DNS_QTYPE_DNSKEY ( 0x0030 )
#define DNS_QTYPE_DHCID ( 0x0031 )
#define DNS_QTYPE_TKEY ( 0x00F9 )
#define DNS_QTYPE_TSIG ( 0x00FA )
#define DNS_QTYPE_AXFR ( 0x00FC )
#define DNS_QTYPE_MAILB ( 0x00FD )
#define DNS_QTYPE_MAILA ( 0x00FE )
#define DNS_QTYPE_ALL ( 0x00FF )
#endif
;

enum dns_tkey_mode
#ifndef USE_UINT_ENUMS
 {
	DNS_TKEY_MODE_NULL=(int)(0x0000),
	DNS_TKEY_MODE_SERVER=(int)(0x0001),
	DNS_TKEY_MODE_DH=(int)(0x0002),
	DNS_TKEY_MODE_GSSAPI=(int)(0x0003),
	DNS_TKEY_MODE_CLIENT=(int)(0x0004),
	DNS_TKEY_MODE_DELETE=(int)(0x0005),
	DNS_TKEY_MODE_LAST=(int)(0xFFFF)
}
#else
 { __do_not_use_enum_dns_tkey_mode=0x7FFFFFFF}
#define DNS_TKEY_MODE_NULL ( 0x0000 )
#define DNS_TKEY_MODE_SERVER ( 0x0001 )
#define DNS_TKEY_MODE_DH ( 0x0002 )
#define DNS_TKEY_MODE_GSSAPI ( 0x0003 )
#define DNS_TKEY_MODE_CLIENT ( 0x0004 )
#define DNS_TKEY_MODE_DELETE ( 0x0005 )
#define DNS_TKEY_MODE_LAST ( 0xFFFF )
#endif
;

struct dns_name_question {
	const char * name;
	enum dns_qtype question_type;
	enum dns_qclass question_class;
}/* [public] */;

struct dns_rdata_data {
	uint16_t length;
	uint8_t *data;
}/* [public] */;

struct dns_soa_record {
	const char * mname;
	const char * rname;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};

struct dns_mx_record {
	uint16_t preference;
	const char * exchange;
}/* [public] */;

struct dns_txt_record {
	struct dnsp_string_list txt;
}/* [nopull,public] */;

struct dns_rp_record {
	const char * mbox;
	const char * txt;
}/* [public] */;

struct dns_srv_record {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	const char * target;
}/* [public] */;

struct dns_opt_record {
	uint16_t option_code;
	uint16_t option_length;
	uint8_t *option_data;
}/* [public] */;

struct dns_tkey_record {
	const char * algorithm;
	uint32_t inception;
	uint32_t expiration;
	enum dns_tkey_mode mode;
	uint16_t error;
	uint16_t key_size;
	uint8_t *key_data;
	uint16_t other_size;
	uint8_t *other_data;
}/* [flag(LIBNDR_FLAG_NO_COMPRESSION),public] */;

struct dns_tsig_record {
	const char * algorithm_name;
	uint16_t time_prefix;
	uint32_t time;
	uint16_t fudge;
	uint16_t mac_size;
	uint8_t *mac;
	uint16_t original_id;
	uint16_t error;
	uint16_t other_size;
	uint8_t *other_data;
}/* [flag(LIBNDR_FLAG_NO_COMPRESSION),public] */;

struct dns_fake_tsig_rec {
	const char * name;
	enum dns_qclass rr_class;
	uint32_t ttl;
	const char * algorithm_name;
	uint16_t time_prefix;
	uint32_t time;
	uint16_t fudge;
	uint16_t error;
	uint16_t other_size;
	uint8_t *other_data;
}/* [flag(LIBNDR_FLAG_NO_COMPRESSION|LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_BIGENDIAN|LIBNDR_PRINT_ARRAY_HEX),public] */;

union dns_rdata {
	const char * ipv4_record;/* [case(DNS_QTYPE_A)] */
	const char * ns_record;/* [case(DNS_QTYPE_NS)] */
	const char * cname_record;/* [case(DNS_QTYPE_CNAME)] */
	struct dns_soa_record soa_record;/* [case(DNS_QTYPE_SOA)] */
	const char * ptr_record;/* [case(DNS_QTYPE_PTR)] */
	struct dnsp_hinfo hinfo_record;/* [case(DNS_QTYPE_HINFO)] */
	struct dns_mx_record mx_record;/* [case(DNS_QTYPE_MX)] */
	struct dns_txt_record txt_record;/* [case(DNS_QTYPE_TXT)] */
	struct dns_rp_record rp_record;/* [case(DNS_QTYPE_RP)] */
	const char * ipv6_record;/* [case(DNS_QTYPE_AAAA)] */
	struct dns_srv_record srv_record;/* [case(DNS_QTYPE_SRV)] */
	struct dns_opt_record opt_record;/* [case(DNS_QTYPE_OPT)] */
	struct dns_tsig_record tsig_record;/* [case(DNS_QTYPE_TSIG)] */
	struct dns_tkey_record tkey_record;/* [case(DNS_QTYPE_TKEY)] */
}/* [flag(LIBNDR_FLAG_NOALIGN),nodiscriminant,public] */;

struct dns_res_rec {
	const char * name;
	enum dns_qtype rr_type;
	enum dns_qclass rr_class;
	uint32_t ttl;
	uint16_t length;
	union dns_rdata rdata;/* [switch_is(rr_type)] */
	DATA_BLOB unexpected;
}/* [flag(LIBNDR_PRINT_ARRAY_HEX|LIBNDR_FLAG_NOALIGN),nopull,nopush] */;

struct dns_name_packet {
	uint16_t id;
	uint16_t operation;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	struct dns_name_question *questions;
	struct dns_res_rec *answers;
	struct dns_res_rec *nsrecs;
	struct dns_res_rec *additional;
}/* [flag(LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_BIGENDIAN|LIBNDR_PRINT_ARRAY_HEX),public] */;


struct decode_dns_name_packet {
	struct {
		struct dns_name_packet packet;
	} in;

};

#endif /* _HEADER_dns */
#endif /* _PIDL_HEADER_dns */

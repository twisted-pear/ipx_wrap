#ifndef __IPX_WRAP_PING_H__
#define __IPX_WRAP_PING_H__

#include <bpf/bpf.h>

#define PING_SOCK 0x9086
#define PING_PKT_TYPE 0x04

#define PING_STR "Ping"
#define PING_STR_LEN 4
#define PING_VERSION 0x01
#define PING_TYPE_QUERY 0x00
#define PING_TYPE_REPLY 0x01
#define PING_RESULT_QUERY 0x00
#define PING_RESULT_REPLY 0x01

struct ping_pkt {
	char ping[PING_STR_LEN];
	__u8 version;
	__u8 type;
	__be16 id;
	__u8 result;
	__u8 reserved;
	__u8 data[0];
};

#endif /* __IPX_WRAP_PING_H__ */

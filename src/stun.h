/*
 * stun.h
 *
 *  Created on: Feb 18, 2014
 *      Author: andra
 */

#ifndef STUN_H_INCLUDED
#define STUN_H_INCLUDED


#include <stdbool.h>

#define STUN_SERVER "stun.services.mozilla.com" //"stun.stunprotocol.org", "stunserver.org"
// we use stunserver.org because it recognizes the RESPONSE-ADDRESS attribute in the STUN-REQUEST
// from the client
// --> for the future: we should implement our own server
#define STUN_PORT 3478
//#define STUN_PORT 3479 -- change
#define STUN_COUNT 1
#define STUN_TIMEOUT 5
#define NO_ICMP_PACKET_TO_READ 0
#define TIMEOUT 3
#define MAXBUFLEN 62

typedef struct { unsigned int id[4]; } __attribute__((packed)) stun_trans_id;

typedef struct {
	int tv_sec; // seconds
	int tv_usec; // microseconds
} timeval;

typedef struct{
	int type;
	int code;
	char* r_addr;
} reply_probe;

typedef struct stun_uint_attr
{
     // STUN attribute type.
	unsigned short int		type;
    unsigned short int		length;
     // The 32bit value, in host byte order.
    unsigned int		value; //uint32_t

} stun_uint_attr;


struct stun_header {
	unsigned short msgtype;
	unsigned short msglen;
	stun_trans_id  id;
	unsigned char  ies[0];
} __attribute__((packed));


struct stun_attr {
	unsigned short attr;
	unsigned short len;
	unsigned char  value[0];
} __attribute__((packed));

/*
 * The format normally used for addresses carried by STUN messages.
 */
struct stun_addr {
	unsigned char  unused;
	unsigned char  family;
	unsigned short port;
	unsigned int   addr;
} __attribute__((packed));

#define STUN_IGNORE		(0)
#define STUN_ACCEPT		(1)

/* STUN message types
 * 'BIND' refers to transactions used to determine the externally
 * visible addresses. 'SEC' refers to transactions used to establish
 * a session key for subsequent requests.
 * 'SEC' functionality is not supported here.
 */

#define STUN_BINDREQ	0x0001
#define STUN_BINDRESP	0x0101
#define STUN_BINDERR	0x0111
#define STUN_SECREQ	0x0002
#define STUN_SECRESP	0x0102
#define STUN_SECERR	0x0112

/* Basic attribute types in stun messages.
 * Messages can also contain custom attributes (codes above 0x7fff)
 */
#define STUN_MAPPED_ADDRESS	0x0001
#define STUN_RESPONSE_ADDRESS	0x0002
#define STUN_CHANGE_REQUEST	0x0003
#define STUN_SOURCE_ADDRESS	0x0004
#define STUN_CHANGED_ADDRESS	0x0005
#define STUN_USERNAME		0x0006
#define STUN_PASSWORD		0x0007
#define STUN_MESSAGE_INTEGRITY	0x0008
#define STUN_ERROR_CODE		0x0009
#define STUN_UNKNOWN_ATTRIBUTES	0x000a
#define STUN_REFLECTED_FROM	0x000b

/*
 * define the flags for the CHANGE_REQUEST attribute
 */
#define CHANGE_IP_FLAG 0x04;
#define CHANGE_PORT_FLAG 0x02;

static const char *stun_msg2str(int msg)
{
	switch (msg) {
	case STUN_BINDREQ:
		return "Binding Request";
	case STUN_BINDRESP:
		return "Binding Response";
	case STUN_BINDERR:
		return "Binding Error Response";
	case STUN_SECREQ:
		return "Shared Secret Request";
	case STUN_SECRESP:
		return "Shared Secret Response";
	case STUN_SECERR:
		return "Shared Secret Error Response";
	}
	return "Non-RFC3489 Message";
}

// callback type to be invoked on stun responses.
typedef int (stun_cb_f)(struct stun_attr *, void *);

int stun_request(int , struct sockaddr_in *, struct sockaddr_in *, int , int , int );
int stun_request_response_address(int, int, struct sockaddr_in *, struct sockaddr_in *, struct sockaddr_in*);

#endif /* STUN_H_ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
//#include <stdbool.h>

#include "stun.h"
/*
// helper function to print message names

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
*/

/* wrapper to send a STUN message*/
static int stun_send(int s, struct sockaddr_in * dst, struct stun_header * resp)
{
	return sendto(s, resp, ntohs(resp->msglen) + sizeof(*resp), 0, (struct sockaddr *)dst, sizeof(*dst));
}


/* helper function to generate a random request id */
static void stun_req_id(struct stun_header *req)
{
	int x;
	srandom(time(0));
	for (x = 0; x < 4; x++)
		req->id.id[x] = random();
}


/* handle an incoming STUN message.
 *  int type, code;
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 *
 * check for the Message type of the STUN packet as well
 */
static int stun_handle_packet(int s, struct sockaddr_in *src,
		unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg){

	struct stun_header *hdr = (struct stun_header *)data;
	struct stun_attr *attr;
	//unsigned short stun_type;
	int ret = STUN_IGNORE;
	int x;

	/* On entry, 'len' is the length of the udp payload. After the
	 * initial checks it becomes the size of unprocessed options,
	 * while 'data' is advanced accordingly.
	 */
	if (len < sizeof(struct stun_header)) {
		fprintf(stderr, "Runt STUN packet (only %d, wanting at least %d);", (int) len, (int) sizeof(struct stun_header));
		return -1;
	}
	len -= sizeof(struct stun_header);
	data += sizeof(struct stun_header);
	x = ntohs(hdr->msglen);	/* len as advertised in the message */
	fprintf(stderr, " Received STUN %s (%04x) ;", stun_msg2str(ntohs(hdr->msgtype)), ntohs(hdr->msgtype));
	if (x > len) {
		fprintf(stderr, "Scrambled STUN packet length (got %d, expecting %d);", x, (int)len);
	} else
		len = x;
	while (len) {
		if (len < sizeof(struct stun_attr)) {
			fprintf(stderr, "Runt Attribute (got %d, expecting %d);", (int)len, (int) sizeof(struct stun_attr));
			break;
		}
		attr = (struct stun_attr *)data;
		/* compute total attribute length */
		x = ntohs(attr->len) + sizeof(struct stun_attr);
		if (x > len) {
			fprintf(stderr, "Inconsistent Attribute (length %d exceeds remaining msg len %d);", x, (int)len);
			break;
		}
		if (stun_cb)
			stun_cb(attr, arg);

		/* Clear attribute id: in case previous entry was a string,
		 * this will act as the terminator for the string.
		 */
		attr->attr = 0;
		data += x;

		len -= x;
	}
	/* Null terminate any string.
	 * NOTE, we write past the size of the buffer passed by the
	 * caller, so this is potentially dangerous. The only thing that
	 * saves us is that usually we read the incoming message in a
	 * much larger buffer
	 */
	*data = '\0';


	return ret;
}


/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int stun_get_mapped(struct stun_attr *attr, void *arg)
{
	struct stun_addr *addr = (struct stun_addr *)(attr + 1);
	struct sockaddr_in *sa = (struct sockaddr_in *)arg;

	if (ntohs(attr->attr) != STUN_MAPPED_ADDRESS || ntohs(attr->len) != 8){
		return 1;
	}
	sa->sin_port = addr->port;
	sa->sin_addr.s_addr = addr->addr;
	return 0;
}

/* Extract the STUN_MAPPED_ADDRESS and the STUN_CHANGED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int stun_get_changed(struct stun_attr *attr, void *arg)
{
	struct stun_addr *addr = (struct stun_addr *)(attr + 1);
	struct sockaddr_in *ma = (struct sockaddr_in *)arg;


	if (ntohs(attr->attr) != STUN_CHANGED_ADDRESS || ntohs(attr->len) != 8){
		return 1;
	}
	ma->sin_port = addr->port;
	ma->sin_addr.s_addr = addr->addr;

	return 0;
}

static unsigned int bitWrite(unsigned int value, bool bitVal, int bit_location)
{
    if (bitVal==1) value |= 1 << bit_location;
    else value &= ~(1 << bit_location);
    return(value);
}

int stun_request(int s, struct sockaddr_in *dst, struct sockaddr_in *answer,
		int get_changed_address, int changePort, int changeIP)
{
        struct stun_header *req;
        unsigned char reqdata[1024];
        int reqlen;
        int res = 0;
        int retry;
        int stuncount = 1;
        stun_uint_attr *change_req;


        req = (struct stun_header *)reqdata;
        stun_req_id(req);
        reqlen = sizeof(struct stun_uint_attr);
        //reqleft = sizeof(reqdata) - sizeof(struct stun_header);
        req->msglen = 0;
        req->msgtype = 0;
        change_req = (struct stun_uint_attr *)req->ies;
        change_req->type = htons(STUN_CHANGE_REQUEST);
        change_req->length = ntohs(4);
        unsigned int val = 0;
        if(changePort>0){
        	val = bitWrite(val, 1, 25);
        };//else{
        	//val = bitWrite(val, 0, 25);
        //};

        if(changeIP>0){
        	val = bitWrite(val, 1, 26);
        };//else{
        	//val = bitWrite(val, 0, 26);
        //};
        change_req->value = val;// bitWrite(0, 1, 26);



        //(struct stun_uint_attr *)req->ies = change_req;
        req->msglen = htons(reqlen);
        req->msgtype = htons(STUN_BINDREQ);

        for (retry = 0; retry < stuncount; retry++) {
                /* send request, possibly wait for reply */
                unsigned char reply_buf[1024];
                fd_set rfds;
                struct timeval to = { STUN_TIMEOUT, 0 };
                struct sockaddr_in src;
                socklen_t srclen;

                res = stun_send(s, dst, req);
                if (res < 0) {
                        fprintf(stderr, "Request send #%d failed error %d, retry\n",
                                retry, res);
                        continue;
                }
                if (answer == NULL)
                        break;
                FD_ZERO(&rfds);
                FD_SET(s, &rfds);
                res = select(s + 1, &rfds, NULL, NULL, &to);
                if (res <= 0) { /* timeout or error */
                        fprintf(stderr, "Response read timeout #%d failed error %d, retry\n",
                                retry, res);
                        continue;
                }
                bzero(&src, sizeof(src));
                srclen = sizeof(src);
                res = recvfrom(s, reply_buf, sizeof(reply_buf) - 1,
                        0, (struct sockaddr *)&src, &srclen);
                if (res <= 0) {
                        fprintf(stderr, "Response read #%d failed error %d, retry\n",
                                retry, res);
                        continue;
                }
                bzero(answer, sizeof(struct sockaddr_in));
                if (get_changed_address>0){
                	stun_handle_packet(s, &src, reply_buf, res, stun_get_changed, answer);
                }else{
                	stun_handle_packet(s, &src, reply_buf, res, stun_get_mapped, answer);
                };
                return 0;
        }
        return -1;
}
/*send a STUN Binding Request from socket s, request to be replied on socket reply_sock
 * the dst is the STUN server address
 * the answer is the mapped address that the server sends in the STUn Binding Response
 * the rest_addr is the address here the response of the server should be sent*/
int stun_request_response_address(int s, int reply_sock,
		struct sockaddr_in *dst,
		struct sockaddr_in *answer,
		struct sockaddr_in* resp_addr)
{
        struct stun_header *req;
        unsigned char reqdata[1024];
        int reqlen;
        int res = 0;
        int retry;
        int stuncount = 1;
        struct stun_addr *response_address;
        struct stun_attr *addr;


        req = (struct stun_header *)reqdata;
        stun_req_id(req);
        reqlen = sizeof(struct stun_attr) + sizeof(struct stun_addr); //
        //req->msglen = 0;
        //req->msgtype = 0;

        req->msglen = htons(reqlen);
        req->msgtype = htons(STUN_BINDREQ);

        addr = (struct stun_attr *)req->ies;
        addr->attr = htons(STUN_RESPONSE_ADDRESS);
        addr->len = ntohs(8);

        response_address = (struct stun_addr*)addr->value;
        response_address->family = 0x0001;//resp_addr->sin_family;
        response_address->port = resp_addr->sin_port;
        response_address->addr = resp_addr->sin_addr.s_addr;

        for (retry = 0; retry < stuncount; retry++) {
                /* send request, possibly wait for reply */
                unsigned char reply_buf[1024];
                fd_set rfds;
                struct timeval to = { STUN_TIMEOUT, 0 };
                struct sockaddr_in src;
                socklen_t srclen;

                res = stun_send(s, dst, req);
                if (res < 0) {
                        fprintf(stderr, "Request send #%d failed error %d, retry\n",
                                retry, res);
                        continue;
                }
                if (answer == NULL)
                        break;
                FD_ZERO(&rfds);
                FD_SET(reply_sock, &rfds);
                res = select(reply_sock + 1, &rfds, NULL, NULL, &to);
                if (res <= 0) { /* timeout or error */
                        fprintf(stderr, "Response read timeout #%d failed error %d, retry\n",
                                retry, res);
                        continue;
                }
                bzero(&src, sizeof(src));
                srclen = sizeof(src);
                res = recvfrom(reply_sock, reply_buf, sizeof(reply_buf) - 1,
                        0, (struct sockaddr *)&src, &srclen);
                if (res <= 0) {
                        fprintf(stderr, "Response read #%d failed error %d, retry\n",
                                retry, res);
                        continue;
                }
                bzero(answer, sizeof(struct sockaddr_in));
                stun_handle_packet(reply_sock, &src, reply_buf, res, stun_get_mapped, answer);
                return 0;
        }
        return -1;
}


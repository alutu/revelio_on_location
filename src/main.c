#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include "stun.h"
//for microworkers, I'll need to statically link the library
// otherwise, write makefile and put dependency on the miniupnpc
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnperrors.h>

char *stunserver = STUN_SERVER;
int stunport = STUN_PORT;
int debug = 0;
char* location = "";
int icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;
struct timeval timeout = { TIMEOUT, 0 };

/*--------------------------------------------------------------------
 * -------------------- UPnP get external IP -------------------------
 -------------------------------------------------------------------*/

static void DisplayIP(struct UPNPUrls * urls, struct IGDdatas * data) {
	char externalIPAddress[40];
	int r;

	r = UPNP_GetExternalIPAddress(urls->controlURL, data->first.servicetype,
			externalIPAddress);
	if (r != UPNPCOMMAND_SUCCESS) {
		if (debug)
			fprintf(stderr, "GetExternalIPAddress failed. (errorcode=%d);", r);
		fprintf(stdout, "noIGD;");
	} else {
		if (debug) {
			fprintf(stderr, "UPnP EXTERNAL IP: %s\n", externalIPAddress);
		}
		fprintf(stdout, "upnp %s;", externalIPAddress);
	}
}
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
	switch (sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *) sa)->sin_addr), s, maxlen);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) sa)->sin6_addr), s,
				maxlen);
		break;

	default:
		strncpy(s, "Unknown AF", maxlen);
		return NULL;
	}

	return s;
}

/*------------------------------------------------------------------------------------------
 * ---------------------------MAIN----------------------------------------------------------
 -----------------------------------------------------------------------------------------*/

int main(int argc, char ** argv) {
	char oldTests[4096];
	char tests[4096];
	setvbuf(stdout, tests, _IOFBF, 4096);

	//check for the "debug" parameter and the "location"
	int opt;
	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] == '-') {
			if (argv[opt][1] == 'd') {
				debug = 1;
			}
			if (argv[opt][1] == 'l'){ // this parameter allows to uniquely identify the test ran
				location = argv[opt+1];
			}
		}else
			continue;
	}

	//test description
	fprintf(stdout, "REVELIO-onLocation:%s;", location);

	// add unix timestamp
	fprintf(stdout, "%d;", (int) time(NULL));

	/*--------------------------------------------------------------------------------------------------
	 * ---------------------------------------Local IP address-------------------------------------------------
	 --------------------------------------------------------------------------------------------------*/

	char buff[1024] = { 0 };
	struct ifconf ifc = { 0 };
	struct ifreq *ifr = NULL;
	int sck = 0;
	int nInterfaces = 0;
	int i = 0;

	sck = socket(AF_INET, SOCK_DGRAM, 0);
	if (sck < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket");
		}
		return -1;
	}

	/* Query available interfaces. */
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
		if (debug)
			fprintf(stderr, "ioctl(SIOCGIFCONF)");
		return -1;
	}

	/* Iterate through the list of interfaces. */
	ifr = ifc.ifc_req;
	nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
	for (i = 0; i < nInterfaces; i++) {
		struct ifreq *item = &ifr[i];
		/* Show the device name and IP address */
		struct sockaddr *addr = &(item->ifr_addr);
		char ip[INET6_ADDRSTRLEN];
		fprintf(stdout, "%s:%s,", item->ifr_name,
				get_ip_str(addr, ip, INET6_ADDRSTRLEN));
	}
	fprintf(stdout, ";");

	/*--------------------------------------------------------------------------------------------------
	 * ---------------------------------------UPnP detection-------------------------------------------------
	 --------------------------------------------------------------------------------------------------*/
//libminiupnpc needed!!!
	struct UPNPDev * devlist = 0;
	char lanaddr[64]; /* my ip address on the LAN */
	const char * rootdescurl = 0;
	const char * multicastif = 0;
	const char * minissdpdpath = 0;
	int error = 0;
	int ipv6 = 0;
	if (rootdescurl
			|| (devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0,
					ipv6, &error))) {
		struct UPNPUrls urls;
		struct IGDdatas data;

		if (!devlist) {
			if (debug)
				fprintf(stderr, "upnpDiscover()error_code=%d;", error);
		}

		i = 1;
		if ((rootdescurl
				&& UPNP_GetIGDFromUrl(rootdescurl, &urls, &data, lanaddr,
						sizeof(lanaddr)))
				|| (i = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr,
						sizeof(lanaddr)))) {
			DisplayIP(&urls, &data);//prints upnp data
			FreeUPNPUrls(&urls);
		} else {
			fprintf(stdout, "noIGD;");//otherwise noIGD device remark is printed
		}
		freeUPNPDevlist(devlist);
		devlist = 0;
	} else {
		fprintf(stdout, "noIGD;");
	}
	//fflush(stdout);

	/*--------------------------------------------------------------------------------------------------
	 * ---------------------------------------STUN mapped address-------------------------------------------------
	 --------------------------------------------------------------------------------------------------*/
//ministun -- classic stun
	int sock, res, sock2, sock_raw, sock_ttl;
	struct sockaddr_in server, client, mapped, reply_mapped, client2;
	struct hostent *hostinfo;
	int numbytes;
	struct sockaddr_in their_addr;

	socklen_t addr_len;
	addr_len = sizeof their_addr;

	// STEP1: get MAPPED ADDRESS from a STUN server
	hostinfo = gethostbyname(stunserver);
	if (!hostinfo) {
		if (debug) {
			fprintf(stderr, "Error resolving host %s\n", stunserver);
		}
		return -1;
	}
	bzero(&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
	server.sin_port = htons(stunport); //3478

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket\n");
		}
		return -1;
	}

	bzero(&client, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_ANY);
	//client.sin_port = 0;

	if (bind(sock, (struct sockaddr*) &client, sizeof(client)) < 0) {
		if (debug) {
			fprintf(stderr, "Error bind to socket for STUN request\n");
		}
		close(sock);
		return -1;
	}

	res = stun_request(sock, &server, &mapped, -1, -1, -1);
	if (res >= 0) {
		if (debug) {
			fprintf(stderr, "STUN MAPPED ADDRESS: %s:%i;\n",
					inet_ntoa(mapped.sin_addr), ntohs(mapped.sin_port));
		}
		fprintf(stdout, "stun %s:%i;", inet_ntoa(mapped.sin_addr),
				ntohs(mapped.sin_port));
	} else {
		fprintf(stdout, "\n");//exit from here
		exit(0);
	}


	/*---------------------------------------------------------------------------------------------
	 * ------the port-preservation test --> using the STUN server from mozzila---------------------
	 * --------------------------------------------------------------------------------------------*/

	// send one STUN BR to the server, with TTL=2 and hope that the NAT respects port preservation
	int res_pp = -1;
	int ttl_test = 2;
	res = -1;

while (res_pp<0 && res<0) {
	sock_ttl = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_ttl < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket\n");
		}
		return -1;
	}
    //optional: increment until we receive the reply from the STUN server in step1 or the port is preserved
	setsockopt(sock_ttl, IPPROTO_IP, IP_TTL, &ttl_test, sizeof(ttl_test) );
	bzero(&client, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_ANY);
	//client.sin_port = 0;

	if (bind(sock_ttl, (struct sockaddr*) &client, sizeof(client)) < 0) {
		if (debug) {
			fprintf(stderr, "Error bind to socket for STUN request\n");
		}
		close(sock_ttl);
		return -1;
	}
	// this should not make it to the server
	fprintf(stderr, "step 1: send STUN-BR with TTL=%d\n", ttl_test);
	mapped.sin_port=0;

	res_pp = stun_request(sock_ttl, &server, &mapped, -1, -1, -1);
	if (res_pp >= 0) {
		if (mapped.sin_port > 0) {
			fprintf(stderr, "STUN MAPPED ADDRESS: %s:%i;\n",
					inet_ntoa(mapped.sin_addr), ntohs(mapped.sin_port));
		}else{
			fprintf(stderr, "Error: server did not reply");
		}
	}else{
		fprintf(stderr, "STUN server further away than TTL=%i hops\n", ttl_test);
	}

	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	if (getsockname(sock_ttl, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else{
		mapped.sin_port = sin.sin_port;
	    fprintf(stderr, "Assuming gateway mapping preserves client port number: %d\n", ntohs(sin.sin_port));
	}
	// open a new socket, send STUN-BR to the server
	// request that the response of the server be send to the port previously used

	sock2 = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock2 < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket\n");
		}
		return -1;
	}
	bzero(&client2, sizeof(listen));
	client2.sin_family = AF_INET;
	client2.sin_addr.s_addr = htonl(INADDR_ANY);
	//client2.sin_port = 0;

	//socket used to send a STUN BR to the mapped address
	if (bind(sock2, (struct sockaddr*) &client2, sizeof(client2)) < 0) {
		//open sock2 for a random port to send a new request
		if (debug) {
			fprintf(stderr, "Error bind to socket\n");
		}
		close(sock2);
		return -1;
	}

	fprintf(stderr, "step2: check if port open in home gateway\n");
	res = stun_request_response_address(sock2, sock_ttl, &server, &reply_mapped, &mapped);
	if (res >= 0) {
		fprintf(stdout, "TTL=%d,port-preserved:%d[no-CGN]|", ttl_test, ntohs(sin.sin_port));
		if (debug) {
			fprintf(stderr, "STUN MAPPED ADDRESS: %s:%i;\n",
					inet_ntoa(reply_mapped.sin_addr), ntohs(reply_mapped.sin_port));
		}
	}else{
		fprintf(stdout, "TTL=%d,noSTUNresponse-port:%d|", ttl_test, ntohs(sin.sin_port));
	}
	ttl_test++;
	close(sock_ttl);
	close(sock2);
}
    fprintf(stdout, ";");


	/* --------------------------------------------------------------------------------------------------
	 * ---------------------------------------HAIRPIN TEST-----------------------------------------------
	 * -------------------------------------------------------------------------------------------------*/

	//Send a STUN Binding Request to the MAPPED ADDRESS using socket sock2

	sock2 = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock2 < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket\n");
		}
		return -1;
	}
	bzero(&client2, sizeof(listen));
	client2.sin_family = AF_INET;
	client2.sin_addr.s_addr = htonl(INADDR_ANY);
	//client2.sin_port = 0;

	//socket used to send a STUN BR to the mapped address
	if (bind(sock2, (struct sockaddr*) &client2, sizeof(client2)) < 0) {
		//open sockfd for a random port to send a new request
		if (debug) {
			fprintf(stderr, "Error bind to socket\n");
		}
		close(sock2);
		return -1;
	}

	fd_set rfds;
	struct timeval to = { TIMEOUT, 0 };
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	sock_raw = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //listen for incoming STUN BIND REQUESTS
	// error with IPPROTO_UDP --> change to 0
	if (sock_raw < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket hairpin test\n");
		}
		return -1;
	}

	if (bind(sock_raw, (struct sockaddr*) &client, sizeof(client)) < 0) { //open sock for client -- 34780
		if (debug) {
			fprintf(stderr, "Error bind to socket hairpin test\n");
		}
		close(sock_raw);
		return -1;
	}
	res = stun_request(sock2, &server, &mapped, -1, -1, -1);
	stun_request(sock_raw, &mapped, &reply_mapped, -1, -1, -1); // replaced server2 with mapped

	res = select(sock_raw + 1, &rfds, NULL, NULL, &to);
	unsigned char *buf = (unsigned char *) malloc(MAXBUFLEN);
	//if no events are detected on the socket "sock", then close the raw socket
	if (res <= 0) {
		fprintf(stdout, "no hairpin;");//something feeds line break at this place
		close(sock_raw);
	} else {
		if (debug) {
			fprintf(stderr, "will hairpin:");
		}
		int loopback = 0;
		while (loopback == 0) {
			if ((numbytes = recvfrom(sock_raw, buf, MAXBUFLEN - 1, 0,
					(struct sockaddr *) &their_addr, &addr_len)) < 0) {
				if (debug) {
					fprintf(stderr, "Error for recvfrom");
				}

			}

			struct stun_header *hdr = (struct stun_header *) (buf
					+ sizeof(struct udphdr) + sizeof(struct iphdr));
			if (ntohs(hdr->msgtype) == STUN_BINDREQ) {
				loopback = 1;
				fprintf(stdout, "%s(%04x)-", stun_msg2str(ntohs(hdr->msgtype)),
						ntohs(hdr->msgtype));
				struct iphdr *iph = (struct iphdr*) (buf);
				fprintf(stdout, "TTL:%d;", (unsigned int) iph->ttl);
				if (debug) {
					fprintf(stderr, "  |-STUN %s (%04x) \n",
							stun_msg2str(ntohs(hdr->msgtype)),
							ntohs(hdr->msgtype));
					fprintf(stderr, "   |-TTL      : %d\n",
							(unsigned int) iph->ttl);
					fprintf(stderr, "   |-Protocol : %d\n",
							(unsigned int) iph->protocol);
					fprintf(stderr,
							"   |-IP Header Length  : %d DWORDS or %d Bytes\n",
							(unsigned int) iph->ihl,
							((unsigned int) (iph->ihl)) * 4);
				}

			}
		}
		free(buf);
	}
	close(sock2);
	close(sock);
	close(res);
	close(sock_raw);

	strncpy(oldTests, tests, 4096);
//because both arrays were empty initially the line is broken by one of the zeros
//inserted during initialisation.

	/*-------------------------------------------------------------------------------------------------------------------------
	 * --------------------------------TRACEROUTE---------------------------------------------------------------------------
	 ------------------------------------------------------------------------------------------------------------------------*/
// traceroute to mapped address
	int iter = 0;
	int packet_len = 100;
	char trace[512];
	char path[1035];
	memset(trace, '\0', sizeof(512));
	FILE * f;
	char * split;
	//fflush(stdout);
	fprintf(stdout, "%d;", packet_len);
	//fprintf(stdout, "%s", oldTests);
	// normal UDP traceroute
	sprintf(trace, "traceroute -n -q 1 -m 16 -p %d %s %d", ntohs(mapped.sin_port), inet_ntoa(mapped.sin_addr), packet_len);
	f = popen(trace, "r");
	if (f == NULL) {
		fprintf(stdout, ";\n");
		fprintf(stderr, "Failed to run command\n");
		exit(0);
	}
	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path) - 1, f) != NULL) {
		split = strtok(path, "\n");
		fprintf(stdout, "%s|", split);
	}
	fprintf(stdout, ";\n");

	/* close */
	pclose(f);
	fflush(stdout);

	// TCP traceroute to the mapped address

	packet_len = 60;
	fprintf(stdout, "%s", oldTests);
	fprintf(stdout, "%d;", packet_len);
	sprintf(trace, "traceroute -T -n -q 1 -m 16 -p %d %s %d", ntohs(mapped.sin_port), inet_ntoa(mapped.sin_addr), packet_len);
	f = popen(trace, "r");
	if (f == NULL) {
		fprintf(stdout, ";\n");
		fprintf(stderr, "Failed to run command\n");
		exit(0);
	}
	while (fgets(path, sizeof(path) - 1, f) != NULL) {
		split = strtok(path, "\n");
		fprintf(stdout, "%s|", split);
	}
	fprintf(stdout, ";\n");
		/* close */
	pclose(f);
	fflush(stdout);


	while (iter < 5) {
		packet_len = 120 + 200 * iter;
		iter++;
		fprintf(stdout, "%s", oldTests);
		fprintf(stdout, "%d;", packet_len);
		//4.69.158.197  --> level 3 router interface --> no rate limiting
		// alternative target: samknows1.lon1.level3.net --> problem though: it's paced
		sprintf(trace, "traceroute -n -q 1 -m 16 4.69.202.89 %d", packet_len);
		f = popen(trace, "r");
		if (f == NULL) {
			fprintf(stdout, ";\n");
			fprintf(stderr, "Failed to run command\n");
			exit(0);
		}

		/* Read the output a line at a time - output it. */
		while (fgets(path, sizeof(path) - 1, f) != NULL) {
			split = strtok(path, "\n");
			fprintf(stdout, "%s|", split);
		}
		fprintf(stdout, ";");




		fprintf(stdout, "\n");
		fflush(stdout);
	}

	return 1;
}

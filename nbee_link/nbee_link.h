/*
 * nbee_link.h 
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#ifndef TEST_HPP_
#define TEST_HPP_

#include <stdio.h>
#include <stdint.h>
#include "../lib/list_t.h"
#include "../lib/hmap.h"

#define ETHADDLEN 6
#define IPV6ADDLEN 16
#define ETHTYPELEN 2
#define ERRBUF_SIZE 256


typedef struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
}pcap_pkthdr_t;

struct ethernetpkt {
	short ethdst[ETHADDLEN];
	short ethsrc[ETHADDLEN];
	short ethtype[ETHTYPELEN];
};

struct ipv6pkt {
	short ipv6dst[IPV6ADDLEN];
	short ipv6src[IPV6ADDLEN];

};

typedef struct field_values {
       list_t list_node;
       uint8_t* value;
}field_values_t;

typedef struct packet_fields{
       struct hmap_node hmap_node;
           uint32_t header;                  /* NXM_* value. */
           list_t fields;              /* List of field values (In one packet, there may be more than one value per field) */
}packet_fields_t;

#ifdef __cplusplus
extern "C"
#endif
int initialize_nb_engine();

#ifdef __cplusplus
extern "C"
#endif
int convertpkt_test(const unsigned char* pkt_in, struct packet_out * pkt_out);

#endif /* TEST_HPP_ */

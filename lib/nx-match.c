/*
 * Copyright (c) 2011 CPqD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "nx-match.h"

#include <netinet/icmp6.h>

#include "bj_hash.h"
#include "byte-order.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "packets.h"
#include "vlog.h"
#include "ofpbuf.h"
#include "flex-array.h"
#include "openflow/match-ext.h"

#define LOG_MODULE VLM_nx_match

/* Rate limit for nx_match parse errors.  These always indicate a bug in the
 * peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* For each NXM_* field, define NFI_NXM_* as consecutive integers starting from
 * zero. */
enum nxm_field_index {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPES, NW_PROTO) \
        NFI_NXM_##HEADER,
#include "nx-match.def"
    N_NXM_FIELDS
};

struct nxm_field {
    struct hmap_node hmap_node;
    enum nxm_field_index index;       /* NFI_* value. */
    uint32_t header;                  /* NXM_* value. */
    unsigned int wildcard;            /* FWW_* bit, if exactly one. */
    uint16_t dl_type[N_NXM_DL_TYPES]; /* dl_type prerequisites. */
    uint8_t nw_proto;                 /* nw_proto prerequisite, if nonzero. */
    const char *name;                 /* "NXM_*" string. */
};


/* All the known fields. */
static struct nxm_field nxm_fields[N_NXM_FIELDS] = {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPES, NW_PROTO)     \
    { HMAP_NODE_NULL_INITIALIZER, NFI_NXM_##HEADER, NXM_##HEADER, WILDCARD, \
        DL_CONVERT DL_TYPES, NW_PROTO, "NXM_" #HEADER},
#define DL_CONVERT(T1, T2) { CONSTANT_HTONS(T1), CONSTANT_HTONS(T2) }
#include "nx-match.def"
};

/* Hash table of 'nxm_fields'. */
static struct hmap all_nxm_fields = HMAP_INITIALIZER(&all_nxm_fields);

/* Possible masks for NXM_OF_ETH_DST_W. */
static const uint8_t eth_all_0s[ETH_ADDR_LEN]
    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t eth_all_1s[ETH_ADDR_LEN]
    = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t eth_mcast_1[ETH_ADDR_LEN]
    = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t eth_mcast_0[ETH_ADDR_LEN]
    = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff};

static void
nxm_init(void)
{
    if (hmap_is_empty(&all_nxm_fields)) {
        int i;

        for (i = 0; i < N_NXM_FIELDS; i++) {
            struct nxm_field *f = &nxm_fields[i];
            hmap_insert(&all_nxm_fields, &f->hmap_node,
                        hash_int(f->header, 0));
        }

        /* Verify that the header values are unique (duplicate "case" values
         * cause a compile error). */
        switch (0) {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPE, NW_PROTO)  \
        case NXM_##HEADER: break;
#include "nx-match.def"
        }
    }
}

static const struct nxm_field *
nxm_field_lookup(uint32_t header)
{
    struct nxm_field *f;

    nxm_init();

    HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(header, 0),
                             &all_nxm_fields) {
        if (f->header == header) {
            return f;
        }
    }

    return NULL;
}


int
nxm_field_bytes(uint32_t header)
{
    unsigned int length = NXM_LENGTH(header);
    return NXM_HASMASK(header) ? length / 2 : length;
}

/* Returns the width of the data for a field with the given 'header', in
 * bits. */
int
nxm_field_bits(uint32_t header)
{
    return nxm_field_bytes(header) * 8;
}

/* nx_pull_match() and helpers. */


uint32_t
ext_entry_ok(const void *p, unsigned int match_len)
{
    unsigned int payload_len;
    uint32_t header_be;
    uint32_t header;
    
    if (match_len < 4) {
        if (match_len) {
            VLOG_DBG(LOG_MODULE,"ext_match ends with partial ext_header");
        }
        return 0;
    }
    memcpy(&header_be, p, 4);
    header = ntohl(header_be);
    payload_len = NXM_LENGTH(header);
    if (!payload_len) {
        VLOG_DBG(LOG_MODULE, "ext_entry %08"PRIx32" has invalid payload "
                    "length 0", header);
        return 0;
    }
    if (match_len < payload_len + 4) {
        VLOG_DBG(LOG_MODULE, "%"PRIu32"-byte ext_entry but only "
                    "%u bytes left in nx_match", payload_len + 4, match_len);
        return 0;
    }

    return header;
}
/*
int 
ext_put_match(struct ext_match* match, struct flow* flow){

    if (!flow->flow_list == NULL)
        return 0;
    else
    
    ofpbuf *buffer = ;
        

    match->match_fields = (struct flex_array *) buffer->data;
    return match_len;

}*/

/* ext_put_match() and helpers.
 *
 * 'put' functions whose names end in 'w' add a wildcarded field.
 * 'put' functions whose names end in 'm' add a field that might be wildcarded.
 * Other 'put' functions add exact-match fields.
 */

void
ext_put_header(struct flex_array *f, uint32_t header)
{
    uint32_t n_header = htonl(header);
    flex_array_put(f, &n_header, sizeof n_header);
  
}

void
ext_put_8(struct flex_array *f, uint32_t header, uint8_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    f->total++;
}

void
ext_put_16(struct flex_array *f, uint32_t header, uint16_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
}

void
ext_put_16w(struct flex_array *f, uint32_t header, uint16_t value, uint16_t mask)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
}

void
ext_put_16m(struct flex_array *f, uint32_t header, uint16_t value, uint16_t mask)
{
    switch (mask) {
    case 0:
        break;

    case CONSTANT_HTONS(UINT16_MAX):
        ext_put_16(f, header, value);
        break;

    default:
        ext_put_16w(f, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

void
ext_put_32(struct flex_array *f, uint32_t header, uint32_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    uint8_t * x = f->entries;
    f->total++;
}

void
ext_put_32w(struct flex_array *f, uint32_t header, uint32_t value, uint32_t mask)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
}

void
nxm_put_32m(struct flex_array *f, uint32_t header, uint32_t value, uint32_t mask)
{
    switch (mask) {
    case 0:
        break;

    case CONSTANT_HTONL(UINT32_MAX):
        ext_put_32(f, header, value);
        break;

    default:
        ext_put_32w(f, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

void
ext_put_64(struct flex_array *f, uint32_t header, uint64_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
}

void
ext_put_64w(struct flex_array *f, uint32_t header, uint64_t value, uint64_t mask)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
}

void
ext_put_64m(struct flex_array *f, uint32_t header, uint64_t value, uint64_t mask)
{
    switch (mask) {
    case 0:
        break;

    case CONSTANT_HTONLL(UINT64_MAX):
        ext_put_64(f, header, value);
        break;

    default:
        ext_put_64w(f, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

void
ext_put_eth(struct flex_array *f, uint32_t header,
            const uint8_t value[ETH_ADDR_LEN])
{
    ext_put_header(f, header);
    flex_array_put(f, value, ETH_ADDR_LEN);
}

/*static void
ext_put_eth_dst(struct ofpbuf *b,
                uint32_t wc, const uint8_t value[ETH_ADDR_LEN])
{
    switch (wc & (FWW_DL_DST | FWW_ETH_MCAST)) {
    case FWW_DL_DST | FWW_ETH_MCAST:
        break;
    case FWW_DL_DST:
        nxm_put_header(b, NXM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, eth_mcast_1, ETH_ADDR_LEN);
        break;
    case FWW_ETH_MCAST:
        nxm_put_header(b, NXM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, eth_mcast_0, ETH_ADDR_LEN);
        break;
    case 0:
        nxm_put_eth(b, NXM_OF_ETH_DST, value);
        break;
    }
}

/*static void
nxm_put_ipv6(struct ofpbuf *b, uint32_t header,
             const struct in6_addr *value, const struct in6_addr *mask)
{
    if (ipv6_mask_is_any(mask)) {
        return;
    } else if (ipv6_mask_is_exact(mask)) {
        nxm_put_header(b, header);
        ofpbuf_put(b, value, sizeof *value);
    } else {
        nxm_put_header(b, NXM_MAKE_WILD_HEADER(header));
        ofpbuf_put(b, value, sizeof *value);
        ofpbuf_put(b, mask, sizeof *mask);
    }
}*/

/*
int 
ext_pull_match(struct ofpbuf *, unsigned int match_len, uint16_t priority){


}*/

static uint32_t
parse_nxm_field_name(const char *name, int name_len)
{
    const struct nxm_field *f;

    /* Check whether it's a field name. */
    for (f = nxm_fields; f < &nxm_fields[ARRAY_SIZE(nxm_fields)]; f++) {
        if (!strncmp(f->name, name, name_len) && f->name[name_len] == '\0') {
            return f->header;
        }
    }

    return 0;
}


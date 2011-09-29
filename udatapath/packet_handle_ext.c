#include "packet_handle_ext.h"
#include "match_ext.h"

/* Creates a handler */
struct packet_handle_ext *
packet_handle_ext_create(struct packet *pkt) {
	struct packet_handle_ext *handle = xmalloc(sizeof(struct packet_handle_ext));
	handle->pkt = pkt;
	hmap_init(&handle->fields);
	
	handle->valid = false;
	packet_handle_ext_validate(handle);

	return handle;
}

int
packet_handle_ext_validate(struct packet_handle_ext *handle) {

    int ret;
	if(handle->valid)
		return 0;

	ret = 0;
	ret = nbee_link_convertpkt(handle->pkt->buffer,&handle->fields);
    if (ret > -1)
        handle->valid = true;
	return ret;

}

bool
packet_handle_ext_match(struct packet_handle_ext *handle, struct flow_hmap *match){
    
    int val = packet_handle_ext_validate(handle);
    printf("VALIDE:?? %d\n", val);
    if (val < 0){ 
        printf("Don't Match \n");
        return false;
        
    }
    printf("VALIDEI\n");
    return packet_match(&handle->fields, &match->flow_fields);

}

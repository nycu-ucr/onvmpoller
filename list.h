#ifndef _LIST_H
#define _LIST_H

typedef struct list_node {
	void *go_channel_ptr;
	int pkt_type;
	struct list_node *next;
} list_node;

#endif


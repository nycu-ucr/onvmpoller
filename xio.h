#ifndef _XIO_H
#define _XIO_H
#include "onvm_nflib.h"

typedef struct list_node {
	void *go_channel_ptr;
	int pkt_type;
	struct list_node *next;
} list_node;

typedef enum socket_status {
    NEW_SOCKET,
    LISTENING,
    LISTENER_WAITING,
    WAITING_EST_ACK,
    EST_COMPLETE,
    READER_WAITING
} socket_status;

struct ipv4_4tuple
{
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
};

typedef struct Node
{
    void *data;
    struct Node *next;
} Node;

typedef struct Queue
{
    Node *front;
    Node *rear;
} Queue;

struct xio_socket
{
    socket_status status;
    int socket_type;

    int service_id;
    struct ipv4_4tuple fourTuple;

    struct Queue *socket_buf; /* Use for store pkts or connection-requests */

    void *go_channel_ptr;
    rte_rwlock_t *rwlock;
    rte_atomic16_t *rx_status; /* [0:ACTIVE] [1:CLOSE] */
    rte_atomic16_t *tx_status; /* [0:ACTIVE] [1:CLOSE] */
};

#endif


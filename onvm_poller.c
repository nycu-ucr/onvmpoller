#include "onvm_nflib.h"
#include "_cgo_export.h"
#include "string.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

// extern int XIO_wait(int, void *)

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx);
void get_monotonic_time(struct timespec *ts);
long get_time_nano(struct timespec *ts);
double get_elapsed_time_sec(struct timespec *before, struct timespec *after);
long get_elapsed_time_nano(struct timespec *before, struct timespec *after);

int xio_write(struct xio_socket *xs, uint8_t *buffer, int buffer_length);
int xio_read(struct xio_socket *xs, uint8_t *buffer, int buffer_length, int *return_value);
struct xio_socket *xio_connect(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *sem);
struct xio_socket *xio_accept(struct xio_socket *listener, char *sem);
struct xio_socket *xio_listen(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *complete_chan_ptr);

/*
********************************

            Define

********************************
*/

/* PKT TYPE */
#define HTTP_FRAME 0
#define ESTABLISH_CONN 1
#define CLOSE_CONN 2
#define REPLY_CONN 3
#define BIG_FRAME 4

/* const */
#define TCP_PROTO_NUM 0x06

/* dpdk config*/
#define MBUF_SIZE 4096

/* Socket type */
#define LISTENER_SOCKET 1
#define XIO_SOCKET 2

/* Socket status */
#define NEW_SOCKET 0
#define LISTENING 1
#define WAITING_EST_ACK 2
#define EST_COMPLETE 3
#define RX_CLOSED 4
#define TX_CLOSED 5
#define RX_TX_CLOSED 6
#define READER_WAITING 7
#define READER_HANDLING 8

/*
********************************

       Global variables

********************************
*/

uint16_t ETH_HDR_LEN = sizeof(struct rte_ether_hdr);
uint16_t IP_HDR_LEN = sizeof(struct rte_ipv4_hdr);
uint16_t TCP_HDR_LEN = sizeof(struct rte_tcp_hdr);

struct rte_mempool *pktmbuf_pool;
struct rte_hash *conn_tables;
struct rte_hash *IpToID;
struct onvm_nf_local_ctx *globalVar_nf_local_ctx;

/*
********************************

           Structures

********************************
*/

struct ipv4_4tuple
{
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
};

struct mbuf_list
{
    struct rte_mbuf *pkt;
    struct mbuf_list *next;
};

struct pkt_descriptor
{
    int payload_len;
    int start_offset;
    struct mbuf_list *pkt;
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

struct recieve_buf
{
    uint8_t *buf;
    int buf_len;
    int *return_value;
};

struct conn_request
{
    uint32_t ip;
    uint16_t port;
};

struct xio_socket
{
    int status;
    int socket_type;

    int service_id;
    struct ipv4_4tuple fourTuple;

    struct Queue *socket_buf; /* Use for store pkts or connection-requests */
    struct recieve_buf recieve_buf;

    char *go_channel_ptr;
    rte_rwlock_t *rwlock;
};

/*
********************************

           Functions

********************************
*/

static inline void print_socket(struct xio_socket *xs)
{
    if(xs == NULL){
        printf("[print_socket] Empty socket\n");
        return;
    }
    printf("xio_socket->status = %d\n", xs->status);
    printf("xio_socket->socket_type = %d\n", xs->socket_type);
    printf("xio_socket->service_id = %d\n", xs->service_id);
    printf("xio_socket->fourTuple.ip_src = %d\n", xs->fourTuple.ip_src);
    printf("xio_socket->fourTuple.port_src = %d\n", xs->fourTuple.port_src);
    printf("xio_socket->fourTuple.ip_dst = %d\n", xs->fourTuple.ip_dst);
    printf("xio_socket->fourTuple.port_dst = %d\n", xs->fourTuple.port_dst);
}

static inline void print_fourTuple(struct ipv4_4tuple *four_tuple)
{
    printf("IP_SRC:%d\nPORT_SRC:%d\nIP_DST:%d\nPORT_DST:%d\n", four_tuple->ip_src, four_tuple->port_src, four_tuple->ip_dst, four_tuple->port_dst);
}

/* define the hash function for the ipv4_4tuple key */
static inline uint32_t ipv4_4tuple_hash(const void *key, __rte_unused uint32_t key_len,
                                        __rte_unused uint32_t init_val)
{
    const struct ipv4_4tuple *tuple = (const struct ipv4_4tuple *)key;
    uint32_t hash = rte_jhash_3words(tuple->ip_dst, tuple->ip_src,
                                      ((uint32_t)tuple->port_dst << 16) | tuple->port_src, 0);
    return hash;
}

/* Simple functional fifo queue */
Queue *createQueue()
{
    Queue *queue = (Queue *)malloc(sizeof(Queue));
    queue->front = NULL;
    queue->rear = NULL;
    return queue;
}

static inline int isEmpty(Queue *queue)
{
    return queue->front == NULL;
}

static inline void enqueue(Queue *queue, void *data)
{
    // printf("Enqueue\n");

    Node *newNode = (Node *)malloc(sizeof(Node));
    newNode->data = data;
    newNode->next = NULL;
    if (isEmpty(queue))
    {
        queue->front = newNode;
        queue->rear = newNode;
    }
    else
    {
        queue->rear->next = newNode;
        queue->rear = newNode;
    }
}

static inline void *dequeue(Queue *queue)
{
    // printf("Dequeue\n");
    if (isEmpty(queue))
    {
        return NULL;
    }
    void *data = queue->front->data;
    Node *temp = queue->front;
    queue->front = queue->front->next;
    if (queue->front == NULL)
    {
        queue->rear = NULL;
    }
    free(temp);
    return data;
}

static inline void insert_IpToID(uint32_t ip, int id)
{
    printf("IP:%d, ID:%d\n", ip, id);
    int ret;
    uint32_t *ip_p = (uint32_t *)malloc(sizeof(uint32_t));
    int *id_p = (int *)malloc(sizeof(int));
    *ip_p = ip;
    *id_p = id;

    ret = rte_hash_add_key_data(IpToID, (void *)ip_p, (void *)id_p);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "[insert_IpToID] Unable to add to IpToID\n");
    }
}

// Return service_id or -1 if failed
static inline int convert_IpToID(uint32_t ip)
{
    int *service_id_ptr = NULL;

    int ret = rte_hash_lookup_data(IpToID, &ip, (void **)&service_id_ptr);
    if (ret < 0)
    {
        return -1;
    }

    int service_id = *service_id_ptr;

    return service_id;
}

static inline struct ipv4_4tuple swap_four_tuple(struct ipv4_4tuple four_tuple)
{
    struct ipv4_4tuple swap_4tuple = {
        .ip_dst = four_tuple.ip_src,
        .ip_src = four_tuple.ip_dst,
        .port_dst = four_tuple.port_src,
        .port_src = four_tuple.port_dst,
    };

    return swap_4tuple;
}

static inline struct mbuf_list *create_mbuf_list(struct rte_mbuf *pkt)
{
    struct mbuf_list *result = (struct mbuf_list *)malloc(sizeof(struct mbuf_list));
    struct mbuf_list *list_ptr = result;

    result->pkt = pkt;
    result->next = NULL;

    while (pkt->next != NULL)
    {
        // Move packet
        pkt = pkt->next;
        // Create an new list
        list_ptr->next = (struct mbuf_list *)malloc(sizeof(struct mbuf_list));
        // Move list
        list_ptr = list_ptr->next;
        // Store packet
        list_ptr->pkt = pkt;
    }

    return result;
}

void delete_mbuf_list(struct mbuf_list *list)
{
    struct mbuf_list *ptr = list;

    while (ptr != NULL)
    {
        struct mbuf_list *tmp = ptr->next;

        free(ptr);
        ptr = tmp->next;
    }

    return;
}

static inline int string_len(char *p)
{
    unsigned int count = 0;

    while (*p != '\0')
    {
        count++;
        p++;
    }

    return count;
}

static inline struct rte_tcp_hdr *
pkt_tcp_hdr(struct rte_mbuf *pkt)
{
    uint8_t *pkt_data =
        rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
    return (struct rte_tcp_hdr *)pkt_data;
}

void get_monotonic_time(struct timespec *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
}

long get_time_nano(struct timespec *ts)
{
    return (long)ts->tv_sec * 1e9 + ts->tv_nsec;
}

double get_elapsed_time_sec(struct timespec *before, struct timespec *after)
{
    double deltat_s = after->tv_sec - before->tv_sec;
    double deltat_ns = after->tv_nsec - before->tv_nsec;
    return deltat_s + deltat_ns * 1e-9;
}

long get_elapsed_time_nano(struct timespec *before, struct timespec *after)
{
    return get_time_nano(after) - get_time_nano(before);
}

int onvm_init(struct onvm_nf_local_ctx **nf_local_ctx, char *nfName)
{
    printf("[NF Name]: %s\n", nfName);
    const char *NF_TAG = nfName;
    int nfName_size = string_len(nfName);
    char nf_name[nfName_size];
    memcpy(nf_name, nfName, nfName_size);

    int arg_offset;
    struct onvm_nf_function_table *nf_function_table;

    // Initialize ONVM variables
    *nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(*nf_local_ctx, NULL);

    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;

    int argc = 3;
    char file_path[] = "/home/hstsai/onvm/NF_json/";
    int path_len = strlen(file_path);

    char cmd0[] = "./go.sh";
    char cmd1[] = "-F";
    char cmd2[path_len + nfName_size + 5];
    sprintf(cmd2, "%s%s.json", file_path, nf_name);
    char *argv[] = {cmd0, cmd1, cmd2};

    // Initialize ONVM
    arg_offset = onvm_nflib_init(argc, argv, NF_TAG, *nf_local_ctx, nf_function_table);
    if (arg_offset < 0)
    {
        onvm_nflib_stop(*nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION)
        {
            printf("Exiting due to user termination\n");
            return 0;
        }
        else
        {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL)
    {
        onvm_nflib_stop(*nf_local_ctx);
        rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }

    /* Create connection look-up table */
    char conn_table_name[nfName_size + 11];
    sprintf(conn_table_name, "conn_table_%s", nf_name);
    struct rte_hash_parameters xio_ipv4_hash_params = {
        .name = conn_table_name,
        .entries = 1024*1024*1,
        .key_len = sizeof(struct ipv4_4tuple),
        .hash_func = ipv4_4tuple_hash, // rte_hash_crc may be faster but the key need to be less related
        .hash_func_init_val = 0,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    conn_tables = rte_hash_create(&xio_ipv4_hash_params);
    if (conn_tables == NULL)
    {
        rte_exit(EXIT_FAILURE, "Unable to create the connection lookup table\n");
    }

    /* Create IP address to openNetVM's NFID */
    char IpToID_name[nfName_size + 7];
    sprintf(IpToID_name, "IpToID_%s", nf_name);
    struct rte_hash_parameters xio_IpToID_hash_params = {
        .name = IpToID_name,
        .entries = (uint32_t)256,
        .key_len = sizeof(uint32_t),
        .hash_func = DEFAULT_HASH_FUNC,
        .hash_func_init_val = 0,
    };
    IpToID = rte_hash_create(&xio_IpToID_hash_params);
    if (IpToID == NULL)
    {
        rte_exit(EXIT_FAILURE, "Unable to create the IpToID table\n");
    }

    // Parse the input lines and insert the key-value pairs into the hash table.
    FILE *fp = fopen("/home/hstsai/onvm/testbed/bin/ipid.txt", "r");
    char line[256];
    while (fgets(line, 256, fp) != NULL)
    {
        // Skip comment lines and empty lines.
        if (line[0] == '#' || line[0] == '\n')
        {
            continue;
        }

        // Parse the IP address and service ID from the input line.
        char *ip_str = strtok(line, ":");
        char *service_id_str = strtok(NULL, " ");

        // Convert the IP address string to a uint32_t.
        uint32_t ip_addr = inet_addr(ip_str);

        // Convert the service ID string to an integer.
        int service_id = atoi(service_id_str);

        // Insert the IP address and service ID into the hash table.
        insert_IpToID(ip_addr, service_id);
    }
    fclose(fp);

    /* Set the nf_local_ctx to global variable */
    globalVar_nf_local_ctx = *nf_local_ctx;

    return 0;
}

struct rte_mbuf *handle_payload(char *buffer, int buffer_length)
{
    struct rte_mbuf *pkt;
    pkt = rte_pktmbuf_alloc(pktmbuf_pool);
    if (pkt == NULL)
    {
        printf("Failed to allocate packets\n");
        return NULL;
    }
    else if (buffer_length == 0)
    {
        return pkt;
    }

    struct rte_mbuf *head = pkt;
    uint16_t mbuf_size = rte_pktmbuf_tailroom(head);
    // printf("pktmbuf tailroom: %d\n", mbuf_size);

    /* Set payload data */
    if (buffer_length <= mbuf_size)
    {
        uint8_t *head_mbuf;
        head_mbuf = (uint8_t *)rte_pktmbuf_append(pkt, buffer_length);
        if (head_mbuf == NULL)
        {
            printf("Failed to append payload. Consider splitting up the packet.\n");
            rte_pktmbuf_free(pkt);
            return NULL;
        }
        rte_memcpy(head_mbuf, buffer, buffer_length);
        // printf("[handle_payload][Small pkt][Copy: %d(bytes)]\n", buffer_length);
    }
    else
    {
        /* Calculate number of segmants */
        int quotient = (buffer_length / mbuf_size);
        int remainder = buffer_length % mbuf_size;
        // printf("Buffer length: %d\n", buffer_length);
        // printf("Quotient: %d\n", quotient);
        // printf("Remainder: %d\n", remainder);

        /* Full the first segmant*/
        uint8_t *head_mbuf = (uint8_t *)rte_pktmbuf_append(pkt, mbuf_size);
        if (head_mbuf == NULL)
        {
            printf("Failed to append payload. Consider splitting up the packet.\n");
            rte_pktmbuf_free(pkt);
            return NULL;
        }
        rte_memcpy(head_mbuf, buffer, mbuf_size);
        // printf("[handle_payload][Big pkt][Head][Copy: %d(bytes)]\n", mbuf_size);

        /* Full the complete segmants  */
        for (int i = 1; i < quotient; i++)
        {
            struct rte_mbuf *mb = rte_pktmbuf_alloc(pktmbuf_pool);
            if (mb == NULL)
            {
                printf("Failed to allocate packets\n");
                rte_pktmbuf_free(pkt);
                return NULL;
            }
            head->next = mb;
            head = head->next;

            uint8_t *mid_mbuf = (uint8_t *)rte_pktmbuf_append(pkt, mbuf_size);
            if (mid_mbuf == NULL)
            {
                printf("Failed to append payload. Consider splitting up the packet.\n");
                rte_pktmbuf_free(pkt);
                return NULL;
            }

            rte_memcpy(mid_mbuf, buffer + mbuf_size * i, mbuf_size);
            // printf("[handle_payload][Big pkt][Midd][Copy: %d(bytes)]\n", mbuf_size);
        }

        /* Full the remaind segmants */
        if (remainder != 0)
        {
            struct rte_mbuf *mb = rte_pktmbuf_alloc(pktmbuf_pool);
            if (mb == NULL)
            {
                printf("Failed to allocate packets\n");
                rte_pktmbuf_free(pkt);
                return NULL;
            }
            head->next = mb;
            head = head->next;

            uint8_t *tail_mbuf = (uint8_t *)rte_pktmbuf_append(pkt, remainder);
            if (tail_mbuf == NULL)
            {
                printf("Failed to append payload. Consider splitting up the packet.\n");
                rte_pktmbuf_free(pkt);
                return NULL;
            }

            rte_memcpy(tail_mbuf, buffer + mbuf_size * quotient, remainder);
            // printf("[handle_payload][Big pkt][Tail][Copy: %d(bytes)]\n", remainder);
        }
    }
    // printf("\033[0;31m[handle_payload][Pkt-size][Total: %d(bytes)]\033[0m\n", pkt->pkt_len);

    return pkt;
}

int onvm_send_pkt(struct onvm_nf_local_ctx *ctx, int service_id, int pkt_type,
                   uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                   char *buffer, int buffer_length)
{
    struct rte_mbuf *pkt;
    struct onvm_pkt_meta *pmeta;
    uint8_t *pkt_payload;
    struct rte_tcp_hdr *pkt_tcp_hdr;
    struct rte_ipv4_hdr *pkt_iph;
    struct rte_ether_hdr *pkt_eth_hdr;

    // struct timespec t_start;
    // struct timespec t_end;

    // get_monotonic_time(&t_start);
    // pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    // get_monotonic_time(&t_end);
    // printf("[ONVM] rte_mempool_lookup latency: %ld\n", get_elapsed_time_nano(&t_start, &t_end));

    switch (pkt_type)
    {
    case ESTABLISH_CONN:
        pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        break;
    case REPLY_CONN:
        pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        break;
    case CLOSE_CONN:
        pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        break;
    case HTTP_FRAME:
        pkt = handle_payload(buffer, buffer_length);
        break;
    default:
        printf("[onvm_send_pkt]Unknown pkt type: %d\n", pkt_type);
        break;
    }
    // get_monotonic_time(&t_start);
    // pkt = handle_payload(buffer, buffer_length);
    // get_monotonic_time(&t_end);
    // printf("[ONVM] handle_payload latency: %ld\n", get_elapsed_time_nano(&t_start, &t_end));
    if (pkt == NULL)
    {
        printf("Payload handling error\n");
        return -1;
    }

    // pkt->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
    // pkt->l2_len = ETH_HDR_LEN;
    // pkt->l3_len = IP_HDR_LEN;
    // printf("buffer size(give): %d\n", buffer_length);
    // struct rte_mbuf *m_last;
    // m_last = rte_pktmbuf_lastseg(pkt);
    // printf("pktmbuf tailroom: %d\n", rte_pktmbuf_tailroom(m_last));

    // if (buffer_length > 0)
    // {
    //     /* Set payload data */
    //     pkt_payload = (uint8_t *)rte_pktmbuf_append(pkt, buffer_length);
    //     if (pkt_payload == NULL)
    //     {
    //         printf("Failed to append payload. Consider splitting up the packet.\n");
    //         return;
    //     }
    //     rte_memcpy(pkt_payload, buffer, buffer_length);
    // }
    // printf("[onvm_send_pkt][pkt->data_off: %d][before]\n", pkt->data_off);
    // printf("[onvm_send_pkt][pkt->pkt_len: %d][before]\n", pkt->pkt_len);

    /* Set TCP header */
    // get_monotonic_time(&t_start);
    pkt_tcp_hdr = (struct rte_tcp_hdr *)rte_pktmbuf_prepend(pkt, TCP_HDR_LEN);
    // get_monotonic_time(&t_end);
    // printf("[ONVM] rte_pktmbuf_prepend latency: %ld\n", get_elapsed_time_nano(&t_start, &t_end));
    if (pkt_tcp_hdr == NULL)
    {
        printf("Failed to prepend TCP header. Consider splitting up the packet.\n");
        return -1;
    }
    pkt_tcp_hdr->src_port = src_port;
    pkt_tcp_hdr->dst_port = dst_port;
    switch (pkt_type)
    {
    case ESTABLISH_CONN:
        pkt_tcp_hdr->tcp_flags = RTE_TCP_SYN_FLAG;
        break;
    case REPLY_CONN:
        pkt_tcp_hdr->tcp_flags = RTE_TCP_ACK_FLAG;
        break;
    case CLOSE_CONN:
        pkt_tcp_hdr->tcp_flags = RTE_TCP_FIN_FLAG;
        break;
    case HTTP_FRAME:
        pkt_tcp_hdr->tcp_flags = RTE_TCP_PSH_FLAG;
        break;
    default:
        printf("[onvm_send_pkt]Unknown pkt type: %d\n", pkt_type);
        break;
    }
    // rte_memcpy(pkt_tcp_hdr, pkt_tcp_hdr, sizeof(TCP_HDR_LEN)); // + option_len);

    /* Set IP header */
    pkt_iph = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(pkt, IP_HDR_LEN);
    if (pkt_iph == NULL)
    {
        printf("Failed to prepend IP header. Consider splitting up the packet.\n");
        return -1;
    }
    pkt_iph->src_addr = src_ip;
    pkt_iph->dst_addr = dst_ip;
    pkt_iph->next_proto_id = TCP_PROTO_NUM;
    pkt_iph->version_ihl = IPV4_VERSION_IHL;
    // rte_memcpy(pkt_iph, pkt_iph, sizeof(IP_HDR_LEN));

    /* Set ethernet header */
    pkt_eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, ETH_HDR_LEN);
    if (pkt_eth_hdr == NULL)
    {
        printf("Failed to prepend ethernet header. Consider splitting up the packet.\n");
        return -1;
    }
    // rte_memcpy(pkt_eth_hdr, pkt_eth_hdr, sizeof(pkt_eth_hdr));

    pkt->pkt_len = pkt->data_len;
    // pkt_iph->total_length = rte_cpu_to_be_16(buffer_length + sizeof(struct rte_tcp_hdr) +
    //                                          sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr));
    // printf("Pkt len %d, total iph len %lu\n", pkt->pkt_len,
    //        buffer_length + sizeof(struct rte_tcp_hdr) +
    //            sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr));

    /* Handle checksuming */
    // onvm_pkt_set_checksums(pkt);

    // Fill out the meta data of the packet
    pmeta = onvm_get_pkt_meta(pkt);
    pmeta->destination = service_id;
    pmeta->action = ONVM_NF_ACTION_TONF;

    pkt->hash.rss = 0;
    pkt->port = 0;
    // pkt->data_len = buffer_length;
    // Copy the packet into the rte_mbuf data section
    // rte_memcpy(rte_pktmbuf_mtod(pkt, char *), buffer, buffer_length);

    // Send out the generated packet
    // printf("[onvm_send_pkt][pkt->data_off: %d][After]\n", pkt->data_off);
    // printf("[onvm_send_pkt][pkt->pkt_len: %d][After]\n", pkt->pkt_len);
    return onvm_nflib_return_pkt(ctx->nf, pkt);

    // printf("onvm_send_pkt() send packet to NF: %d\n", service_id);
}

static inline int calculate_payload_len(struct rte_mbuf *pkt)
{
    int payload_len = rte_pktmbuf_data_len(pkt) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    pkt = pkt->next;

    while (pkt != NULL)
    {
        payload_len = payload_len + pkt->data_len;
        pkt = pkt->next;
    }

    // printf("\033[0;31m[calculate_payload_len][Total: %d(bytes)]\033[0m\n", payload_len);
    return payload_len;
}

static inline int calculate_offset(int empty_space, int mbuf_data_len, int mbuf_cap)
{
    if (empty_space >= mbuf_data_len)
    {
        return mbuf_data_len;
    }
    else
    {
        return empty_space;
    }
}

static inline int copy(uint8_t *dst_ptr, uint8_t *src_ptr, int copy_len)
{
    rte_memcpy(dst_ptr, src_ptr, copy_len);
    return copy_len;
}

int handle_assemble(uint8_t *buffer_ptr, int buff_cap, struct mbuf_list *pkt_list, int start_offset)
{
    struct rte_mbuf *pkt = pkt_list->pkt;
    struct rte_mbuf *head = pkt;               // Restore the pointer
    struct mbuf_list *tmp_pkt_list = pkt_list; // For move pointer

    pkt->next = NULL;
    // Rebuild packet
    while (tmp_pkt_list->next != NULL)
    {
        // Move pakcet list
        tmp_pkt_list = tmp_pkt_list->next;
        // Store packet
        pkt->next = tmp_pkt_list->pkt;
        // Move packet
        pkt = pkt->next;
    }
    pkt = head;

#if 0
    // Debug mbuf list
    struct mbuf_list *tmp;
    tmp = pkt_list;
    printf("payload_assemble show mbuf list\n");
    while (tmp != NULL) {
        printf("%p (%p) -> ", tmp, tmp_pkt_list->pkt);
        tmp = tmp_pkt_list->next;
    }
    printf("\n");
#endif

    int remaining_pkt_len = calculate_payload_len(pkt) - start_offset;
    int end_offset = start_offset;

    // Calc already read part, the current position of payload pointer
    uint16_t c_q = start_offset / MBUF_SIZE;
    uint16_t c_r = start_offset % MBUF_SIZE;

    if (c_q == 0 && c_r == 0 && remaining_pkt_len <= buff_cap && remaining_pkt_len <= MBUF_SIZE)
    {
        // Shortcut
        uint8_t *payload_ptr = rte_pktmbuf_mtod(pkt, uint8_t *) + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
        rte_memcpy(buffer_ptr, payload_ptr, remaining_pkt_len);
        end_offset += remaining_pkt_len;
        // printf("[handle_assemble] (shortcut): read %d bytes data\n", end_offset - start_offset);
        return end_offset;
    }

    struct rte_mbuf *c_pkt = pkt;
    for (uint16_t x = 0; x < c_q; ++x)
    {
        c_pkt = c_pkt->next;
    }

    // Calc the payload pointer
    uint8_t *payload_ptr;
    if (c_q == 0)
    {
        // First segment has header
        payload_ptr = rte_pktmbuf_mtod(c_pkt, uint8_t *) + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    }
    else
    {
        payload_ptr = rte_pktmbuf_mtod(c_pkt, uint8_t *);
    }
    payload_ptr += c_r;

    if (remaining_pkt_len <= buff_cap)
    {
        // It is able to read all packet into buffer

        // Calc remaining need read part
        uint16_t need_r1 = (remaining_pkt_len > MBUF_SIZE) ? MBUF_SIZE - c_r : remaining_pkt_len; // The remaining part of the current segment
        uint16_t need_q = (remaining_pkt_len - need_r1) / MBUF_SIZE;
        uint16_t need_r2 = remaining_pkt_len - need_r1 - (need_q * MBUF_SIZE); // The remaining part of the last segment

        if ((need_r1 + need_q * MBUF_SIZE + need_r2) != remaining_pkt_len)
        {
            printf("Error: size mismatch %d != %d\n", need_r1 + need_q * MBUF_SIZE + need_r2, remaining_pkt_len);
        }

        int n = 0;
        // Read the first part
        n = copy(buffer_ptr, payload_ptr, need_r1);
        buffer_ptr += n;
        end_offset += n;
        c_pkt = c_pkt->next; // Move to next segment

        // Read the second part
        if (need_q != 0)
        {
            for (int x = 0; x < need_q; ++x)
            {
                payload_ptr = rte_pktmbuf_mtod(c_pkt, uint8_t *);
                n = copy(buffer_ptr, payload_ptr, MBUF_SIZE);
                buffer_ptr += n;
                end_offset += n;

                c_pkt = c_pkt->next;
            }
        }

        // Read the third part
        if (need_r2 != 0)
        {
            payload_ptr = rte_pktmbuf_mtod(c_pkt, uint8_t *);
            n = copy(buffer_ptr, payload_ptr, need_r2);
            buffer_ptr += n;
            end_offset += n;
        }

        // printf("[handle_assemble] (Case 1): read %d bytes data\n", end_offset - start_offset);
        return end_offset;
    }
    else
    {
        // It can not read all packet into buffer, only read buff_cap

        int n = 0;
        int original_buff_cap = buff_cap;

        // Read the first part
        uint16_t need_r1 = (remaining_pkt_len > MBUF_SIZE) ? MBUF_SIZE - c_r : remaining_pkt_len; // The remaining part of the current segment
        if (need_r1 > buff_cap)
        {
            n = copy(buffer_ptr, payload_ptr, buff_cap);
            end_offset += n;

            // printf("[handle_assemble] (Case 2-1-1): read %d bytes data\n", end_offset - start_offset);
            return end_offset;
        }
        else
        {
            n = copy(buffer_ptr, payload_ptr, need_r1);
            buffer_ptr += n;
            end_offset += n;
            buff_cap -= n;
        }
        c_pkt = c_pkt->next; // Move to next segment

        if (buff_cap == 0)
        {
            // printf("[handle_assemble] (Case 2-1-2): read %d bytes data\n", end_offset - start_offset);
            return end_offset;
        }
        else if (buff_cap < 0)
        {
            // This is error
            printf("Error: the capacity of buffer is %d\n", buff_cap);
        }

        // Challenge 2: Read the second part
        uint16_t need_q = buff_cap / MBUF_SIZE;

        if (need_q != 0)
        {
            for (int x = 0; x < need_q; ++x)
            {
                payload_ptr = rte_pktmbuf_mtod(c_pkt, uint8_t *);
                n = copy(buffer_ptr, payload_ptr, MBUF_SIZE);
                buffer_ptr += n;
                end_offset += n;
                buff_cap -= n;

                c_pkt = c_pkt->next;
            }
        }

        // Challenge 3: Read the third part
        if (buff_cap != 0)
        {
            n = copy(buffer_ptr, payload_ptr, buff_cap);
            end_offset += n;
        }

        // printf("[handle_assemble] (Case 2): read %d bytes data\n", end_offset - start_offset);
        return end_offset;
    }
}

// int payload_assemble(uint8_t *buffer_ptr, int buff_cap, struct rte_mbuf *pkt, int start_offset)
int payload_assemble(uint8_t *buffer_ptr, int buff_cap, struct mbuf_list *pkt_list, int start_offset)
{
    // printf("[payload_assemble] Start\n");
    int end_offset = 0;

    // struct timespec t_start;
    // struct timespec t_end;

    // get_monotonic_time(&t_start);
    end_offset = handle_assemble(buffer_ptr, buff_cap, pkt_list, start_offset);
    // get_monotonic_time(&t_end);
    // printf("[ONVM] handle_assemble latency: %ld\n", get_elapsed_time_nano(&t_start, &t_end));
    // get_monotonic_time(&t_start);
    // rte_pktmbuf_free(pkt_list->pkt);
    // get_monotonic_time(&t_end);
    // printf("[ONVM] rte_pktmbuf_free latency: %ld\n", get_elapsed_time_nano(&t_start, &t_end));

    // printf("[payload_assemble] End\n");
    return end_offset;
}

static inline int handle_ESTABLISH_CONN(struct ipv4_4tuple *four_tuple, struct rte_mbuf *pkt)
{
    // printf("[handle_ESTABLISH_CONN] Recieve pkt\n");
    // print_fourTuple(four_tuple);

    struct ipv4_4tuple ft = {
        .ip_dst = four_tuple->ip_dst,
        .ip_src = 0,
        .port_dst = four_tuple->port_dst,
        .port_src = 0,
    };
    struct conn_request *req = (struct conn_request *)malloc(sizeof(struct conn_request));
    req->ip = four_tuple->ip_src;
    req->port = four_tuple->port_src;

    struct xio_socket *listener;
    int ret;
    ret = rte_hash_lookup_data(conn_tables, (void *)&ft, (void **)&listener);
    if (ret < 0) {
        printf("[handle_ESTABLISH_CONN] Failed to retrieve value from conn_tables\n");
        return -1;
    }else{
        // print_socket(listener);
    }

    if (listener->socket_type != LISTENER_SOCKET)
    {
        printf("ESTABLISH_CONN pkt look-up result is not LISTENER_SOCKET");
        return -1;
    }

    rte_rwlock_write_lock(listener->rwlock);
    enqueue(listener->socket_buf, req);
    rte_rwlock_write_unlock(listener->rwlock);

    int res_code;
    res_code = XIO_wait(ESTABLISH_CONN, listener->go_channel_ptr);

    return res_code;
}

static inline int handle_REPLY_CONN(struct ipv4_4tuple *four_tuple, struct rte_mbuf *pkt)
{
    // printf("[handle_REPLY_CONN] Recieve pkt\n");
    // print_fourTuple(four_tuple);

    int ret;
    struct xio_socket *xs;
    ret = rte_hash_lookup_data(conn_tables, four_tuple, (void **)&xs);
    if (ret < 0) {
        printf("[handle_REPLY_CONN] Failed to retrieve value from conn_tables\n");
        return -1;
    }

    rte_rwlock_write_lock(xs->rwlock);
    if(xs->status != WAITING_EST_ACK){
        printf("[handle_REPLY_CONN] Socket status != WAITING_EST_ACK, but recieve REPLY_CONN pkt");
    }else{
        xs->status == EST_COMPLETE;
    }
    rte_rwlock_write_unlock(xs->rwlock);

    int res_code;
    res_code = XIO_wait(REPLY_CONN, xs->go_channel_ptr);
}

static inline int handle_CLOSE_CONN(struct ipv4_4tuple *four_tuple, struct rte_mbuf *pkt)
{
    // printf("[handle_CLOSE_CONN] Recieve pkt\n");
    // print_fourTuple(four_tuple);

    int ret;
    struct xio_socket *xs;
    ret = rte_hash_lookup_data(conn_tables, four_tuple, (void **)&xs);
    if (ret < 0) {
        printf("[handle_CLOSE_CONN] Failed to retrieve value from conn_tables\n");
        return -1;
    }

    /* TODO XIO socket close */

    int res_code;
    res_code = XIO_wait(CLOSE_CONN, xs->go_channel_ptr);
}

static inline int handle_HTTP_FRAME(struct ipv4_4tuple *four_tuple, struct rte_mbuf *pkt)
{
    // printf("[handle_HTTP_FRAME] Recieve pkt\n");
    // print_fourTuple(four_tuple);

    int res_code;
    struct mbuf_list *mbuf_list;
    mbuf_list = create_mbuf_list(pkt);

    int payload_len = 0;
    uint8_t *payload;
    if (pkt->next == NULL)
    {
        payload_len = rte_pktmbuf_data_len(pkt) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        payload = rte_pktmbuf_mtod(pkt, uint8_t *) + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    }
    else
    {
        payload_len = calculate_payload_len(pkt);
    }

    int ret;
    struct xio_socket *xs;
    ret = rte_hash_lookup_data(conn_tables, four_tuple, (void **)&xs);
    if (ret < 0) {
        printf("[handle_HTTP_FRAME] Failed to retrieve value from conn_tables\n");
        return -1;
    }

    struct pkt_descriptor *des = (struct pkt_descriptor *)malloc(sizeof(struct pkt_descriptor));
    des->payload_len = payload_len;
    des->start_offset = 0;
    des->pkt = mbuf_list;

    rte_rwlock_write_lock(xs->rwlock);
    enqueue(xs->socket_buf, des);
    if (xs->status == READER_WAITING)
    {
        // printf("[handle_HTTP_FRAME] READER_WAITING\n");
        uint8_t *buf = xs->recieve_buf.buf;
        int buf_len = xs->recieve_buf.buf_len;

        /* Reset status */
        xs->status = READER_HANDLING;
        rte_rwlock_write_unlock(xs->rwlock);

        int read_res = xio_read(xs, buf, buf_len, NULL);
        /* [TODO] handle different read_res */
        res_code = XIO_wait(HTTP_FRAME, xs->go_channel_ptr);
    } else if (xs->status == EST_COMPLETE)
    {
        // printf("[handle_HTTP_FRAME] EST_COMPLETE\n");
        rte_rwlock_write_unlock(xs->rwlock);
    } else
    {
        // printf("[handle_HTTP_FRAME] ELSE_STATUS\n");
        rte_rwlock_write_unlock(xs->rwlock);
        /* [TODO] handle different socket status */
    }

    return res_code;
}

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *ctx)
{
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ether_hdr *eth_hdr;

    // struct timespec t_start;
    // struct timespec t_end;
    // printf("[packet_handler]\n");

    meta->action = ONVM_NF_ACTION_DROP;

    // eth_hdr = onvm_pkt_ether_hdr(pkt);
    // if (eth_hdr == NULL)
    // {
    //     printf("Error packet is not Ethernet packet\n");
    //     return -1;
    // }

    // get_monotonic_time(&t_start);
    ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
    // get_monotonic_time(&t_end);
    // printf("[ONVM] onvm_pkt_ipv4_hdr latency: %ld\n", get_elapsed_time_nano(&t_start, &t_end));
    if (ipv4_hdr == NULL)
    {
        // printf("Error packet is not IP packet\n");
        return -1;
    }

    if (ipv4_hdr->next_proto_id != IP_PROTOCOL_TCP)
    {
        // printf("Error packet is not TCP packet\n");
        return -1;
    }

    tcp_hdr = pkt_tcp_hdr(pkt);
    struct ipv4_4tuple four_tuple = {
        .ip_dst = ipv4_hdr->dst_addr,
        .ip_src = ipv4_hdr->src_addr,
        .port_dst = tcp_hdr->dst_port,
        .port_src = tcp_hdr->src_port,
    };

    int res_code;
    /* Check the packet type */
    switch (tcp_hdr->tcp_flags)
    {
    case RTE_TCP_SYN_FLAG:
        /* ESTABLISH_CONN */
        res_code = handle_ESTABLISH_CONN(&four_tuple, pkt);
        break;
    case RTE_TCP_ACK_FLAG:
        /* REPLY_CONN */
        res_code = handle_REPLY_CONN(&four_tuple, pkt);
        break;
    case RTE_TCP_FIN_FLAG:
        /* CLOSE_CONN */
        res_code = handle_CLOSE_CONN(&four_tuple, pkt);
        break;
    case RTE_TCP_PSH_FLAG:
        /* HTTP_FRAME */
        res_code = handle_HTTP_FRAME(&four_tuple, pkt);
        break;
    }

    return res_code;
}

void test_cgo(char *ptr)
{
    char *tmp = (char *)malloc(sizeof(char) * 8);
    strncpy(tmp, ptr, 8);
    free(tmp);
    return;
}

char *conditon_var;

/* Test wake-up latency by using golang condition var */
void test_CondVarPut(char *condVarPtr)
{
    conditon_var = condVarPtr;
    // printf("[test_CondVarPut] Successful assign golang cond_var into clang global var\n");

    return;
}

void *test_CondVarGet()
{
    // printf("[test_CondVarGet] Start to get golang cond_var from clang global var\n");
    return conditon_var;
}

struct xio_socket *xio_new_socket(int socket_type, int service_id, struct ipv4_4tuple four_tuple, char *sem)
{
    // printf("[xio_new_socket] Start create type-%d socket\n", socket_type);
    struct xio_socket *xs = (struct xio_socket *)malloc(sizeof(struct xio_socket));

    xs->status = NEW_SOCKET;
    xs->socket_type = socket_type;

    xs->service_id = service_id;
    xs->fourTuple = four_tuple;

    xs->socket_buf = createQueue();
    xs->recieve_buf.buf = NULL;
    xs->recieve_buf.buf_len = 0;

    xs->go_channel_ptr = sem;
    xs->rwlock = (rte_rwlock_t *)malloc(sizeof(rte_rwlock_t));

    /* Init rwlock */
    rte_rwlock_init(xs->rwlock);

    // print_socket(xs);
    /* populate into table*/
    int ret;
    struct ipv4_4tuple key = swap_four_tuple(four_tuple);
    /*
       Q: Why key need to be swaped when insert to table?
       A: The incoming pkt don't need to be swaped to look-up socket.
    */
    ret = rte_hash_add_key_data(conn_tables, (void *)&key, (void *)xs);
    if (ret < 0)
    {
        printf("[xio_new_socket] Unable to add to conn_tables\n");
    }

    return xs;
}

int xio_write(struct xio_socket *xs, uint8_t *buffer, int buffer_length)
{
    int ret;
    ret = onvm_send_pkt(globalVar_nf_local_ctx, xs->service_id, HTTP_FRAME,
                  xs->fourTuple.ip_src, xs->fourTuple.port_src, xs->fourTuple.ip_dst, xs->fourTuple.port_dst,
                  (char *)buffer, buffer_length);

    if(ret < 0){
        printf("[xio_write] onvm_send_pkt not success\n");
        return -1;
    }

    return buffer_length;
}

/*
   [Input]
   return_value: used to get the newest return value in async case
   [Return]
   >0: read size
    0: no pkt in socket buffer
   -1: EOF
*/
int xio_read(struct xio_socket *xs, uint8_t *buffer, int buffer_length, int *return_value)
{
    // printf("[xio_read] Start read\n");
    int ret = 0;

    struct pkt_descriptor *pkt_desc = NULL;

    rte_rwlock_read_lock(xs->rwlock);
    if(!isEmpty(xs->socket_buf))
    {
        pkt_desc = (struct pkt_descriptor *)xs->socket_buf->front->data;
    }
    rte_rwlock_read_unlock(xs->rwlock);

    if (pkt_desc != NULL)
    {
        // printf("[xio_read] exist pkt\n");
        /*
           Already have pkt descriptor in socket's buffer
           so we can directly call payload_assemble
        */
        int end_offset = payload_assemble(buffer, buffer_length, pkt_desc->pkt, pkt_desc->start_offset);

        rte_rwlock_write_lock(xs->rwlock);
        ret = end_offset - pkt_desc->start_offset;

        if (xs->status == READER_HANDLING){
            /* Exist return_value need to be handle for asyc case */
            // unsigned char bytes[4];
            // bytes[0] = (ret >> 24) & 0xFF;
            // bytes[1] = (ret >> 16) & 0xFF;
            // bytes[2] = (ret >> 8) & 0xFF;
            // bytes[3] = (ret >> 0) & 0xFF;
            // printf("Before return_value used\n");
            // rte_memcpy(xs->recieve_buf.return_value, bytes, 4);
            // printf("After return_value used\n");
            *xs->recieve_buf.return_value = ret;

            /* Async read complete */
            xs->status = ESTABLISH_CONN;
            xs->recieve_buf.buf = NULL;
            xs->recieve_buf.buf_len = 0;
            xs->recieve_buf.return_value = NULL;
        }

        if (end_offset == pkt_desc->payload_len)
        {
            struct pkt_descriptor *tmp = (struct pkt_descriptor *)dequeue(xs->socket_buf);
            rte_rwlock_write_unlock(xs->rwlock);
            if (tmp != pkt_desc)
            {
                printf("[Delete pkt] dequeue() != queue->front->data");
            }

            //delete_mbuf_list(tmp->pkt);
            free(tmp);
        }
        else
        {
            pkt_desc->start_offset = end_offset;
            rte_rwlock_write_unlock(xs->rwlock);
        }
    }
    else
    {
        // printf("[xio_read] non-exist pkt\n");
        /* No pkt in socket's buffer
           so we have to hook up a recieve buffer
           and change the socket's status
        */
        rte_rwlock_write_lock(xs->rwlock);
        xs->recieve_buf.buf = buffer;
        xs->recieve_buf.buf_len = buffer_length;
        xs->recieve_buf.return_value = return_value;
        xs->status = READER_WAITING;
        rte_rwlock_write_unlock(xs->rwlock);

        ret = 0;
    }

    return ret;
}

struct xio_socket *xio_connect(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *sem)
{
    // printf("[xio_connect] Start xio_connect\n");

    struct ipv4_4tuple four_tuple = {
        .ip_src = ip_src,
        .port_src = port_src,
        .ip_dst = ip_dst,
        .port_dst = port_dst,
    };

    /* Check whether the ip-address is valid */
    int service_id = 0;
    service_id = convert_IpToID(four_tuple.ip_dst);
    if (service_id < 0)
    {
        // printf("[xio_connect] Unable to convert IpToID\n");
        return NULL;
    }

    /* Create new XIO socket structure */
    struct xio_socket *xs = xio_new_socket(XIO_SOCKET, service_id, four_tuple, sem);

    /* Send ESTABLISH control message */
    onvm_send_pkt(globalVar_nf_local_ctx, xs->service_id, ESTABLISH_CONN,
                  xs->fourTuple.ip_src, xs->fourTuple.port_src, xs->fourTuple.ip_dst, xs->fourTuple.port_dst,
                  NULL, 0);

    /* Set socket status to waiting ESTABLISH_ACK */
    rte_rwlock_write_lock(xs->rwlock);
    if (xs != NULL)
    {
        xs->status = WAITING_EST_ACK;
    }
    rte_rwlock_write_unlock(xs->rwlock);

    return xs;
}

struct xio_socket *xio_accept(struct xio_socket *listener, char *sem)
{
    // printf("[xio_accept] Start xio_accept\n");

    /* Check if the listener socket's buffer exist ESTABLISH_CONN request */
    struct conn_request *req;
    rte_rwlock_write_lock(listener->rwlock);
    req = (struct conn_request *)dequeue(listener->socket_buf);
    rte_rwlock_write_unlock(listener->rwlock);

    if (req == NULL)
    {
        /* Do not ESTABLISH_CONN exist */
        return NULL;
    }

    /* Exist ESTABLISH_CONN request socket's buffer in need to be handled */
    /* Check whether the ip-address is valid */
    int service_id = 0;
    service_id = convert_IpToID(req->ip);
    if (service_id < 0)
    {
        printf("[xio_accept] Unable to convert IpToID\n");
        return NULL;
    }

    struct ipv4_4tuple four_tuple = {
        .ip_dst = req->ip,
        .ip_src = listener->fourTuple.ip_src,
        .port_dst = req->port,
        .port_src = listener->fourTuple.port_src,
    };
    struct xio_socket *xs = xio_new_socket(XIO_SOCKET, service_id, four_tuple, sem);

    /* Send ESTABLISH_ACK control message */
    onvm_send_pkt(globalVar_nf_local_ctx, xs->service_id, REPLY_CONN,
                  xs->fourTuple.ip_src, xs->fourTuple.port_src, xs->fourTuple.ip_dst, xs->fourTuple.port_dst,
                  NULL, 0);

    rte_rwlock_write_lock(xs->rwlock);
    xs->status = EST_COMPLETE;
    rte_rwlock_write_unlock(xs->rwlock);

    return xs;
}

struct xio_socket *xio_listen(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *complete_chan_ptr)
{
    // printf("[xio_listen] Listen on %d:%d\n", ip_src, port_src);

    struct ipv4_4tuple four_tuple = {
        .ip_src = ip_src,
        .port_src = port_src,
        .ip_dst = ip_dst,
        .port_dst = port_dst,
    };

    /* Check whether the ip-address is valid */
    int service_id = 0;
    service_id = convert_IpToID(four_tuple.ip_src);
    if (service_id < 0)
    {
        printf("[xio_listen] Unable to convert IP:%d to ID\n", four_tuple.ip_src);
        return NULL;
    }

    struct xio_socket *xs = xio_new_socket(LISTENER_SOCKET, service_id, four_tuple, complete_chan_ptr);

    rte_rwlock_write_lock(xs->rwlock);
    if (xs != NULL)
    {
        xs->status = LISTENING;
    }
    rte_rwlock_write_unlock(xs->rwlock);

    return xs;
}
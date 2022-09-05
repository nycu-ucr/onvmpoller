#include "onvm_nflib.h"
#include "_cgo_export.h"
#include "string.h"

// extern int DeliverPacket(int, char *, int, uint32, uint16, uint32, uint16)

#define HTTP_FRAME      0
#define ESTABLISH_CONN  1
#define CLOSE_CONN      2
#define REPLY_CONN      3
#define TCP_PROTO_NUM   0x06

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx);

struct four_tuple
{
    rte_be32_t src_addr; /**< source address */
    rte_be16_t src_port; /**< TCP source port. */
    rte_be32_t dst_addr; /**< destination address */
    rte_be16_t dst_port; /**< TCP destination port. */
};

struct four_tuple_str
{
    char *tuples[4];
};

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

static inline void parseFourTuple(char *four_tuple)
{
    char *token = strtok(four_tuple, ",");

    while (token != NULL)
    {
        // printf("%s\n", token);
        token = strtok(NULL, ",");
    }
}

static inline struct four_tuple *EncodeFourTuple(char *four_tuple)
{
    struct four_tuple *result;
    return result;
}

int onvm_init(struct onvm_nf_local_ctx **nf_local_ctx, char *nfName)
{
    printf("[NF Name]: %s\n", nfName);
    const char *NF_TAG = nfName;
    int nfName_size = string_len(nfName);
    char nf_name[nfName_size];
    memcpy(nf_name, nfName, sizeof(nfName));

    int arg_offset;
    struct onvm_nf_function_table *nf_function_table;

    // Initialize ONVM variables
    *nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(*nf_local_ctx, NULL);

    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;

    int argc = 3;
    char file_path[] = "/home/hstsai/onvm/";
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

    return 0;
}

void onvm_send_pkt(struct onvm_nf_local_ctx *ctx, int service_id, int pkt_type,
                   uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                   char *buffer, int buffer_length)
{
    struct rte_mbuf *pkt;
    struct onvm_pkt_meta *pmeta;
    struct rte_mempool *pktmbuf_pool;

    // printf("[pkt_type]: %d\n", pkt_type);

    pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL)
    {
        onvm_nflib_stop(ctx);
        rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }

    // pkt = rte_pktmbuf_alloc(pktmbuf_pool);
    // if (pkt == NULL)
    // {
    //     printf("Failed to allocate packets\n");
    //     return;
    // }

    struct rte_tcp_hdr   tcp_hdr;
    struct rte_ipv4_hdr  ipv4_hdr;
    struct rte_ether_hdr eth_hdr; 

    /* Fill out TCP header */
    tcp_hdr.src_port = src_port;
    tcp_hdr.dst_port = dst_port;
    switch (pkt_type)
    {
    case ESTABLISH_CONN:
        tcp_hdr.tcp_flags = RTE_TCP_SYN_FLAG;
        break;
    case REPLY_CONN:
        tcp_hdr.tcp_flags = RTE_TCP_ACK_FLAG;
        break;
    case CLOSE_CONN:
        tcp_hdr.tcp_flags = RTE_TCP_FIN_FLAG;
        break;
    default:
        break;
    }
    
    /* Fill out IP header */
    onvm_pkt_fill_ipv4(&ipv4_hdr, src_ip, dst_ip, TCP_PROTO_NUM);
    
    /* Fill out Ethernet header */
    onvm_get_fake_macaddr(&eth_hdr.s_addr);
    onvm_get_fake_macaddr(&eth_hdr.d_addr);
    eth_hdr.ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);

    /* Generate packet */
    pkt = onvm_pkt_generate_tcp(pktmbuf_pool, &tcp_hdr, &ipv4_hdr, &eth_hdr, NULL, 0, buffer, buffer_length);

    // Fill out the meta data of the packet
    pmeta = onvm_get_pkt_meta(pkt);
    pmeta->destination = service_id;
    pmeta->action = ONVM_NF_ACTION_TONF;

    pkt->hash.rss = 0;
    pkt->port = 0;
    pkt->data_len = buffer_length;
 
    // Copy the packet into the rte_mbuf data section
    // rte_memcpy(rte_pktmbuf_mtod(pkt, char *), buffer, buffer_length);

    // Send out the generated packet
    onvm_nflib_return_pkt(ctx->nf, pkt);

    // printf("onvm_send_pkt() send packet to NF: %d\n", service_id);
}

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
    struct rte_tcp_hdr   *tcp_hdr;
    struct rte_ipv4_hdr  *ipv4_hdr;
    struct rte_ether_hdr *eth_hdr;
    uint8_t *payload;
    int payload_len, pkt_type;

	meta->action = ONVM_NF_ACTION_DROP;

    eth_hdr = onvm_pkt_ether_hdr(pkt);
    if(eth_hdr == NULL) {
        printf("Error packet is not Ethernet packet\n");
        return -1;
    }

    ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
    if(ipv4_hdr == NULL) {
        printf("Error packet is not IP packet\n");
        return -1;
    }

    tcp_hdr = onvm_pkt_tcp_hdr(pkt);
    if(tcp_hdr == NULL) {
        printf("Error packet is not TCP packet\n");
        return -1;
    }

    payload = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
    payload_len = rte_pktmbuf_data_len(pkt) - (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));

    switch (tcp_hdr->tcp_flags)
    {
    case RTE_TCP_SYN_FLAG:
        pkt_type = ESTABLISH_CONN;
        break;
    case RTE_TCP_ACK_FLAG:
        pkt_type = REPLY_CONN;
        break;
    case RTE_TCP_FIN_FLAG:
        pkt_type = CLOSE_CONN;
        break;
    default:
        pkt_type = HTTP_FRAME;
        break;
    }

    DeliverPacket(pkt_type, payload, payload_len, ipv4_hdr->src_addr, tcp_hdr->src_port, ipv4_hdr->dst_addr, tcp_hdr->dst_port);

    return 0;
}
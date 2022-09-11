#include "onvm_nflib.h"
#include "_cgo_export.h"
#include "string.h"

// extern int DeliverPacket(int, char *, int, uint32, uint16, uint32, uint16)

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx);

#define HTTP_FRAME 0
#define ESTABLISH_CONN 1
#define CLOSE_CONN 2
#define REPLY_CONN 3
#define TCP_PROTO_NUM 0x06

uint16_t ETH_HDR_LEN = sizeof(struct rte_ether_hdr);
uint16_t IP_HDR_LEN = sizeof(struct rte_ipv4_hdr);
uint16_t TCP_HDR_LEN = sizeof(struct rte_tcp_hdr);

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

static inline struct rte_tcp_hdr *
pkt_tcp_hdr(struct rte_mbuf *pkt)
{
    uint8_t *pkt_data =
        rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
    return (struct rte_tcp_hdr *)pkt_data;
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
    uint8_t *pkt_payload;
    struct rte_tcp_hdr *pkt_tcp_hdr;
    struct rte_ipv4_hdr *pkt_iph;
    struct rte_ether_hdr *pkt_eth_hdr;

    // printf("[service_id]: %d\n[pkt_type]: %d\n[src_ip]: %d\n[src_port]: %d\n[dst_ip]: %d\n[dst_port]: %d\n",
    //        service_id, pkt_type, src_ip, src_port, dst_ip, dst_port);

    pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL)
    {
        onvm_nflib_stop(ctx);
        rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }

    pkt = rte_pktmbuf_alloc(pktmbuf_pool);
    if (pkt == NULL)
    {
        printf("Failed to allocate packets\n");
        return;
    }

    // pkt->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
    // pkt->l2_len = ETH_HDR_LEN;
    // pkt->l3_len = IP_HDR_LEN;

    if (buffer_length > 0)
    {
        /* Set payload data */
        pkt_payload = (uint8_t *)rte_pktmbuf_prepend(pkt, buffer_length);
        if (pkt_payload == NULL)
        {
            printf("Failed to prepend payload. Consider splitting up the packet.\n");
            return;
        }
        rte_memcpy(pkt_payload, buffer, buffer_length);
    }

    /* Set TCP header */
    pkt_tcp_hdr = (struct rte_tcp_hdr *)rte_pktmbuf_prepend(pkt, TCP_HDR_LEN);
    if (pkt_tcp_hdr == NULL)
    {
        printf("Failed to prepend TCP header. Consider splitting up the packet.\n");
        return;
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
    default:
        break;
    }
    // rte_memcpy(pkt_tcp_hdr, pkt_tcp_hdr, sizeof(TCP_HDR_LEN)); // + option_len);

    /* Set IP header */
    pkt_iph = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(pkt, IP_HDR_LEN);
    if (pkt_iph == NULL)
    {
        printf("Failed to prepend IP header. Consider splitting up the packet.\n");
        return;
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
        return;
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
    onvm_nflib_return_pkt(ctx->nf, pkt);

    // printf("onvm_send_pkt() send packet to NF: %d\n", service_id);
}

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *ctx)
{
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ether_hdr *eth_hdr;
    uint8_t *payload;
    int payload_len, pkt_type;

    meta->action = ONVM_NF_ACTION_DROP;

    // eth_hdr = onvm_pkt_ether_hdr(pkt);
    // if (eth_hdr == NULL)
    // {
    //     printf("Error packet is not Ethernet packet\n");
    //     return -1;
    // }

    ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
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

    payload = rte_pktmbuf_mtod(pkt, uint8_t *) + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    payload_len = rte_pktmbuf_data_len(pkt) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);

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

    // printf("[pkt_type]: %d\n[src_ip]: %d\n[src_port]: %d\n[dst_ip]: %d\n[dst_port]: %d\n",
    //        pkt_type, ipv4_hdr->src_addr, tcp_hdr->src_port, ipv4_hdr->dst_addr, tcp_hdr->dst_port);

    int res_code;
    res_code = DeliverPacket(pkt_type, payload, payload_len, ipv4_hdr->src_addr, tcp_hdr->src_port, ipv4_hdr->dst_addr, tcp_hdr->dst_port);

    // if(res_code != 0) {
    //     meta->action = ONVM_NF_ACTION_TONF;
    // }

    return 0;
}
#include "onvm_nflib.h"
#include "_cgo_export.h"
#include "string.h"

// extern int DeliverPacket(struct rte_mbuf *, int, char *, int, uint32, uint16, uint32, uint16)

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx);

#define HTTP_FRAME 0
#define ESTABLISH_CONN 1
#define CLOSE_CONN 2
#define REPLY_CONN 3
#define BIG_FRAME 4
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

    return 0;
}
// handle_payload(pktmbuf_pool, buffer, buffer_length);
struct rte_mbuf *handle_payload(struct rte_mempool *pktmbuf_pool, char *buffer, int buffer_length)
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
    // printf("C char ptr: %p\n", buffer);

    pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL)
    {
        onvm_nflib_stop(ctx);
        rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }

    pkt = handle_payload(pktmbuf_pool, buffer, buffer_length);
    if (pkt == NULL)
    {
        printf("Payload handling error\n");
        return;
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
    // printf("[onvm_send_pkt][pkt->data_off: %d][After]\n", pkt->data_off);
    // printf("[onvm_send_pkt][pkt->pkt_len: %d][After]\n", pkt->pkt_len);
    onvm_nflib_return_pkt(ctx->nf, pkt);

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

int payload_assemble(uint8_t *buffer_ptr, int buff_cap, struct rte_mbuf *pkt, int Start_offset)
{
    int offset = 0;
    int End_offset = Start_offset;
    int first_segm_payload_len = rte_pktmbuf_data_len(pkt) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);

    // printf("[payload_assemble][Get: %d(bytes)]\n", first_segm_payload_len);
    if (buff_cap < first_segm_payload_len - Start_offset)
    {
        /* Target buffer cap is smaller than data left in pkt*/
        offset = buff_cap;
    }
    else
    {
        /* Target buffer cap is larger than data left in first mbuf */
        offset = first_segm_payload_len - Start_offset;
    }

    uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *) + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    rte_memcpy(buffer_ptr, data + Start_offset, offset);
    End_offset = End_offset + offset;

    // int empty_space = buff_cap - offset;
    // if (!empty_space)
    // {
    //     /* No space left in target buff */
    //     return End_offset
    // };

    // uint16_t mbuf_size = rte_pktmbuf_tailroom(head);
    // pkt = pkt->next;

    // while (pkt != NULL)
    // {
    //     // printf("[payload_assemble][Get: %d(bytes)]\n", pkt->data_len);
    //     uint8_t *src = rte_pktmbuf_mtod(pkt, uint8_t *);
    //     int offset = calculate_offset(empty_space, pkt->data_len);

    //     rte_memcpy(buffer_ptr + End_offset, src, offset);
    //     End_offset = End_offset + offset;
    //     pkt = pkt->next;
    // }

    return End_offset;
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

    int res_code;
    if (pkt->next == NULL)
    {
        payload_len = rte_pktmbuf_data_len(pkt) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        payload = rte_pktmbuf_mtod(pkt, uint8_t *) + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
        res_code = DeliverPacket(pkt, pkt_type, payload, payload_len, ipv4_hdr->src_addr, tcp_hdr->src_port, ipv4_hdr->dst_addr, tcp_hdr->dst_port);
    }
    else
    {
        payload_len = calculate_payload_len(pkt);
        res_code = DeliverPacket(pkt, BIG_FRAME, payload, payload_len, ipv4_hdr->src_addr, tcp_hdr->src_port, ipv4_hdr->dst_addr, tcp_hdr->dst_port);
    }

    return 0;
}
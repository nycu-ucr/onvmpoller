package onvmpoller

/*
#include <onvm_nflib.h>

//wrapper for c macro
static inline int pktmbuf_data_len_wrapper(struct rte_mbuf* pkt){
	return rte_pktmbuf_data_len(pkt);
}
static inline uint8_t* pktmbuf_mtod_wrapper(struct rte_mbuf* pkt){
	return rte_pktmbuf_mtod(pkt,uint8_t*);
}
*/
import "C"

import (
	"unsafe"
)

//export PacketHandler
func PacketHandler(pkt *C.struct_rte_mbuf, meta *C.struct_onvm_pkt_meta, nf_local_ctx *C.struct_onvm_nf_local_ctx) int32 {
	// Change to Go bytes from C char pointer
	recv_len := int(C.pktmbuf_data_len_wrapper(pkt))
	buf := C.GoBytes(unsafe.Pointer(C.pktmbuf_mtod_wrapper(pkt)), C.int(recv_len))

	// Deliver packet to onvmpoller
	var rx_data RxChannelData
	rx_data = DecodeToRxChannelData(buf)
	nf_pkt_handler_chan <- rx_data

	meta.action = C.ONVM_NF_ACTION_DROP

	return 0
}

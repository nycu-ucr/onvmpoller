package onvmpoller

// #cgo CFLAGS: -m64 -pthread -O3 -march=native
// #cgo CFLAGS: -I/home/hstsai/onvm/onvm-upf/onvm/onvm_nflib
// #cgo CFLAGS: -I/home/hstsai/onvm/onvm-upf/onvm/lib
// #cgo CFLAGS: -I/home/hstsai/onvm/onvm-upf/dpdk/x86_64-native-linuxapp-gcc/include
// #cgo LDFLAGS: /home/hstsai/onvm/onvm-upf/onvm/onvm_nflib/x86_64-native-linuxapp-gcc/libonvm.a
// #cgo LDFLAGS: /home/hstsai/onvm/onvm-upf/onvm/lib/x86_64-native-linuxapp-gcc/lib/libonvmhelper.a -lm
// #cgo LDFLAGS: -L/home/hstsai/onvm/onvm-upf/dpdk/x86_64-native-linuxapp-gcc/lib
// #cgo LDFLAGS: -lrte_flow_classify -Wl,--whole-archive -lrte_pipeline -Wl,--no-whole-archive -Wl,--whole-archive -lrte_table -Wl,--no-whole-archive -Wl,--whole-archive -lrte_port -Wl,--no-whole-archive -lrte_pdump -lrte_distributor -lrte_ip_frag -lrte_meter -lrte_fib -lrte_rib -lrte_lpm -lrte_acl -lrte_jobstats -Wl,--whole-archive -lrte_metrics -Wl,--no-whole-archive -lrte_bitratestats -lrte_latencystats -lrte_power -lrte_efd -lrte_bpf -lrte_ipsec -Wl,--whole-archive -lrte_cfgfile -lrte_gro -lrte_gso -lrte_hash -lrte_member -lrte_vhost -lrte_kvargs -lrte_telemetry -lrte_mbuf -lrte_net -lrte_ethdev -lrte_bbdev -lrte_cryptodev -lrte_security -lrte_compressdev -lrte_eventdev -lrte_rawdev -lrte_timer -lrte_mempool -lrte_stack -lrte_mempool_ring -lrte_mempool_octeontx2 -lrte_ring -lrte_pci -lrte_eal -lrte_cmdline -lrte_reorder -lrte_sched -lrte_rcu -lrte_graph -lrte_node -lrte_kni -lrte_common_cpt -lrte_common_octeontx -lrte_common_octeontx2 -lrte_common_dpaax -lrte_bus_pci -lrte_bus_vdev -lrte_bus_dpaa -lrte_bus_fslmc -lrte_mempool_bucket -lrte_mempool_stack -lrte_mempool_dpaa -lrte_mempool_dpaa2 -lrte_pmd_af_packet -lrte_pmd_ark -lrte_pmd_atlantic -lrte_pmd_avp -lrte_pmd_axgbe -lrte_pmd_bnxt -lrte_pmd_bond -lrte_pmd_cxgbe -lrte_pmd_dpaa -lrte_pmd_dpaa2 -lrte_pmd_e1000 -lrte_pmd_ena -lrte_pmd_enetc -lrte_pmd_enic -lrte_pmd_fm10k -lrte_pmd_failsafe -lrte_pmd_hinic -lrte_pmd_hns3 -lrte_pmd_i40e -lrte_pmd_iavf -lrte_pmd_ice -lrte_common_iavf -lrte_pmd_igc -lrte_pmd_ionic -lrte_pmd_ixgbe -lrte_pmd_kni -lrte_pmd_lio -lrte_pmd_memif -lrte_pmd_nfp -lrte_pmd_null -lrte_pmd_octeontx2 -lrte_pmd_qede -lrte_pmd_ring -lrte_pmd_softnic -lrte_pmd_sfc_efx -lrte_pmd_tap -lrte_pmd_thunderx_nicvf -lrte_pmd_vdev_netvsc -lrte_pmd_virtio -lrte_pmd_vhost -lrte_pmd_ifc -lrte_pmd_vmxnet3_uio -lrte_bus_vmbus -lrte_pmd_netvsc -lrte_pmd_bbdev_null -lrte_pmd_bbdev_fpga_lte_fec -lrte_pmd_bbdev_fpga_5gnr_fec -lrte_pmd_bbdev_turbo_sw -lrte_pmd_null_crypto -lrte_pmd_nitrox -lrte_pmd_octeontx_crypto -lrte_pmd_octeontx2_crypto -lrte_pmd_crypto_scheduler -lrte_pmd_dpaa2_sec -lrte_pmd_dpaa_sec -lrte_pmd_caam_jr -lrte_pmd_virtio_crypto -lrte_pmd_octeontx_zip -lrte_pmd_qat -lrte_pmd_skeleton_event -lrte_pmd_sw_event -lrte_pmd_dsw_event -lrte_pmd_octeontx_ssovf -lrte_pmd_dpaa_event -lrte_pmd_dpaa2_event -lrte_mempool_octeontx -lrte_pmd_octeontx -lrte_pmd_octeontx2_event -lrte_pmd_opdl_event -lrte_rawdev_skeleton -lrte_rawdev_dpaa2_cmdif -lrte_rawdev_dpaa2_qdma -lrte_bus_ifpga -lrte_rawdev_ioat -lrte_rawdev_ntb -lrte_rawdev_octeontx2_dma -lrte_rawdev_octeontx2_ep -Wl,--no-whole-archive -lrt -lm -lnuma -ldl
/*
#include <onvm_nflib.h>
#include "xio.h"

struct mbuf_list;
struct ipv4_4tuple;
struct xio_socket;

extern int onvm_init(struct onvm_nf_local_ctx **nf_local_ctx, char *nfName);
extern int payload_assemble(uint8_t *buffer_ptr, int buff_cap, struct mbuf_list *pkt_list, int start_offset);
extern int onvm_send_pkt(struct onvm_nf_local_ctx *ctx, int service_id, int pkt_type,
                uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                char *buffer, int buffer_length);
extern int xio_write(struct xio_socket *xs, uint8_t *buffer, int buffer_length, int *error_code);
extern int xio_read(struct xio_socket *xs, uint8_t *buffer, int buffer_length, int *error_code);
extern int xio_close(struct xio_socket *xs, int *error_code);
extern struct xio_socket *xio_connect(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *sem, int *error_code);
extern struct xio_socket *xio_accept(struct xio_socket *listener, char *sem, int *error_code);
extern struct xio_socket *xio_listen(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *complete_chan_ptr, int *error_code);

*/
import "C"

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cornelk/hashmap"
	"github.com/nycu-ucr/onvmpoller/logger"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	// For four_tuple
	SRC_IP_ADDR_IDX = 0
	SRC_PORT_IDX    = 1
	DST_IP_ADDR_IDX = 2
	DST_PORT_IDX    = 3
	// Distinguish packet type
	HTTP_FRAME     = 0
	ESTABLISH_CONN = 1
	CLOSE_CONN     = 2
	REPLY_CONN     = 3
	BIG_FRAME      = 4
	// Port manager setting
	PM_CHANNEL_SIZE = 1024
	// Logger level
	LOG_LEVEL = logrus.WarnLevel
	// Packet manager numbers
	ONVM_POLLER_NUM = 8
	// Error code
	END_OF_PKT = 87
)

type Buffer struct {
	buffer  []byte
	counter int
	is_done bool
}

type Config struct {
	// Map the IP address to Service ID
	IPIDMap map[string]int32 `yaml:"IPIDMap,omitempty"`
}

type NFip struct {
	// Map the NF to IP address
	Map map[string]string `yaml:"NFIPMap,omitempty"`
}

type ChannelData struct {
	PacketType  int
	FourTuple   Four_tuple_rte
	Payload_len int
	// PacketList  []*C.struct_rte_mbuf
	PacketList *C.struct_mbuf_list
}

type Pkt struct {
	Payload_len  int
	Start_offset int // How many bytes has been read
	PacketList   *C.struct_mbuf_list
	is_done      bool
}

type buffer struct {
	sync.Mutex
	list *list.List
	cond *sync.Cond
}

type Connection struct {
	dst_id uint8
	// rxchan         chan ([]byte)
	four_tuple Four_tuple_rte
	state      *connState
	sync_chan  chan struct{} // For waiting ACK
	buffer     *shareList
	pkt        *Pkt
}

type XIO_Connection struct {
	xio_socket *C.struct_xio_socket
	four_tuple Four_tuple_rte
	sync_chan  *sema
	dst_id     uint8
}

type XIO_Listener struct {
	xio_socket    *C.struct_xio_socket
	four_tuple    Four_tuple_rte
	laddr         OnvmAddr // Local Address
	complete_chan *sema
}

type connState struct {
	is_rxchan_closed atomic.Bool
	is_txchan_closed atomic.Bool
}

type Four_tuple_rte struct {
	Src_ip   uint32
	Src_port uint16
	Dst_ip   uint32
	Dst_port uint16
}

type OnvmListener struct {
	laddr         OnvmAddr         // Local Address
	conn          *Connection      // For handling the incoming connection
	complete_chan chan *Connection // Used in Accept() to get completed connection
}

type OnvmAddr struct {
	service_id uint8 // Service ID of NF
	network    string
	ipv4_addr  string
	port       uint16
}

type OnvmPoll struct {
	/*
		Connection table
		key: Use four-tuple to calculate this hash-key
		value: pointer to the Connection
	*/
	tables *hashmap.Map[uint32, *Connection]
	// pkt_table      *hashmap.Map[int, *C.struct_rte_mbuf]
	syn_chan       chan (*Four_tuple_rte)
	ack_chan       chan (*Four_tuple_rte)
	fin_frame_chan chan (*ChannelData) //*sharedBuffer
}

type PortManager struct {
	pool            map[uint16]bool
	get_port_ch     chan uint16
	release_port_ch chan uint16
}

type StatusFlag struct {
	is_rxchan_closed bool
	is_txchan_closed bool
	is_ready         bool
}

/* Global Variables */
var (
	config        Config
	nfIP          NFip
	onvmpoll      []*OnvmPoll
	local_address string
	nf_ctx        *C.struct_onvm_nf_local_ctx
	listener      *OnvmListener
	xio_listener  *XIO_Listener
	port_manager  *PortManager
	conn_pool     sync.Pool

	// Control Message (bytes)
	SYN = []byte("SYN")
	ACK = []byte("ACK")
	FIN = []byte("FIN")
)

func init() {
	/* Initialize Global Variable */
	initConfig()
	initNfIP()
	// initOnvmPoll()

	port_manager = &PortManager{
		pool:            make(map[uint16]bool),
		get_port_ch:     make(chan uint16, PM_CHANNEL_SIZE),
		release_port_ch: make(chan uint16, PM_CHANNEL_SIZE),
	}

	conn_pool = sync.Pool{
		New: func() any {
			return createConnection()
		},
	}

	/* Setup Logger */
	logger.SetLogLevel(LOG_LEVEL)

	/* Parse NF Name */
	NfName := parseNfName(os.Args[0])
	var char_ptr *C.char = C.CString(NfName)

	/* Set local_address by NF config */
	local_address, _ = NfToIP(NfName)

	/* Initialize NF context */
	logger.Log.Traceln("Start onvm init")
	C.onvm_init(&nf_ctx, char_ptr)
	C.free(unsafe.Pointer(char_ptr))

	/* Run port manager */
	port_manager.Run()

	/* Run onvmpoller */
	logger.Log.Traceln("Start onvmpoll run")
	runOnvmPoller()

	time.Sleep(2 * time.Second)
	logger.Log.Warnln("Init onvmpoller (XIO-refactor ver)")
}

func runOnvmPoller() {
	go C.onvm_nflib_run(nf_ctx)
	// runPktWorker()
}

/*********************************
	     onvmpoller API
*********************************/

func SetLocalAddress(addr string) {
	local_address = addr
}

func CloseONVM() {
	C.onvm_nflib_stop(nf_ctx)
}

/*********************************
	     Hepler functions
*********************************/

func initConfig() {
	// Get absolute file name of ipid.yaml
	var ipid_fname string
	if dir, err := os.Getwd(); err != nil {
		ipid_fname = "./ipid.yaml"
	} else {
		ipid_fname = dir + "/ipid.yaml"
	}

	// Read and decode the yaml content
	if yaml_content, err := ioutil.ReadFile(ipid_fname); err != nil {
		panic(err)
	} else {
		if unMarshalErr := yaml.Unmarshal(yaml_content, &config); unMarshalErr != nil {
			panic(unMarshalErr)
		}
	}
}

func initNfIP() {
	// Get absolute file name of ipid.yaml
	var nfIP_fname string
	if dir, err := os.Getwd(); err != nil {
		nfIP_fname = "./NFip.yaml"
	} else {
		nfIP_fname = dir + "/NFip.yaml"
	}

	// Read and decode the yaml content
	if yaml_content, err := ioutil.ReadFile(nfIP_fname); err != nil {
		panic(err)
	} else {
		if unMarshalErr := yaml.Unmarshal(yaml_content, &nfIP); unMarshalErr != nil {
			panic(unMarshalErr)
		}
	}
}

func IpToID(ip string) (id int32, err error) {
	id, ok := config.IPIDMap[ip]

	if !ok {
		err = fmt.Errorf("no match id")
	}

	return
}

func NfToIP(nf string) (ip string, err error) {
	ip, ok := nfIP.Map[nf]
	logger.Log.Warnf("[NF: %+v][IP: %+v]", nf, ip)

	if !ok {
		err = fmt.Errorf("no match from NF to IP")
	}

	return
}

func parseNfName(args string) string {
	nfName := strings.Split(args, "/")
	return nfName[1]
}

func parseAddress(address string) (string, uint16) {
	addr := strings.Split(address, ":")
	v, _ := strconv.ParseUint(addr[1], 10, 64)
	ip_addr, port := addr[0], uint16(v)

	return ip_addr, port
}

func intToIP4(ipInt int64) string {
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((ipInt & 0xff), 10)

	return b0 + "." + b1 + "." + b2 + "." + b3
}

func makeConnCtrlMsg(msg_type int) []byte {
	switch msg_type {
	case ESTABLISH_CONN:
		return SYN
	case REPLY_CONN:
		return ACK
	default:
		return FIN
	}
}

func unMarshalIP(ip uint32) string {
	ipInt := int64(ip)
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((ipInt & 0xff), 10)
	return b3 + "." + b2 + "." + b1 + "." + b0
}

func hashV4Flow(four_tuple Four_tuple_rte) uint32 {
	flowHash := (four_tuple.Src_ip * 59) ^ (four_tuple.Dst_ip) ^ (uint32(four_tuple.Src_port) << 16) ^ uint32(four_tuple.Dst_port) ^ uint32(6)

	return flowHash
}

func encodeChannelDataToBytes(tx_data ChannelData) ([]byte, error) {
	// Encode TxChannelData to bytes
	// logger.Log.Tracef("EncodeChannelDataToBytes, tx_data:%+v", tx_data)
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	err := enc.Encode(tx_data)

	return buf.Bytes(), err
}

func decodeToChannelData(buf []byte) (ChannelData, error) {
	// Decode bytes to RxChannelData
	var rx_data ChannelData

	dec := gob.NewDecoder(bytes.NewReader(buf))
	err := dec.Decode(&rx_data)

	return rx_data, err
}

func swapFourTuple(four_tuple Four_tuple_rte) Four_tuple_rte {
	return Four_tuple_rte{
		Src_ip:   four_tuple.Dst_ip,
		Src_port: four_tuple.Dst_port,
		Dst_ip:   four_tuple.Src_ip,
		Dst_port: four_tuple.Src_port,
	}
}

func parseFourTupleByIndex(four_tuple string, index int) string {
	tuples := strings.Split(four_tuple, ",")
	return tuples[index]
}

/* Use four-tuple to get the poller-index to dispatch */
func (four_tuple *Four_tuple_rte) getPollIndex() int {
	return int(four_tuple.Src_port+four_tuple.Dst_port) % ONVM_POLLER_NUM
}

/*********************************
	Methods of packet handling
*********************************/

func initOnvmPoll() {
	onvmpoll = make([]*OnvmPoll, ONVM_POLLER_NUM)
	for i := 0; i < ONVM_POLLER_NUM; i++ {
		onvmpoll[i] = &OnvmPoll{
			tables:         hashmap.New[uint32, *Connection](),
			syn_chan:       make(chan *Four_tuple_rte, 128/ONVM_POLLER_NUM),
			ack_chan:       make(chan *Four_tuple_rte, 128/ONVM_POLLER_NUM),
			fin_frame_chan: make(chan *ChannelData, 128/ONVM_POLLER_NUM),
		}
	}
}

func runPktWorker() {
	for i := 0; i < ONVM_POLLER_NUM; i++ {
		go onvmpoll[i].connectionHandler()
		go onvmpoll[i].finHandler()
		go onvmpoll[i].replyHandler()
	}
}

//export XIO_wait
func XIO_wait(list *C.struct_list_node) int {
	logger.Log.Tracef("[XIO_wait] Start")
	// defer TimeTrack(time.Now())
	/* Put the packet into the right queue */
	res_code := 0
	// i := 0

	for list != nil {
		c := (*sema)(unsafe.Pointer(list.go_channel_ptr))
		// logger.Log.Warnf("XIO_wait sema ptr: %p", c)
		if int(list.pkt_type) == CLOSE_CONN {
			// logger.Log.Warnf("ClOSE_CONN")
			c.close()
		} else {
			c.signal()
		}
		list = list.next
		// i++
	}
	// logger.Log.Errorf("XIO_wait end, %d", i)

	return res_code
}

func (poll *OnvmPoll) connectionHandler() {
	logger.Log.Traceln("Start connectionWorker")

	for four_tuple := range poll.syn_chan {
		var new_conn *Connection

		logger.Log.Traceln("Receive one connection request")

		// Initialize the new connection
		// new_conn = createConnection()
		new_conn = conn_pool.Get().(*Connection)
		initConnectionCh(new_conn)
		new_conn.four_tuple.Src_ip = binary.BigEndian.Uint32(net.ParseIP(listener.laddr.ipv4_addr)[12:16])
		new_conn.four_tuple.Src_port = listener.laddr.port
		new_conn.four_tuple.Dst_ip = four_tuple.Src_ip
		new_conn.four_tuple.Dst_port = four_tuple.Src_port

		// Add the connection to table
		poll.Add(new_conn)

		dst_id, _ := IpToID(unMarshalIP(four_tuple.Src_ip))
		new_conn.dst_id = uint8(dst_id)

		// Send ACK back to client
		err := new_conn.writeControlMessage(REPLY_CONN)
		if err != nil {
			logger.Log.Errorln(err.Error())
			new_conn.Close()
		} else {
			logger.Log.Tracef("Write connection response to (%v, %v)",
				new_conn.four_tuple.Dst_ip,
				new_conn.four_tuple.Dst_port)
		}

		// s := intToIP4(int64(four_tuple.Src_ip))
		// t, _ := IpToID(s)
		// logger.Log.Debugf("Accept connection: %v:%v (NF: %v)", s, four_tuple.Src_port, t)
		listener.complete_chan <- new_conn
	}
}

func (poll *OnvmPoll) replyHandler() {
	for four_tuple := range poll.ack_chan {
		conn, ok := poll.tables.Get(hashV4Flow(*four_tuple))
		if !ok {
			logger.Log.Errorf("DeliverPacket-ACK, Can not get connection via four-tuple %v", four_tuple)
		} else {
			// conn.state.is_ready.Store(true)
			conn.sync_chan <- struct{}{}
		}
	}
}

func (poll *OnvmPoll) finHandler() {
	for channel_data := range poll.fin_frame_chan {
		// Let onvmpoller delete the connection
		conn, ok := poll.tables.Get(hashV4Flow(channel_data.FourTuple))
		if !ok {
			logger.Log.Errorf("DeliverPacket, close can not get the connection via four-tuple:%v\n", channel_data.FourTuple)
		} else {
			if !conn.state.is_rxchan_closed.Load() {
				logger.Log.Tracef("DeliverPacket, close connection, four-tuple: %v\n", conn.four_tuple)
				conn.buffer.close()
				conn.state.is_rxchan_closed.Store(true)
				poll.Delete(conn)
			}
		}
	}
}

func (poll *OnvmPoll) frameHandler(channel_data *ChannelData) {
	conn, ok := poll.tables.Get(hashV4Flow(channel_data.FourTuple))
	if !ok {
		logger.Log.Errorf("DeliverPacket-HTTP Frame, Can not get connection via four-tuple %v", channel_data.FourTuple)
	} else {
		conn.buffer.send(&Pkt{Payload_len: channel_data.Payload_len, PacketList: channel_data.PacketList})
	}
}

/*********************************
	Methods of Port Manager
*********************************/

func (pm *PortManager) DistributePort() {
	// Infinitely fills up the get_port_channel with unused ports, blocked when the channel is full

	var base, upper_limit uint16 = 20000, 65535

	for {
		for port := base; port < upper_limit; port++ {
			if isUsed, isExist := pm.pool[port]; isExist {
				if isUsed {
					continue
				} else {
					pm.get_port_ch <- port
					pm.pool[port] = true
				}
			} else {
				// First use this port
				pm.get_port_ch <- port
				pm.pool[port] = true
			}
		}
	}
}

func (pm *PortManager) RecyclePort() {
	for port := range pm.release_port_ch {
		pm.pool[port] = false
	}
}

func (pm *PortManager) Run() {
	go pm.DistributePort()
	go pm.RecyclePort()
}

func (pm *PortManager) GetPort() uint16 {
	return <-pm.get_port_ch
}

func (pm *PortManager) ReleasePort(port uint16) {
	pm.release_port_ch <- port
}

/*********************************
	Methods of OnvmPoll
*********************************/

func createConnection() *Connection {
	// Create a new connection with unique connection ID
	var conn Connection
	var cs connState
	conn.state = &cs
	conn.buffer = newShareList()
	conn.pkt = &Pkt{Payload_len: 0, Start_offset: 0, PacketList: nil, is_done: true}

	return &conn
}

func initConnectionCh(conn *Connection) {
	var new_state connState

	// conn.rxchan = make(chan []byte, 5) // For non-blocking
	conn.sync_chan = make(chan struct{})

	/* Need to reset the connection state */
	conn.state = &new_state
	conn.buffer = newShareList()
}

func (poll *OnvmPoll) Add(conn *Connection) {
	// Add connection to connection table
	poll.tables.Insert(hashV4Flow(swapFourTuple(conn.four_tuple)), conn)
}

func (poll *OnvmPoll) Delete(conn *Connection) error {
	// defer TimeTrack(time.Now())
	// Delete the connection from connection and four-tuple tables
	if conn.state.is_txchan_closed.Load() && conn.state.is_rxchan_closed.Load() {
		var four_tuple Four_tuple_rte = swapFourTuple(conn.four_tuple)
		ok := poll.tables.Del(hashV4Flow(four_tuple))
		if !ok {
			msg := fmt.Sprintf("Delete connection from four-tuple fail, %v is not exsit", four_tuple)
			err := errors.New(msg)
			logger.Log.Errorln(msg)
			return err
		}

		port_manager.ReleasePort(conn.four_tuple.Src_port)

		// Recycle the connection
		conn_pool.Put(conn)

		logger.Log.Tracef("Close connection sucessfully.")
	}

	return nil
}

func GetConnByReverseFourTuple(four_tuple Four_tuple_rte) (*Connection, error) {
	swap_four_tuple := swapFourTuple(four_tuple)
	poller_index := swap_four_tuple.getPollIndex()
	c, ok := onvmpoll[poller_index].tables.Get(hashV4Flow(swap_four_tuple))

	if !ok {
		err := fmt.Errorf("GetConnByReverseFourTuple, Can not get connection via four-tuple %v", four_tuple)

		return nil, err
	} else {
		return c, nil
	}
}

/*********************************
	Methods of OnvmAddr
*********************************/

func (oa OnvmAddr) Network() string {
	return oa.network
}

func (oa OnvmAddr) String() string {
	s := fmt.Sprintf("Network: %s, Service ID: %2d, IP Address: %s, Port: %5d.",
		oa.network, oa.service_id, oa.ipv4_addr, oa.port)
	return s
}

/*********************************
	Methods of Connection
*********************************/

// Read implements the net.Conn Read method.
func (connection Connection) Read(b []byte) (int, error) {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start Connection.Read, four-tuple: %v", connection.four_tuple)

	var length int
	var err error

	// List is empty, waiting for packet
	if connection.pkt.is_done {
		is_close := connection.buffer.recv(connection.pkt)

		if is_close {
			err = io.EOF
			return length, err
		}
	}

	// if true {
	// 	conn, _ := GetConnByReverseFourTuple(connection.four_tuple)
	// 	conn.pkt = connection.pkt
	// 	// logger.Log.Errorln("Read", connection.four_tuple)
	// 	logger.Log.Debugf("1: Conn ptr: %p, Conn pkt ptr: %p", &connection, connection.pkt)
	// 	logger.Log.Debugf("2: Conn ptr: %p, Conn pkt ptr: %p", conn, conn.pkt)
	// 	logger.Log.Debugf("Read, Pkt info, start offset: %v, payload length: %v", connection.pkt.Start_offset, connection.pkt.Payload_len)
	// }

	runtime.KeepAlive(b)

	return connection.reading(b)
}

func (connection Connection) reading(b []byte) (int, error) {
	logger.Log.Tracef("Start Connection.reading, four-tuple: %v", connection.four_tuple)
	// defer TimeTrack(time.Now())
	var length int
	var err error

	buff_cap := cap(b)
	buffer_ptr := (*C.uint8_t)(unsafe.Pointer(&b[0]))
	// length, err2 = buffer.Read(b)
	offset := C.payload_assemble(buffer_ptr, C.int(buff_cap), connection.pkt.PacketList, C.int(connection.pkt.Start_offset))
	end_offset := int(offset)
	length = end_offset - connection.pkt.Start_offset

	if end_offset == connection.pkt.Payload_len {
		connection.pkt.is_done = true
	} else {
		connection.pkt.Start_offset = end_offset
	}

	runtime.KeepAlive(b)

	logger.Log.Tracef("reading read %v (buffer_cap: %v)", length, buff_cap)
	return length, err
}

// Read ACK
func (connection Connection) readACK() error {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start readACK, four-tuple: %v", connection.four_tuple)

	var err error
	// Receive packet from onvmpoller
	_, ok := <-connection.sync_chan

	if !ok {
		err = fmt.Errorf("EOF")
	}

	return err
}

// Write implements the net.Conn Write method.
func (connection Connection) Write(b []byte) (int, error) {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start Connection.Write, four-tuple: %v", connection.four_tuple)
	logger.Log.Debugf("Write %d data.", len(b))

	len := len(b)
	// fmt.Printf("Poller []byte ptr: %p\n", &b[0])

	// Translate Go structure to C char *
	// var buffer_ptr *C.char
	// buffer_ptr = (*C.char)(C.CBytes(b))
	buffer_ptr := (*C.char)(unsafe.Pointer(&b[0]))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, C.int(connection.dst_id), C.int(HTTP_FRAME),
		C.uint32_t(connection.four_tuple.Src_ip), C.uint16_t(connection.four_tuple.Src_port),
		C.uint32_t(connection.four_tuple.Dst_ip), C.uint16_t(connection.four_tuple.Dst_port),
		buffer_ptr, C.int(len))

	runtime.KeepAlive(b)

	return len, nil
}

// For connection control message
func (connection Connection) writeControlMessage(msg_type int) error {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start Connection.writeControlMessage, four-tuple: %v", connection.four_tuple)

	// buffer := makeConnCtrlMsg(msg_type)
	// Translate Go structure to C char *
	// var buffer_ptr *C.char
	// buffer_ptr = (*C.char)(C.CBytes(buffer))
	// buffer_ptr := (*C.char)(unsafe.Pointer(&buffer[0]))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, C.int(connection.dst_id), C.int(msg_type),
		C.uint32_t(connection.four_tuple.Src_ip), C.uint16_t(connection.four_tuple.Src_port),
		C.uint32_t(connection.four_tuple.Dst_ip), C.uint16_t(connection.four_tuple.Dst_port),
		nil, C.int(0))

	return nil
}

// Close implements the net.Conn Close method.
func (connection Connection) Close() error {
	var err error

	logger.Log.Tracef("Close connection four-tuple: %v\n", connection.four_tuple)

	if !connection.state.is_txchan_closed.Load() {
		// Notify peer connection can be closed
		connection.writeControlMessage(CLOSE_CONN)

		// Close local connection
		connection.state.is_txchan_closed.Store(true)

		pollIndex := connection.four_tuple.getPollIndex()
		err = onvmpoll[pollIndex].Delete(&connection)
	}

	return err
}

// LocalAddr implements the net.Conn LocalAddr method.
func (connection Connection) LocalAddr() net.Addr {
	var oa OnvmAddr
	oa.ipv4_addr = unMarshalIP(connection.four_tuple.Src_ip)
	oa.port = connection.four_tuple.Src_port
	oa.network = "onvm"
	id, _ := IpToID(oa.ipv4_addr)
	oa.service_id = uint8(id)

	return oa
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (connection Connection) RemoteAddr() net.Addr {
	var oa OnvmAddr
	oa.ipv4_addr = unMarshalIP(connection.four_tuple.Dst_ip)
	oa.port = connection.four_tuple.Dst_port
	oa.network = "onvm"
	id, _ := IpToID(oa.ipv4_addr)
	oa.service_id = uint8(id)

	return oa
}

// SetDeadline implements the net.Conn SetDeadline method.
func (connection Connection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (connection Connection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (connection Connection) SetWriteDeadline(t time.Time) error {
	return nil
}

/*********************************
	Methods of OnvmListner
*********************************/

func (ol OnvmListener) Accept() (net.Conn, error) {
	logger.Log.Traceln("Start OnvmListener.Accept")
	return <-ol.complete_chan, nil
}

func (ol OnvmListener) Close() error {
	err := ol.conn.Close()
	return err
}

func (ol OnvmListener) Addr() net.Addr {
	return ol.laddr
}

/*
********************************

	API for HTTP Server

********************************
*/

func ListenONVM(network, address string) (net.Listener, error) {
	logger.Log.Traceln("Start ListenONVM")
	logger.Log.Debugf("Listen at %s", address)

	if network != "onvm" {
		msg := fmt.Sprintf("Unsppourt network type: %v", network)
		err := errors.New(msg)
		return nil, err
	}
	ip_addr, port := parseAddress(address)
	local_address = ip_addr

	return listen(ip_addr, port)
}

func DialONVM(network, address string) (net.Conn, error) {
	logger.Log.Traceln("Start DialONVM")

	ip_addr, port := parseAddress(address)

	// Initialize a connection
	// conn := createConnection()
	conn := conn_pool.Get().(*Connection)
	initConnectionCh(conn)
	// conn.four_tuple.Src_ip = binary.BigEndian.Uint32(net.ParseIP(local_address)[12:16])
	conn.four_tuple.Src_ip = inet_addr(local_address)
	conn.four_tuple.Src_port = port_manager.GetPort()
	// conn.four_tuple.Dst_ip = binary.BigEndian.Uint32(net.ParseIP(ip_addr)[12:16])
	conn.four_tuple.Dst_ip = inet_addr(ip_addr)
	conn.four_tuple.Dst_port = port
	logger.Log.Debugf("I'm %s:%v, Dial to %s", local_address, conn.four_tuple.Src_port, address)

	// Add the connection to table, otherwise it can't receive response
	pollIndex := conn.four_tuple.getPollIndex()
	onvmpoll[pollIndex].Add(conn)

	dst_id, _ := IpToID(ip_addr)
	conn.dst_id = uint8(dst_id)

	// Send connection request to server
	err := conn.writeControlMessage(ESTABLISH_CONN)
	logger.Log.Traceln("Dial write connection create request")

	if err != nil {
		logger.Log.Errorln(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Tracef(fmt.Sprintf("Write connection request to (%v,%v)", ip_addr, port))
	}

	// Wait for response
	logger.Log.Traceln("Dial wait connection create response")
	err = conn.readACK()
	if err != nil {
		logger.Log.Errorln(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Traceln("Dial get connection create response")
	}

	logger.Log.Debugln("DialONVM done")

	return conn, nil
}

func TimeTrack(start time.Time) {
	elapsed := time.Since(start)

	// Skip this function, and fetch the PC and file for its parent.
	pc, _, _, _ := runtime.Caller(1)

	// Retrieve a function object this functions parent.
	funcObj := runtime.FuncForPC(pc)

	// Regex to extract just the function name (and not the module path).
	runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
	name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")

	log.Println(fmt.Sprintf("%s took %d(ns)", name, elapsed.Nanoseconds()))
}

type shareList struct {
	cond   *sync.Cond
	closed bool
	l      *list.List
}

func newShareList() *shareList {
	return &shareList{
		cond:   sync.NewCond(&sync.Mutex{}),
		closed: false,
		l:      list.New(),
	}
}

func (c *shareList) recv(pkt_buffer *Pkt) (close bool) {
	c.cond.L.Lock()

	for c.l.Len() == 0 {
		if c.closed {
			c.cond.L.Unlock()
			return true
		}
		c.cond.Wait()
	}

	pkt := c.l.Remove(c.l.Front()).(*Pkt)
	pkt_buffer.is_done = false
	pkt_buffer.PacketList = pkt.PacketList
	pkt_buffer.Payload_len = pkt.Payload_len
	pkt_buffer.Start_offset = pkt.Start_offset

	c.cond.Signal()
	c.cond.L.Unlock()
	return false
}

func (c *shareList) send(pkt *Pkt) {
	c.cond.L.Lock()

	if c.l.Len() == 0 {
		c.l.PushBack(pkt)
		c.cond.Signal()
	} else {
		c.l.PushBack(pkt)
	}

	if c.closed {
		panic("send on closed shareList")
	}

	c.cond.L.Unlock()
}

func (c *shareList) close() {
	c.cond.L.Lock()
	c.closed = true
	c.cond.Signal()
	c.cond.L.Unlock()
}

/*
********************************

	API for XIO listener

********************************
*/

func ListenXIO(network, address string) (net.Listener, error) {
	logger.Log.Traceln("Start ListenXIO")
	logger.Log.Debugf("Listen at %s", address)

	if network != "onvm" {
		msg := fmt.Sprintf("Unsppourt network type: %v", network)
		err := errors.New(msg)
		return nil, err
	}
	ip_addr, port := parseAddress(address)
	local_address = ip_addr

	var l net.Listener
	var err error
	l, err = listenXIO(ip_addr, port)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func listenXIO(ip_addr string, port uint16) (*XIO_Listener, error) {
	var four_tuple Four_tuple_rte
	// four_tuple.Src_ip = binary.BigEndian.Uint32(net.ParseIP(ip_addr)[12:16])
	four_tuple.Src_ip = inet_addr(ip_addr)
	four_tuple.Src_port = port
	four_tuple.Dst_ip = 0
	four_tuple.Dst_port = 0

	id, err := IpToID(ip_addr)
	laddr := OnvmAddr{
		service_id: uint8(id),
		network:    "onvm",
		ipv4_addr:  ip_addr,
		port:       port,
	}

	if err != nil {
		return nil, err
	}

	xio_listener = &XIO_Listener{
		laddr:         laddr,
		four_tuple:    four_tuple,
		complete_chan: newSema(),
	}

	complete_chan_ptr := (*C.char)(unsafe.Pointer(xio_listener.complete_chan))

	xs := C.xio_listen(C.uint32_t(xio_listener.four_tuple.Src_ip), C.uint16_t(xio_listener.four_tuple.Src_port),
		C.uint32_t(xio_listener.four_tuple.Dst_ip), C.uint16_t(xio_listener.four_tuple.Dst_port), complete_chan_ptr, nil)
	if xs == nil {
		msg := fmt.Sprintf("Unable to listen on %v", xio_listener.laddr.String())
		err = errors.New(msg)
		return nil, err
	}

	xio_listener.xio_socket = xs

	return xio_listener, nil
}

func (xl XIO_Listener) Accept() (net.Conn, error) {
	logger.Log.Traceln("Start XIO_Listener.Accept")

	var connection *XIO_Connection

	condVar := newSema()
	// logger.Log.Warnf("xs.complete_chan ptr: %p", condVar)
	condVarPtr := (*C.char)(unsafe.Pointer(condVar))
	err_code := 0
	err_code_ptr := (*C.int)(unsafe.Pointer(&err_code))
	for {
		err_code = 0
		xs := C.xio_accept(xl.xio_socket, condVarPtr, err_code_ptr)

		if err_code == int(syscall.EAGAIN) {
			// Wait for connection request
			ok := xl.complete_chan.wait()
			runtime.KeepAlive(xl.complete_chan)
			if ok {
				err := fmt.Errorf("Accept: listener closed")
				condVar.close()
				return nil, err
			}
			continue
		} else if xs == nil {
			err := fmt.Errorf("Accept: xio_accept return nil socket, errno=%d", err_code)
			condVar.close()
			return nil, err
		} else if err_code != 0 {
			err := fmt.Errorf("Accept: xio_accept errno=%d", err_code)
			condVar.close()
			return nil, err
		} else {
			connection = &XIO_Connection{
				xio_socket: xs,
				sync_chan:  condVar,
			}
			connection.four_tuple.Src_ip = uint32(xs.fourTuple.ip_src)
			connection.four_tuple.Src_port = uint16(xs.fourTuple.port_src)
			connection.four_tuple.Dst_ip = uint32(xs.fourTuple.ip_dst)
			connection.four_tuple.Dst_port = uint16(xs.fourTuple.port_dst)
			// logger.Log.Warnf("[Accept] srcIP:%s, srcPort:%d, dstIP:%s, dstPort:%d",
			// 	unMarshalIP(connection.four_tuple.Src_ip), connection.four_tuple.Src_port,
			// 	unMarshalIP(connection.four_tuple.Dst_ip), connection.four_tuple.Dst_port)
			break
		}
	}

	return connection, nil
}

func (xl XIO_Listener) Close() error {
	/* TODO */
	return nil
}

func (xl XIO_Listener) Addr() net.Addr {
	return xl.laddr
}

/*
********************************

	API for XIO Dial

********************************
*/

func DialXIO(network, address string) (net.Conn, error) {
	logger.Log.Traceln("Start DialXIO")

	ip_addr, port := parseAddress(address)

	// Initialize a connection
	var conn XIO_Connection
	conn.four_tuple.Src_ip = inet_addr(local_address)
	conn.four_tuple.Src_port = port_manager.GetPort()
	conn.four_tuple.Dst_ip = inet_addr(ip_addr)
	conn.four_tuple.Dst_port = port

	condVar := newSema()
	condVarPtr := (*C.char)(unsafe.Pointer(condVar))
	conn.sync_chan = condVar

	dst_id, _ := IpToID(ip_addr)
	conn.dst_id = uint8(dst_id)

	// Send connection request to server
	xs := C.xio_connect(C.uint32_t(conn.four_tuple.Src_ip), C.uint16_t(conn.four_tuple.Src_port),
		C.uint32_t(conn.four_tuple.Dst_ip), C.uint16_t(conn.four_tuple.Dst_port), condVarPtr, nil)
	conn.xio_socket = xs

	if conn.xio_socket == nil {
		err := fmt.Errorf("Read ACK failed")
		conn.Close()
		return conn, err
	} else {
		logger.Log.Tracef(fmt.Sprintf("Write connection request to (%v,%v)", ip_addr, port))
	}

	// Wait for response
	logger.Log.Traceln("Dial wait connection create response")
	ok := condVar.wait()
	runtime.KeepAlive(condVar)

	if ok {
		err := fmt.Errorf("Read ACK failed")

		return nil, err
	}

	logger.Log.Debugln("DialONVM done")
	// logger.Log.Warnf("[Dial] srcIP:%s, srcPort:%d, dstIP:%s, dstPort:%d",
	// 	unMarshalIP(conn.four_tuple.Src_ip), conn.four_tuple.Src_port,
	// 	unMarshalIP(conn.four_tuple.Dst_ip), conn.four_tuple.Dst_port)

	return conn, nil
}

/*
********************************

	API for XIO connection

********************************
*/

// Read implements the net.Conn Read method.
func (connection XIO_Connection) Read(b []byte) (int, error) {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start XIO_Connection.Read, four-tuple: %v, buffer (len, cap) = (%v, %v)", connection.four_tuple, len(b), cap(b))

	var length int
	var err error

	buffer_len := len(b)
	buffer_ptr := (*C.uint8_t)(unsafe.Pointer(&b[0]))

	err_code := 0
	err_code_ptr := (*C.int)(unsafe.Pointer(&err_code))
	for {
		err_code = 0
		ret := C.xio_read(connection.xio_socket, buffer_ptr, C.int(buffer_len), err_code_ptr)
		length = int(ret)

		if err_code == int(syscall.EAGAIN) {
			// Wait for pkt
			ok := connection.sync_chan.wait()
			runtime.KeepAlive(connection.sync_chan)
			// logger.Log.Warnf("Reader wake-up")
			if ok {
				/* Socket closed */
				return 0, io.EOF
			}
			continue
		} else if err_code == END_OF_PKT {
			err = errors.New("EOP")
			break
		} else if err_code != 0 {
			err := fmt.Errorf("Read: xio_read errno=%d", err_code)
			return 0, err
		} else {
			break
		}
	}

	runtime.KeepAlive(b)

	return length, err
}

// Write implements the net.Conn Write method.
func (connection XIO_Connection) Write(b []byte) (int, error) {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start XIO_Connection.Write, four-tuple: %v", connection.four_tuple)
	logger.Log.Debugf("Write %d data.", len(b))

	var length int
	var err error

	buffer_len := len(b)
	buffer_ptr := (*C.uint8_t)(unsafe.Pointer(&b[0]))

	ret := C.xio_write(connection.xio_socket, buffer_ptr, C.int(buffer_len), nil)
	length = int(ret)
	if length < 0 {
		err = fmt.Errorf("xio_write error")
		return 0, err
	}

	runtime.KeepAlive(b)

	return length, nil
}

// Close implements the net.Conn Close method.
func (connection XIO_Connection) Close() error {
	var err error

	logger.Log.Tracef("Close connection four-tuple: %v\n", connection.four_tuple)

	ret := C.xio_close(connection.xio_socket, nil)
	if int(ret) == -1 {
		err = fmt.Errorf("xio_close failed")
	}

	return err
}

// LocalAddr implements the net.Conn LocalAddr method.
func (connection XIO_Connection) LocalAddr() net.Addr {
	var oa OnvmAddr
	oa.ipv4_addr = unMarshalIP(connection.four_tuple.Src_ip)
	oa.port = connection.four_tuple.Src_port
	oa.network = "onvm"
	id, _ := IpToID(oa.ipv4_addr)
	oa.service_id = uint8(id)

	return oa
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (connection XIO_Connection) RemoteAddr() net.Addr {
	var oa OnvmAddr
	oa.ipv4_addr = unMarshalIP(connection.four_tuple.Dst_ip)
	oa.port = connection.four_tuple.Dst_port
	oa.network = "onvm"
	id, _ := IpToID(oa.ipv4_addr)
	oa.service_id = uint8(id)

	return oa
}

// SetDeadline implements the net.Conn SetDeadline method.
func (connection XIO_Connection) SetDeadline(t time.Time) error {
	logger.Log.Tracef("Start XIO_Connection.SetDeadline")
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (connection XIO_Connection) SetReadDeadline(t time.Time) error {
	logger.Log.Tracef("Start XIO_Connection.SetReadDeadline")
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (connection XIO_Connection) SetWriteDeadline(t time.Time) error {
	logger.Log.Tracef("Start XIO_Connection.SetWriteDeadline")
	return nil
}

func inet_addr(ipaddr string) uint32 {
	var (
		ip                 = strings.Split(ipaddr, ".")
		ip1, ip2, ip3, ip4 uint64
		ret                uint32
	)
	ip1, _ = strconv.ParseUint(ip[0], 10, 8)
	ip2, _ = strconv.ParseUint(ip[1], 10, 8)
	ip3, _ = strconv.ParseUint(ip[2], 10, 8)
	ip4, _ = strconv.ParseUint(ip[3], 10, 8)
	ret = uint32(ip4)<<24 + uint32(ip3)<<16 + uint32(ip2)<<8 + uint32(ip1)
	return ret
}

type sema struct {
	cond   *sync.Cond
	flag   bool
	closed bool
}

func newSema() *sema {
	return &sema{
		cond:   sync.NewCond(&sync.Mutex{}),
		flag:   false,
		closed: false,
	}
}

func (c *sema) wait() (close bool) {
	c.cond.L.Lock()

	for !c.flag {
		if c.closed {
			c.cond.L.Unlock()
			return true
		}
		c.cond.Wait()
	}
	c.flag = false

	c.cond.L.Unlock()
	return false
}

func (c *sema) signal() {
	c.cond.L.Lock()

	if c.closed {
		logger.Log.Warnf("sem.signal(): signal on closed sema")
	}

	if !c.flag {
		c.flag = true
		c.cond.Signal()
	}

	c.cond.L.Unlock()
}

func (c *sema) close() {
	c.cond.L.Lock()
	if c.flag {
		logger.Log.Warnf("sem.close(): close on a true flag semaphore")
	}
	c.closed = true
	c.cond.Signal()
	c.cond.L.Unlock()
}

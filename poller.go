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

extern int onvm_init(struct onvm_nf_local_ctx **nf_local_ctx, char *nfName);
extern void onvm_send_pkt(struct onvm_nf_local_ctx *ctx, int service_id, int pkt_type,
                uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                char *buffer, int buffer_length);
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/alphadose/haxmap"
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
	// Port manager setting
	PM_CHANNEL_SIZE = 1024
	// Logger level
	LOG_LEVEL = logrus.WarnLevel
)

type Config struct {
	// Map the IP address to Service ID
	IPIDMap map[string]int32 `yaml:"IPIDMap,omitempty"`
}

type ChannelData struct {
	PacketType int
	FourTuple  Four_tuple_rte
	Payload    []byte // Connection control message or HTTP Frame
}

type Connection struct {
	dst_id           uint8
	rxchan           chan ([]byte)
	is_rxchan_closed bool
	is_txchan_closed bool
	four_tuple       Four_tuple_rte
}

type Four_tuple_rte struct {
	Src_ip   uint32
	Src_port uint16
	Dst_ip   uint32
	Dst_port uint16
}

type OnvmListener struct {
	laddr         OnvmAddr         // Local Address
	conn          *Connection      // This need to handle the incoming connection
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
	tables *haxmap.HashMap[uint32, *Connection]
}

type PortManager struct {
	pool            map[uint16]bool
	get_port_ch     chan uint16
	release_port_ch chan uint16
}

type Port struct {
	count uint32
}

/* Global Variables */
var (
	config Config
	// conn_id             connID
	onvmpoll OnvmPoll
	// port_pool           portPool           // The ports range from 49152 to 65535
	local_address string // Initialize at ListenONVM
	nf_ctx        *C.struct_onvm_nf_local_ctx
	listener      *OnvmListener
	port_manager  *PortManager
	a_port        Port

	//Control Message (bytes)
	SYN = []byte("SYN")
	ACK = []byte("ACK")
	FIN = []byte("FIN")
)

func init() {
	/* Initialize Global Variable */
	InitConfig()
	local_address = "127.0.0.1"
	onvmpoll.tables = haxmap.New[uint32, *Connection]()

	port_manager = &PortManager{
		pool:            make(map[uint16]bool),
		get_port_ch:     make(chan uint16, PM_CHANNEL_SIZE),
		release_port_ch: make(chan uint16, PM_CHANNEL_SIZE),
	}
	a_port.count = 0

	/* Setup Logger */
	logger.SetLogLevel(LOG_LEVEL)

	/* Parse NF Name */
	NfName := ParseNfName(os.Args[0])
	var char_ptr *C.char
	char_ptr = C.CString(NfName)

	/* Initialize NF context */
	logger.Log.Traceln("Start onvm init")
	C.onvm_init(&nf_ctx, char_ptr)
	C.free(unsafe.Pointer(char_ptr))

	/* Run port Manager */
	port_manager.Run()

	/* Run onvmpoller */
	logger.Log.Traceln("Start onvmpoll run")
	onvmpoll.Run()
}

func SetLocalAddress(addr string) {
	local_address = addr
}

func ParseNfName(args string) string {
	nfName := strings.Split(args, "/")
	return nfName[1]
}

func CloseONVM() {
	C.onvm_nflib_stop(nf_ctx)
}

func InitConfig() {
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

func IpToID(ip string) (id int32, err error) {
	id, ok := config.IPIDMap[ip]

	if !ok {
		err = fmt.Errorf("no match id")
	}

	return
}

func ParseAddress(address string) (string, uint16) {
	addr := strings.Split(address, ":")
	v, _ := strconv.ParseUint(addr[1], 10, 64)
	ip_addr, port := addr[0], uint16(v)

	return ip_addr, port
}

func MakeConnCtrlMsg(msg_type int) []byte {
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
	return b0 + "." + b1 + "." + b2 + "." + b3
}

func hashV4Flow(four_tuple Four_tuple_rte) uint32 {
	flowHash := (four_tuple.Src_ip * 59) ^ (four_tuple.Dst_ip) ^ (uint32(four_tuple.Src_port) << 16) ^ uint32(four_tuple.Dst_port) ^ uint32(6)

	return flowHash
}

func EncodeChannelDataToBytes(tx_data ChannelData) ([]byte, error) {
	// Encode TxChannelData to bytes
	// logger.Log.Tracef("EncodeChannelDataToBytes, tx_data:%+v", tx_data)
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	err := enc.Encode(tx_data)

	return buf.Bytes(), err
}

func DecodeToChannelData(buf []byte) (ChannelData, error) {
	// Decode bytes to RxChannelData
	var rx_data ChannelData

	dec := gob.NewDecoder(bytes.NewReader(buf))
	err := dec.Decode(&rx_data)

	return rx_data, err
}

func SwapFourTuple(four_tuple Four_tuple_rte) *Four_tuple_rte {
	return &Four_tuple_rte{
		Src_ip:   four_tuple.Dst_ip,
		Src_port: four_tuple.Dst_port,
		Dst_ip:   four_tuple.Src_ip,
		Dst_port: four_tuple.Src_port,
	}
}

func ParseFourTupleByIndex(four_tuple string, index int) string {
	tuples := strings.Split(four_tuple, ",")
	return tuples[index]
}

//export DeliverPacket
func DeliverPacket(packet_type C.int, buf *C.char, buf_len C.int, src_ip C.uint, src_port C.ushort, dst_ip C.uint, dst_port C.ushort) int {
	// Deliver the packet to the right connection via four-tuple
	res_code := 0
	payload := C.GoBytes(unsafe.Pointer(buf), C.int(buf_len))

	four_tuple := Four_tuple_rte{Src_ip: uint32(src_ip), Src_port: uint16(src_port), Dst_ip: uint32(dst_ip), Dst_port: uint16(dst_port)}
	// rxdata := ChannelData{PacketType: int(packet_type), FourTuple: four_tuple, Payload: payload}
	pktType := int(packet_type)

	switch pktType {
	case ESTABLISH_CONN:
		var err error
		// Deliver packet to litsener's connection
		if (listener.conn.four_tuple.Src_ip != four_tuple.Dst_ip) || (listener.conn.four_tuple.Src_port != four_tuple.Dst_port) {
			err = fmt.Errorf("DeliverPacket-%d, Can not get connection via four-tuple %v", pktType, four_tuple)
		}
		// listener_conn, err := onvmpoll.GetConnByReverseFourTuple(listener_four_tuple)

		if err != nil {
			logger.Log.Errorln(err)
		} else {
			connectionHandler(&four_tuple)
		}
	case CLOSE_CONN:
		// Let onvmpoller delete the connection
		conn, ok := onvmpoll.tables.Get(hashV4Flow(four_tuple))
		if !ok {
			logger.Log.Errorf("DeliverPacket, close can not get the connection via four-tuple:%v\n", four_tuple)
		} else {
			logger.Log.Infof("DeliverPacket, close connection, four-tuple: %v\n", conn.four_tuple)
			close(conn.rxchan)
			conn.is_rxchan_closed = true
			onvmpoll.Delete(conn)
		}
	case HTTP_FRAME:
		conn, ok := onvmpoll.tables.Get(hashV4Flow(four_tuple))
		if !ok {
			logger.Log.Errorf("DeliverPacket-%d, Can not get connection via four-tuple %v", pktType, four_tuple)
		} else {
			conn.rxchan <- payload
			// logger.Log.Tracef("DeliverPacket, deliver packet to Conn ID: %v\n", conn.conn_id)
		}
	case REPLY_CONN:
		conn, ok := onvmpoll.tables.Get(hashV4Flow(four_tuple))
		if !ok {
			logger.Log.Errorf("DeliverPacket-%d, Can not get connection via four-tuple %v", pktType, four_tuple)
		} else {
			conn.rxchan <- payload
			// logger.Log.Tracef("DeliverPacket, deliver packet to Conn ID: %v\n", conn.conn_id)
		}
	default:
		logger.Log.Errorf("Unknown packet type: %v\n", packet_type)
	}
	return res_code
}

func connectionHandler(four_tuple *Four_tuple_rte) {
	logger.Log.Traceln("Start connectionWorker")

	var new_conn *Connection

	logger.Log.Traceln("Receive one connection request")

	// Initialize the new connection
	new_conn = onvmpoll.Create()
	new_conn.four_tuple.Src_ip = binary.BigEndian.Uint32(net.ParseIP(listener.laddr.ipv4_addr)[12:16])
	new_conn.four_tuple.Src_port = listener.laddr.port
	new_conn.four_tuple.Dst_ip = four_tuple.Src_ip
	new_conn.four_tuple.Dst_port = four_tuple.Src_port

	// Add the connection to table
	onvmpoll.Add(new_conn)

	dst_id, _ := IpToID(unMarshalIP(four_tuple.Src_ip))
	new_conn.dst_id = uint8(dst_id)

	// Send ACK back to client
	_, err := new_conn.WriteControlMessage(REPLY_CONN)
	if err != nil {
		logger.Log.Errorln(err.Error())
		new_conn.Close()
	} else {
		logger.Log.Tracef("Write connection response to (%v, %v)",
			new_conn.four_tuple.Dst_ip,
			new_conn.four_tuple.Dst_port)
	}

	listener.complete_chan <- new_conn
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

func (port *Port) atomicPort() uint16 {
	return uint16(atomic.AddUint32(&port.count, 1))
}

/*********************************
	Methods of OnvmPoll
*********************************/

func (onvmpoll *OnvmPoll) Create() *Connection {
	// Create a new connection with unique connection ID
	var conn Connection
	conn.rxchan = make(chan []byte, 5) // For non-blocking

	return &conn
}

func (onvmpoll *OnvmPoll) Add(conn *Connection) {
	// Add connection to connection table
	onvmpoll.tables.Set(hashV4Flow(*SwapFourTuple(conn.four_tuple)), conn)
}

func (onvmpoll *OnvmPoll) Delete(conn *Connection) error {
	// Delete the connection from connection and four-tuple tables
	if conn.is_txchan_closed && conn.is_rxchan_closed {
		var four_tuple *Four_tuple_rte = SwapFourTuple(conn.four_tuple)
		// if _, ok := onvmpoll.tables.GetAndDel(four_tuple); !ok {
		// 	msg := fmt.Sprintf("Delete connection from four-tuple fail, %v is not exsit", *four_tuple)
		// 	err := errors.New(msg)
		// 	logger.Log.Errorln(msg)
		// 	return err
		// }
		// port_manager.ReleasePort(conn.four_tuple.Src_port)
		// logger.Log.Info("Close connection sucessfully.\n")
		onvmpoll.tables.Del(hashV4Flow(*four_tuple))
	}

	return nil
}

func (onvmpoll *OnvmPoll) GetConnByReverseFourTuple(four_tuple *Four_tuple_rte) (*Connection, error) {
	swap_four_tuple := SwapFourTuple(*four_tuple)
	c, ok := onvmpoll.tables.Get(hashV4Flow(*swap_four_tuple))

	if !ok {
		err := fmt.Errorf("GetConnByReverseFourTuple, Can not get connection via four-tuple %v", *four_tuple)

		return nil, err
	} else {
		return c, nil
	}
}

func (onvmpoll *OnvmPoll) Close() {
	C.onvm_nflib_stop(nf_ctx)
}

func (onvmpoll *OnvmPoll) Run() {
	go C.onvm_nflib_run(nf_ctx)
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
	logger.Log.Tracef("Start Connection.Read, four-tuple: %v", connection.four_tuple)

	var length int
	var err error
	// // Receive packet from onvmpoller
	rx_data, ok := <-connection.rxchan

	if ok {
		// Get response
		if len(b) < len(rx_data) {
			// TODO: Fix this problem
			logger.Log.Errorf("Read buffer length is not sufficient. Need %v but got %v", len(rx_data), len(b))
		} else {
			length = copy(b, rx_data)
		}
	} else {
		err = fmt.Errorf("EOF")
	}

	return length, err
}

// Read ACK
func (connection Connection) ReadACK() error {
	logger.Log.Tracef("Start ReadACK, four-tuple: %v", connection.four_tuple)

	var err error
	// Receive packet from onvmpoller
	_, ok := <-connection.rxchan

	if !ok {
		err = fmt.Errorf("EOF")
	}

	return err
}

// Write implements the net.Conn Write method.
func (connection Connection) Write(b []byte) (int, error) {
	logger.Log.Tracef("Start Connection.Write, four-tuple: %v", connection.four_tuple)

	// Translate Go structure to C char *
	var buffer_ptr *C.char
	buffer_ptr = (*C.char)(C.CBytes(b))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, C.int(connection.dst_id), C.int(HTTP_FRAME),
		C.uint32_t(connection.four_tuple.Src_ip), C.uint16_t(connection.four_tuple.Src_port),
		C.uint32_t(connection.four_tuple.Dst_ip), C.uint16_t(connection.four_tuple.Dst_port),
		buffer_ptr, C.int(len(b)))

	return len(b), nil
}

// For connection control message
func (connection Connection) WriteControlMessage(msg_type int) (int, error) {
	logger.Log.Tracef("Start Connection.WriteControlMessage, four-tuple: %v", connection.four_tuple)

	// Translate Go structure to C char *
	var buffer_ptr *C.char
	buffer := MakeConnCtrlMsg(msg_type)
	buffer_ptr = (*C.char)(C.CBytes(buffer))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, C.int(connection.dst_id), C.int(msg_type),
		C.uint32_t(connection.four_tuple.Src_ip), C.uint16_t(connection.four_tuple.Src_port),
		C.uint32_t(connection.four_tuple.Dst_ip), C.uint16_t(connection.four_tuple.Dst_port),
		buffer_ptr, C.int(len(buffer)))

	return len(buffer), nil
}

// Close implements the net.Conn Close method.
func (connection Connection) Close() error {
	var err error
	// conn, err := onvmpoll.GetConnByReverseFourTuple(&connection.four_tuple)

	// if err != nil {
	// 	return err
	// }

	logger.Log.Tracef("Close connection four-tuple: %v\n", connection.four_tuple)

	// Notify peer connection can be closed
	connection.WriteControlMessage(CLOSE_CONN)

	// Close local connection
	connection.is_txchan_closed = true
	err = onvmpoll.Delete(&connection)

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
	oa.ipv4_addr = unMarshalIP(connection.four_tuple.Dst_ip) //ParseFourTupleByIndex(connection.four_tuple, DST_IP_ADDR_IDX)
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
func CreateConnection() net.Conn {
	conn := onvmpoll.Create()
	return conn
}

func ListenONVM(network, address string) (net.Listener, error) {
	logger.Log.Traceln("Start ListenONVM")

	if network != "onvm" {
		msg := fmt.Sprintf("Unsppourt network type: %v", network)
		err := errors.New(msg)
		return nil, err
	}
	ip_addr, port := ParseAddress(address)
	local_address = ip_addr

	return listen(ip_addr, port)
}

func DialONVM(network, address string) (net.Conn, error) {
	logger.Log.Traceln("Start DialONVM")

	ip_addr, port := ParseAddress(address)

	// Initialize a connection
	conn := onvmpoll.Create()
	conn.four_tuple.Src_ip = binary.BigEndian.Uint32(net.ParseIP(local_address)[12:16])
	conn.four_tuple.Src_port = port_manager.GetPort() //a_port.atomicPort()
	conn.four_tuple.Dst_ip = binary.BigEndian.Uint32(net.ParseIP(ip_addr)[12:16])
	conn.four_tuple.Dst_port = port

	// Add the connection to table, otherwise it can't receive response
	onvmpoll.Add(conn)

	dst_id, _ := IpToID(ip_addr)
	conn.dst_id = uint8(dst_id)

	// Send connection request to server
	_, err := conn.WriteControlMessage(ESTABLISH_CONN)
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
	err = conn.ReadACK()
	if err != nil {
		logger.Log.Errorln(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Traceln("Dial get connection create response")
	}

	return conn, nil
}

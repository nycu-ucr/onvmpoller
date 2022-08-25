package onvmpoller

// #cgo CFLAGS: -m64 -pthread -O3 -march=native
// #cgo CFLAGS: -I<replace path>/onvm-upf/onvm/onvm_nflib
// #cgo CFLAGS: -I<replace path>/onvm-upf/onvm/lib
// #cgo CFLAGS: -I<replace path>/onvm-upf/dpdk/x86_64-native-linuxapp-gcc/include
// #cgo LDFLAGS: <replace path>/onvm-upf/onvm/onvm_nflib/x86_64-native-linuxapp-gcc/libonvm.a
// #cgo LDFLAGS: <replace path>/onvm-upf/onvm/lib/x86_64-native-linuxapp-gcc/lib/libonvmhelper.a -lm
// #cgo LDFLAGS: -L<replace path>/onvm-upf/dpdk/x86_64-native-linuxapp-gcc/lib
// #cgo LDFLAGS: -lrte_flow_classify -Wl,--whole-archive -lrte_pipeline -Wl,--no-whole-archive -Wl,--whole-archive -lrte_table -Wl,--no-whole-archive -Wl,--whole-archive -lrte_port -Wl,--no-whole-archive -lrte_pdump -lrte_distributor -lrte_ip_frag -lrte_meter -lrte_fib -lrte_rib -lrte_lpm -lrte_acl -lrte_jobstats -Wl,--whole-archive -lrte_metrics -Wl,--no-whole-archive -lrte_bitratestats -lrte_latencystats -lrte_power -lrte_efd -lrte_bpf -lrte_ipsec -Wl,--whole-archive -lrte_cfgfile -lrte_gro -lrte_gso -lrte_hash -lrte_member -lrte_vhost -lrte_kvargs -lrte_telemetry -lrte_mbuf -lrte_net -lrte_ethdev -lrte_bbdev -lrte_cryptodev -lrte_security -lrte_compressdev -lrte_eventdev -lrte_rawdev -lrte_timer -lrte_mempool -lrte_stack -lrte_mempool_ring -lrte_mempool_octeontx2 -lrte_ring -lrte_pci -lrte_eal -lrte_cmdline -lrte_reorder -lrte_sched -lrte_rcu -lrte_graph -lrte_node -lrte_kni -lrte_common_cpt -lrte_common_octeontx -lrte_common_octeontx2 -lrte_common_dpaax -lrte_bus_pci -lrte_bus_vdev -lrte_bus_dpaa -lrte_bus_fslmc -lrte_mempool_bucket -lrte_mempool_stack -lrte_mempool_dpaa -lrte_mempool_dpaa2 -lrte_pmd_af_packet -lrte_pmd_ark -lrte_pmd_atlantic -lrte_pmd_avp -lrte_pmd_axgbe -lrte_pmd_bnxt -lrte_pmd_bond -lrte_pmd_cxgbe -lrte_pmd_dpaa -lrte_pmd_dpaa2 -lrte_pmd_e1000 -lrte_pmd_ena -lrte_pmd_enetc -lrte_pmd_enic -lrte_pmd_fm10k -lrte_pmd_failsafe -lrte_pmd_hinic -lrte_pmd_hns3 -lrte_pmd_i40e -lrte_pmd_iavf -lrte_pmd_ice -lrte_common_iavf -lrte_pmd_igc -lrte_pmd_ionic -lrte_pmd_ixgbe -lrte_pmd_kni -lrte_pmd_lio -lrte_pmd_memif -lrte_pmd_nfp -lrte_pmd_null -lrte_pmd_octeontx2 -lrte_pmd_qede -lrte_pmd_ring -lrte_pmd_softnic -lrte_pmd_sfc_efx -lrte_pmd_tap -lrte_pmd_thunderx_nicvf -lrte_pmd_vdev_netvsc -lrte_pmd_virtio -lrte_pmd_vhost -lrte_pmd_ifc -lrte_pmd_vmxnet3_uio -lrte_bus_vmbus -lrte_pmd_netvsc -lrte_pmd_bbdev_null -lrte_pmd_bbdev_fpga_lte_fec -lrte_pmd_bbdev_fpga_5gnr_fec -lrte_pmd_bbdev_turbo_sw -lrte_pmd_null_crypto -lrte_pmd_nitrox -lrte_pmd_octeontx_crypto -lrte_pmd_octeontx2_crypto -lrte_pmd_crypto_scheduler -lrte_pmd_dpaa2_sec -lrte_pmd_dpaa_sec -lrte_pmd_caam_jr -lrte_pmd_virtio_crypto -lrte_pmd_octeontx_zip -lrte_pmd_qat -lrte_pmd_skeleton_event -lrte_pmd_sw_event -lrte_pmd_dsw_event -lrte_pmd_octeontx_ssovf -lrte_pmd_dpaa_event -lrte_pmd_dpaa2_event -lrte_mempool_octeontx -lrte_pmd_octeontx -lrte_pmd_octeontx2_event -lrte_pmd_opdl_event -lrte_rawdev_skeleton -lrte_rawdev_dpaa2_cmdif -lrte_rawdev_dpaa2_qdma -lrte_bus_ifpga -lrte_rawdev_ioat -lrte_rawdev_ntb -lrte_rawdev_octeontx2_dma -lrte_rawdev_octeontx2_ep -Wl,--no-whole-archive -lrt -lm -lnuma -ldl
/*
#include <onvm_nflib.h>

extern int onvm_init(struct onvm_nf_local_ctx **nf_local_ctx, char *nfName);
extern void onvm_send_pkt(struct onvm_nf_local_ctx *ctx, int service_id, char *buff, int buff_length);
*/
import "C"

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

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
)

type Config struct {
	// Map the IP address to Service ID
	IPIDMap map[string]int32 `yaml:"IPIDMap,omitempty"`
}

type HttpTransaction struct {
	FourTuple   [4]string
	HttpMessage []byte // Request or Response
}

type RxChannelData struct {
	Transaction HttpTransaction
	PacketType  int
}

type TxChannelData struct {
	Transaction HttpTransaction
	PacketType  int
}

type Connection struct {
	conn_id    uint16
	rxchan     chan (RxChannelData)
	txchan     chan (TxChannelData)
	four_tuple [4]string
}

type OnvmListener struct {
	laddr OnvmAddr    // Local Address
	conn  *Connection // This need to handle the incoming connection
}

type OnvmAddr struct {
	service_id uint8 // Service ID of NF
	network    string
	ipv4_addr  string
	port       uint16
}

type OnvmPoll struct {
	/*
		tables contain two tables, connection table and four-tuple table:
			conn_table: uint16: *Connection (conn_id: *Connection)
			four-tuple table: [4]string: *Connection
	*/
	tables sync.Map
}

/* Global Variables */
var (
	config              Config
	conn_id             uint16
	onvmpoll            OnvmPoll
	port_pool           map[uint16]bool      // The ports range from 49152 to 65535
	local_address       string               // Initialize at ListenONVM
	nf_pkt_handler_chan chan (RxChannelData) // data type may change to pointer to buffer
	// fourTuple_to_connID map[[4]string]uint16 // TODO: sync.Map or cmap
	nf_ctx           *C.struct_onvm_nf_local_ctx
	listener_conn_id uint16
)

func init() {
	/* Initialize Global Variable */
	InitConfig()
	conn_id = 0
	local_address = "127.0.0.1"
	port_pool = make(map[uint16]bool)
	onvmpoll.tables = sync.Map{}
	nf_pkt_handler_chan = make(chan RxChannelData, 5)
	listener_conn_id = 0
	// fourTuple_to_connID = make(map[[4]string]uint16)

	/* Setup Logger */
	logger.SetLogLevel(logrus.TraceLevel)

	/* Parse NF Name */
	NfName := ParseNfName(os.Args[0])
	var char_ptr *C.char
	char_ptr = C.CString(NfName)

	/* Initialize NF context */
	logger.Log.Traceln("Start onvm init")
	C.onvm_init(&nf_ctx, char_ptr)
	C.free(unsafe.Pointer(char_ptr))

	/* Run onvmpoller */
	logger.Log.Traceln("Start onvmpoll run")
	onvmpoll.Run()
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

func GetConnID() uint16 {
	// TODO: Perhaps there is a sync issue in here.
	var result uint16
	for {
		// Reserve conn_id = 0 to listener
		if conn_id == listener_conn_id {
			conn_id++
			continue
		}

		if _, isExist := onvmpoll.tables.Load(conn_id); !isExist {
			result = conn_id
			conn_id++
			break
		} else {
			logger.Log.Infof("ID:%d is used.", conn_id)
			conn_id++
		}
	}

	return result
}

func GetUnusedPort() uint16 {
	var base int32 = 49152
	var upper_limit int32 = 65536 - base
	var port uint16

	for {
		n := rand.Int31n(upper_limit)
		port = uint16(base + n)
		if _, isExist := port_pool[port]; !isExist {
			port_pool[port] = true
			break
		} else {
			continue
		}
	}

	return port
}

func DeletePort(port uint16) error {
	if _, isExist := port_pool[port]; !isExist {
		msg := fmt.Sprintf("Delete port fail, %d is not exist.", port)
		err := errors.New(msg)
		logger.Log.Fatal(msg)
		return err
	}
	delete(port_pool, port)
	return nil
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
	var msg []byte
	switch msg_type {
	case ESTABLISH_CONN:
		msg = []byte("SYN")
	case REPLY_CONN:
		msg = []byte("ACK")
	case CLOSE_CONN:
		msg = []byte("FIN")
	}

	return msg
}

func GetPacketType(buf []byte) int {
	var pkt_type int

	if bytes.Equal(buf, []byte("SYN")) {
		pkt_type = ESTABLISH_CONN
	} else if bytes.Equal(buf, []byte("ACK")) {
		pkt_type = REPLY_CONN
	} else if bytes.Equal(buf, []byte("FIN")) {
		pkt_type = CLOSE_CONN
	} else {
		pkt_type = HTTP_FRAME
	}

	return pkt_type
}

func EncodeTxChannelDataToBytes(tx_data TxChannelData) []byte {
	// Encode TxChannelData to bytes
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	err := enc.Encode(tx_data)
	if err != nil {
		logger.Log.Fatal(err)
	}

	return buf.Bytes()
}

func DecodeToRxChannelData(buf []byte) RxChannelData {
	// Decode bytes to RxChannelData
	var rx_data RxChannelData

	dec := gob.NewDecoder(bytes.NewReader(buf))
	err := dec.Decode(&rx_data)
	if err != nil {
		logger.Log.Fatal(err)
	}

	return rx_data
}

/*********************************
	Methods of OnvmPoll
*********************************/

func (onvmpoll *OnvmPoll) Create() *Connection {
	// Create a new connection with unique connection ID
	var conn Connection
	conn.rxchan = make(chan RxChannelData, 1) // For non-blocking
	conn.txchan = make(chan TxChannelData, 1) // For non-blocking
	conn.conn_id = GetConnID()

	// Add the connection into the table
	onvmpoll.Add(&conn)

	return &conn
}

func (onvmpoll *OnvmPoll) Add(conn *Connection) {
	// Add connection to connection table
	onvmpoll.tables.Store(conn.conn_id, conn)
	logger.Log.Debugln(onvmpoll.String())
}

func (onvmpoll *OnvmPoll) Delete(id uint16) error {
	// TODO: Try to use pointer to Connection instead of connection id

	if _, isExist := onvmpoll.tables.Load(id); !isExist {
		msg := fmt.Sprintf("This connID, %v, is not exist", id)
		err := errors.New(msg)
		logger.Log.Fatal(msg)
		return err
	}

	c, _ := onvmpoll.tables.Load(id)
	conn := c.(*Connection)
	onvmpoll.DeleteEntryFromTable(conn)
	onvmpoll.tables.Delete(id)

	return nil
}

func (onvmpoll *OnvmPoll) AddEntryToTable(caller string, conn *Connection) {
	/* Add the connection to four-tuple table */
	var four_tuple [4]string

	// If it is invoked by dialONVM, it should swap SRC and DST.
	if caller == "dial" {
		four_tuple[SRC_IP_ADDR_IDX] = conn.four_tuple[DST_IP_ADDR_IDX]
		four_tuple[SRC_PORT_IDX] = conn.four_tuple[DST_PORT_IDX]
		four_tuple[DST_IP_ADDR_IDX] = conn.four_tuple[SRC_IP_ADDR_IDX]
		four_tuple[DST_PORT_IDX] = conn.four_tuple[SRC_PORT_IDX]
	} else {
		four_tuple = conn.four_tuple
	}

	// fourTuple_to_connID[four_tuple] = conn.conn_id
	onvmpoll.tables.Store(four_tuple, conn)
}

func (onvmpoll *OnvmPoll) DeleteEntryFromTable(conn *Connection) error {
	/* Delete the connection from four-tuple table */
	if _, isExist := onvmpoll.tables.Load(conn.four_tuple); !isExist {
		msg := fmt.Sprintf("Delete connection from four-tuple fail, %v is not exsit", conn.four_tuple)
		err := errors.New(msg)
		logger.Log.Fatal(msg)
		return err
	}
	// delete(fourTuple_to_connID, conn.four_tuple)
	onvmpoll.tables.Delete(conn.four_tuple)

	return nil
}

func (onvmpoll *OnvmPoll) Close() {
	C.onvm_nflib_stop(nf_ctx)
}

func (onvmpoll OnvmPoll) String() string {
	result := "OnvmPoll has following connections:\n"
	// for key, _ := range onvmpoll.conn_table {
	// 	result += fmt.Sprintf("\tConnection ID: %d\n", key)
	// }

	onvmpoll.tables.Range(func(k, v interface{}) bool {
		if _, ok := k.(uint16); ok {
			result += fmt.Sprintf("\tConnection ID: %v\n", k)
		}
		return true
	})

	return result
}

func (onvmpoll *OnvmPoll) ReadFromONVM() {
	// This function receives the packet from NF's packet handler function
	// Then forward the packet to the HTTP server
	for rxData := range nf_pkt_handler_chan {
		switch rxData.PacketType {
		case ESTABLISH_CONN:
			// Deliver packet to litsener's connection
			lc, _ := onvmpoll.tables.Load(listener_conn_id)
			listener_conn := lc.(*Connection)
			listener_conn.rxchan <- rxData
			logger.Log.Tracef("ReadFromONVM, deliver packet to Conn ID: %v\n", listener_conn.conn_id)
		case CLOSE_CONN:
			// Let onvmpoller delete the connection
			c, _ := onvmpoll.tables.Load(rxData.Transaction.FourTuple)
			conn := c.(*Connection)
			onvmpoll.Delete(conn.conn_id)
			logger.Log.Infoln("ReadFromONVM, close connection, Conn ID: %v\n", conn.conn_id)
		case REPLY_CONN, HTTP_FRAME:
			// TODO: REPLY_CONN may be removed
			c, _ := onvmpoll.tables.Load(rxData.Transaction.FourTuple)
			conn := c.(*Connection)
			conn.rxchan <- rxData
			logger.Log.Tracef("ReadFromONVM, deliver packet to Conn ID: %v\n", conn.conn_id)
		default:
			logger.Log.Errorf("Unknown packet type: %v\n", rxData.PacketType)
		}
	}
}

func (onvmpoll *OnvmPoll) WriteToONVM(conn *Connection, tx_data TxChannelData) {
	// Get destination NF ID
	logger.Log.Tracef("Conn ID:%d, WriteToONVM()", conn.conn_id)

	id, _ := IpToID(conn.four_tuple[DST_IP_ADDR_IDX])
	dst_id := C.int(id)

	// Translate Go structure to C char *
	var buffer []byte
	var buffer_ptr *C.char

	buffer = EncodeTxChannelDataToBytes(tx_data)
	buffer_ptr = (*C.char)(C.CBytes(buffer))

	// Use CGO to call functions of NFLib
	logger.Log.Tracef("Conn ID:%d, onvm_send_pkt()", conn.conn_id)
	C.onvm_send_pkt(nf_ctx, dst_id, buffer_ptr, C.int(len(buffer)))
}

func (onvmpoll *OnvmPoll) Polling() {
	// The infinite loop checks each connection for unsent data
	for {
		// for _, conn := range onvmpoll.conn_table {
		// 	select {
		// 	case txData := <-conn.txchan:
		// 		onvmpoll.WriteToONVM(&conn, txData)
		// 	}
		// }
		onvmpoll.tables.Range(func(k, v interface{}) bool {
			if _, ok := k.(uint16); ok {
				conn := v.(*Connection)
				select {
				case txData := <-conn.txchan:
					logger.Log.Tracef("Conn ID:%d, handle by Polling()", conn.conn_id)
					onvmpoll.WriteToONVM(conn, txData)
				}
			}
			return true
		})
	}
}

func (onvmpoll *OnvmPoll) Run() {
	go onvmpoll.ReadFromONVM()
	go onvmpoll.Polling()
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
	logger.Log.Traceln("Start Connection.Read")

	// Receive packet from onvmpoller
	rx_data := <-connection.rxchan

	// Get response
	if len(b) < len(rx_data.Transaction.HttpMessage) {
		// TODO: Fix this problem
		logger.Log.Fatal("Read buffer length is not sufficient")
	} else {
		copy(b, rx_data.Transaction.HttpMessage)
	}

	return len(rx_data.Transaction.HttpMessage), nil
}

// Write implements the net.Conn Write method.
func (connection Connection) Write(b []byte) (int, error) {
	logger.Log.Traceln("Start Connection.Write")

	// Encapsulate buffer into HttpTransaction
	var ht HttpTransaction
	ht.FourTuple = connection.four_tuple
	ht.HttpMessage = make([]byte, len(b))
	copy(ht.HttpMessage, b)

	// Encapuslate HttpTransaction into TxChannelData
	var tx_data TxChannelData
	tx_data.PacketType = GetPacketType(b)
	tx_data.Transaction = ht

	// Send packet to onvmpoller via channel
	connection.txchan <- tx_data

	return len(b), nil
}

// Close implements the net.Conn Close method.
func (connection Connection) Close() error {
	// Notify peer connection can be closed
	var msg []byte = MakeConnCtrlMsg(CLOSE_CONN)
	connection.Write(msg)

	// Close local connection
	err := onvmpoll.Delete(connection.conn_id)

	return err
}

// LocalAddr implements the net.Conn LocalAddr method.
func (connection Connection) LocalAddr() net.Addr {
	var oa OnvmAddr
	v, _ := strconv.ParseUint(connection.four_tuple[SRC_PORT_IDX], 10, 64)
	oa.ipv4_addr = connection.four_tuple[SRC_IP_ADDR_IDX]
	oa.port = uint16(v)
	oa.network = "onvm"
	id, _ := IpToID(oa.ipv4_addr)
	oa.service_id = uint8(id)

	return oa
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (connection Connection) RemoteAddr() net.Addr {
	var oa OnvmAddr
	v, _ := strconv.ParseUint(connection.four_tuple[DST_PORT_IDX], 10, 64)
	oa.ipv4_addr = connection.four_tuple[DST_IP_ADDR_IDX]
	oa.port = uint16(v)
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

	var new_conn *Connection

	rx_data := <-ol.conn.rxchan // Payload is our defined connection request, not HTTP payload

	if !bytes.Equal([]byte("SYN"), rx_data.Transaction.HttpMessage) {
		msg := fmt.Sprintf("Payload is not SYN, is %v", rx_data.Transaction.HttpMessage)
		err := errors.New(msg)
		logger.Log.Fatal(msg)
		return new_conn, err
	} else {
		logger.Log.Traceln("Receive one connection request")
	}

	// Initialize the new connection
	new_conn = onvmpoll.Create()
	new_conn.four_tuple[SRC_IP_ADDR_IDX] = ol.laddr.ipv4_addr
	new_conn.four_tuple[SRC_PORT_IDX] = fmt.Sprint(ol.laddr.port)
	new_conn.four_tuple[DST_IP_ADDR_IDX] = rx_data.Transaction.FourTuple[SRC_IP_ADDR_IDX]
	new_conn.four_tuple[DST_PORT_IDX] = rx_data.Transaction.FourTuple[SRC_PORT_IDX]

	// Send ACK back to client
	conn_response := make([]byte, 3)
	conn_response = MakeConnCtrlMsg(REPLY_CONN)

	_, err := new_conn.Write(conn_response)
	if err != nil {
		logger.Log.Fatal(err.Error())
		new_conn.Close()
		return new_conn, err
	} else {
		logger.Log.Tracef("Write connection response to (%v, %v)",
			new_conn.four_tuple[DST_IP_ADDR_IDX],
			new_conn.four_tuple[DST_PORT_IDX])
	}

	// Add the connection to table
	onvmpoll.AddEntryToTable("accept", new_conn)

	return new_conn, nil
}

func (ol OnvmListener) Close() error {
	err := ol.conn.Close()
	return err
}

func (ol OnvmListener) Addr() net.Addr {
	return ol.laddr
}

/*********************************
	API for HTTP Server
*********************************/
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
	conn.four_tuple[SRC_IP_ADDR_IDX] = local_address
	conn.four_tuple[SRC_PORT_IDX] = fmt.Sprint(GetUnusedPort())
	conn.four_tuple[DST_IP_ADDR_IDX] = ip_addr
	conn.four_tuple[DST_PORT_IDX] = fmt.Sprint(port)

	// Send connection request to server
	conn_request := make([]byte, 3)
	conn_response := make([]byte, 3)
	conn_request = MakeConnCtrlMsg(ESTABLISH_CONN)

	logger.Log.Traceln("Dial write connection create request")
	_, err := conn.Write(conn_request)
	if err != nil {
		logger.Log.Fatal(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Tracef(fmt.Sprintf("Write connection request to (%v,%v)", ip_addr, port))
	}

	// Add the connection to table, otherwise it can't receive response
	onvmpoll.AddEntryToTable("dial", conn)

	// Wait for response
	logger.Log.Traceln("Dial wait connection create response")
	_, err = conn.Read(conn_response)
	if err != nil {
		logger.Log.Fatal(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Traceln("Dial get connection create response")
	}

	return conn, nil
}

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
	// Logger level
	LOG_LEVEL = logrus.WarnLevel
)

type Config struct {
	// Map the IP address to Service ID
	IPIDMap map[string]int32 `yaml:"IPIDMap,omitempty"`
}

// type HttpTransaction struct {
// 	FourTuple   [4]string
// 	HttpMessage []byte // Request or Response
// }

// type RxChannelData struct {
// 	Transaction HttpTransaction
// 	PacketType  int
// }

// type TxChannelData struct {
// 	Transaction HttpTransaction
// 	PacketType  int
// }

type ChannelData struct {
	PacketType int
	FourTuple  [4]string
	Payload    []byte // Connection control message or HTTP Frame
}

type Connection struct {
	dst_id uint8
	// conn_id uint16
	rxchan chan (ChannelData)
	// txchan           chan (TxChannelData)
	four_tuple       [4]string
	is_rxchan_closed bool
	is_txchan_closed bool
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

// type connID struct {
// 	m  *sync.Mutex
// 	ID uint16
// }

type portPool struct {
	m    *sync.Mutex
	pool map[uint16]bool
}

/* Global Variables */
var (
	config Config
	// conn_id             connID
	onvmpoll            OnvmPoll
	port_pool           portPool           // The ports range from 49152 to 65535
	local_address       string             // Initialize at ListenONVM
	nf_pkt_handler_chan chan (ChannelData) // data type may change to pointer to buffer
	// fourTuple_to_connID map[[4]string]uint16 // TODO: sync.Map or cmap
	nf_ctx              *C.struct_onvm_nf_local_ctx
	listener_four_tuple *[4]string
)

func init() {
	/* Initialize Global Variable */
	InitConfig()
	// conn_id.ID = 0
	// conn_id.m = new(sync.Mutex)
	local_address = "127.0.0.1"
	port_pool.pool = make(map[uint16]bool)
	port_pool.m = new(sync.Mutex)
	onvmpoll.tables = sync.Map{}
	nf_pkt_handler_chan = make(chan ChannelData, 1024)
	// fourTuple_to_connID = make(map[[4]string]uint16)

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

// func GetConnID() uint16 {
// 	// TODO: Perhaps there is a sync issue in here.
// 	conn_id.m.Lock()
// 	defer conn_id.m.Unlock()
// 	var result uint16
// 	for {
// 		// Reserve conn_id = 0 to listener
// 		if conn_id.ID == listener_conn_id {
// 			conn_id.ID++
// 			continue
// 		}

// 		if _, isExist := onvmpoll.tables.Load(conn_id); !isExist {
// 			result = conn_id.ID
// 			conn_id.ID++
// 			break
// 		} else {
// 			logger.Log.Infof("ID:%d is used.", conn_id)
// 			conn_id.ID++
// 		}
// 	}

// 	return result
// }

func GetUnusedPort() uint16 {
	var base int32 = 49152
	var upper_limit int32 = 65536 - base
	var port uint16
	port_pool.m.Lock()
	defer port_pool.m.Unlock()
	for {
		n := rand.Int31n(upper_limit)
		port = uint16(base + n)
		if _, isExist := port_pool.pool[port]; !isExist {
			port_pool.pool[port] = true
			break
		} else {
			continue
		}
	}

	return port
}

func DeletePort(port uint16) error {
	if _, isExist := port_pool.pool[port]; !isExist {
		msg := fmt.Sprintf("Delete port fail, %d is not exist.", port)
		err := errors.New(msg)
		logger.Log.Errorf(msg)
		return err
	}
	delete(port_pool.pool, port)
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

// func GetPacketType(buf []byte) int {
// 	var pkt_type int

// 	if bytes.Equal(buf, []byte("SYN")) {
// 		pkt_type = ESTABLISH_CONN
// 	} else if bytes.Equal(buf, []byte("ACK")) {
// 		pkt_type = REPLY_CONN
// 	} else if bytes.Equal(buf, []byte("FIN")) {
// 		pkt_type = CLOSE_CONN
// 	} else {
// 		pkt_type = HTTP_FRAME
// 	}

// 	return pkt_type
// }

func EncodeTxChannelDataToBytes(tx_data ChannelData) []byte {
	// Encode TxChannelData to bytes
	logger.Log.Tracef("EncodeTxChannelDataToBytes, tx_data:%+v", tx_data)

	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	err := enc.Encode(tx_data)
	if err != nil {
		logger.Log.Errorf("EncodeTxChannelDataToBytes error:%+v", err)
	}

	return buf.Bytes()
}

func DecodeToRxChannelData(buf []byte) (ChannelData, error) {
	// Decode bytes to RxChannelData
	var rx_data ChannelData

	dec := gob.NewDecoder(bytes.NewReader(buf))
	err := dec.Decode(&rx_data)
	if err == nil {
		logger.Log.Tracef("DecodeToRxChannelData, rx_data:%+v", rx_data)
	}

	return rx_data, err
}

func SwapFourTuple(four_tuple [4]string) [4]string {
	var result [4]string

	result[SRC_IP_ADDR_IDX] = four_tuple[DST_IP_ADDR_IDX]
	result[SRC_PORT_IDX] = four_tuple[DST_PORT_IDX]
	result[DST_IP_ADDR_IDX] = four_tuple[SRC_IP_ADDR_IDX]
	result[DST_PORT_IDX] = four_tuple[SRC_PORT_IDX]

	return result
}

/*********************************
	Methods of OnvmPoll
*********************************/

func (onvmpoll *OnvmPoll) Create() *Connection {
	// Create a new connection with unique connection ID
	var conn Connection
	conn.rxchan = make(chan ChannelData, 1) // For non-blocking
	// conn.txchan = make(chan TxChannelData, 1) // For non-blocking
	// conn.conn_id = GetConnID()

	// Add the connection into the table
	// onvmpoll.Add(&conn)

	return &conn
}

func (onvmpoll *OnvmPoll) Add(conn *Connection) {
	// Add connection to connection table
	var four_tuple [4]string = SwapFourTuple(conn.four_tuple)

	onvmpoll.tables.Store(four_tuple, conn)

	if LOG_LEVEL >= 5 {
		onvmpoll.DebugFourTupleTable()
	}
}

func (onvmpoll *OnvmPoll) Delete(conn *Connection) error {
	// Delete the connection from connection and four-tuple tables
	if conn.is_txchan_closed && conn.is_rxchan_closed {
		var four_tuple [4]string = SwapFourTuple(conn.four_tuple)

		if _, isExist := onvmpoll.tables.Load(four_tuple); !isExist {
			msg := fmt.Sprintf("Delete connection from four-tuple fail, %v is not exsit", four_tuple)
			err := errors.New(msg)
			logger.Log.Errorln(msg)
			return err
		}

		onvmpoll.tables.Delete(four_tuple)

		logger.Log.Info("Close connection sucessfully.\n")
		if LOG_LEVEL >= 5 {
			onvmpoll.DebugConnectionTable()
		}
	}

	return nil
}

func (onvmpoll *OnvmPoll) GetConnByReverseFourTuple(four_tuple *[4]string) (*Connection, error) {
	swap_four_tuple := SwapFourTuple(*four_tuple)
	c, ok := onvmpoll.tables.Load(swap_four_tuple)

	if !ok {
		err := fmt.Errorf("GetConnByReverseFourTuple, Can not get connection via four-tuple %v", *four_tuple)

		return nil, err
	} else {
		conn, _ := c.(*Connection)

		return conn, nil
	}
}

// func (onvmpoll *OnvmPoll) AddEntryToTable(conn *Connection) {
// 	/* Add the connection to four-tuple table */
// 	var four_tuple [4]string = SwapFourTuple(conn.four_tuple)

// 	onvmpoll.tables.Store(four_tuple, conn)

// 	if LOG_LEVEL >= 5 {
// 		onvmpoll.DebugFourTupleTable()
// 	}
// }

// func (onvmpoll *OnvmPoll) DeleteEntryFromTable(conn *Connection) error {
// 	/* Delete the connection from four-tuple table */
// 	var four_tuple [4]string = SwapFourTuple(conn.four_tuple)

// 	if _, isExist := onvmpoll.tables.Load(four_tuple); !isExist {
// 		msg := fmt.Sprintf("Delete connection from four-tuple fail, %v is not exsit", four_tuple)
// 		err := errors.New(msg)
// 		logger.Log.Errorln(msg)
// 		return err
// 	}
// 	// delete(fourTuple_to_connID, conn.four_tuple)
// 	onvmpoll.tables.Delete(four_tuple)

// 	return nil
// }

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

func (onvmpoll OnvmPoll) DebugConnectionTable() {
	msg := "Connection Table:\n"

	onvmpoll.tables.Range(func(k, v interface{}) bool {
		if _, ok := k.(uint16); ok {
			msg += fmt.Sprintf("\tConnection ID: %v\n", k)
		}
		return true
	})

	logger.Log.Debugln(msg)
}

func (onvmpoll OnvmPoll) DebugFourTupleTable() {
	msg := "Connection and Four Tuple\n"

	onvmpoll.tables.Range(func(k, v interface{}) bool {
		if four_tuple, key_ok := k.([4]string); key_ok {
			if conn, val_ok := v.(*Connection); val_ok {
				msg += fmt.Sprintf("\tDst ID: %v\tFour Tuple: %v\n", conn.dst_id, four_tuple)
			}
		}
		return true
	})

	logger.Log.Debugln(msg)
}

func (onvmpoll *OnvmPoll) ReadFromONVM() {
	// This function receives the packet from NF's packet handler function
	// Then forward the packet to the HTTP server
	for rxData := range nf_pkt_handler_chan {
		switch rxData.PacketType {
		case ESTABLISH_CONN:
			// Deliver packet to litsener's connection
			// lc, ok := onvmpoll.tables.Load(*listener_four_tuple)
			// if !ok {
			// 	logger.Log.Errorf("ReadFromONVM, can not get connection via listener's four-tuple: %v\n", *listener_four_tuple)
			// } else {
			// 	listener_conn := lc.(*Connection)
			// 	listener_conn.rxchan <- rxData
			// 	// logger.Log.Tracef("ReadFromONVM, deliver packet to Conn ID: %v\n", listener_conn.conn_id)
			// }
			listener_conn, err := onvmpoll.GetConnByReverseFourTuple(listener_four_tuple)

			if err != nil {
				logger.Log.Errorln(err)
			} else {
				listener_conn.rxchan <- rxData
			}

		case CLOSE_CONN:
			// Let onvmpoller delete the connection
			c, ok := onvmpoll.tables.Load(rxData.FourTuple)
			if !ok {
				logger.Log.Errorf("ReadFromONVM, can not get the connection via four-tuple:%v\n", rxData.FourTuple)
			} else {
				conn := c.(*Connection)
				logger.Log.Infof("ReadFromONVM, close connection, four-tuple: %v\n", conn.four_tuple)
				close(conn.rxchan)
				conn.is_rxchan_closed = true
				onvmpoll.Delete(conn)
			}
		case REPLY_CONN, HTTP_FRAME:
			// TODO: REPLY_CONN may be removed
			c, ok := onvmpoll.tables.Load(rxData.FourTuple)
			if !ok {
				logger.Log.Errorf("ReadFromONVM, can not get the connection via four-tuple:%v\n", rxData.FourTuple)
			} else {
				conn := c.(*Connection)
				conn.rxchan <- rxData
				// logger.Log.Tracef("ReadFromONVM, deliver packet to Conn ID: %v\n", conn.conn_id)
			}
		default:
			logger.Log.Errorf("Unknown packet type: %v\n", rxData.PacketType)
		}
	}
}

func (onvmpoll *OnvmPoll) WriteToONVM(conn *Connection, tx_data ChannelData) {
	// Get destination NF ID
	logger.Log.Tracef("Four-tuple: %v, WriteToONVM()", conn.four_tuple)

	// id, _ := IpToID(conn.four_tuple[DST_IP_ADDR_IDX])
	dst_id := C.int(conn.dst_id)

	// Translate Go structure to C char *
	var buffer []byte
	var buffer_ptr *C.char

	buffer = EncodeTxChannelDataToBytes(tx_data)
	buffer_ptr = (*C.char)(C.CBytes(buffer))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, dst_id, buffer_ptr, C.int(len(buffer)))
}

// func (onvmpoll *OnvmPoll) Polling() {
// 	// The infinite loop checks each connection for unsent data
// 	for {
// 		onvmpoll.tables.Range(func(k, v interface{}) bool {
// 			if _, ok := k.(uint16); ok {
// 				conn := v.(*Connection)
// 				select {
// 				case txData, ok := <-conn.txchan:
// 					if ok {
// 						logger.Log.Tracef("Conn ID:%d, handle by Polling()", conn.conn_id)
// 						onvmpoll.WriteToONVM(conn, txData)
// 					}
// 				default:
// 				}
// 			}
// 			return true
// 		})
// 	}
// }

func (onvmpoll *OnvmPoll) Run() {
	go onvmpoll.ReadFromONVM()
	// go onvmpoll.Polling()
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

	// Receive packet from onvmpoller
	rx_data, ok := <-connection.rxchan

	if ok {
		// Get response
		var length int
		if len(b) < len(rx_data.Payload) {
			// TODO: Fix this problem
			logger.Log.Errorln("Read buffer length is not sufficient")
		} else {
			length = copy(b, rx_data.Payload)
		}

		return length, nil
	} else {
		err := fmt.Errorf("EOF")

		return 0, err
	}
}

// Write implements the net.Conn Write method.
func (connection Connection) Write(b []byte) (int, error) {
	logger.Log.Tracef("Start Connection.Write, four-tuple: %v", connection.four_tuple)

	// Encapuslate HttpTransaction into TxChannelData
	var tx_data ChannelData
	tx_data.PacketType = HTTP_FRAME
	tx_data.FourTuple = connection.four_tuple
	tx_data.Payload = make([]byte, len(b))
	copy(tx_data.Payload, b)

	// Send packet to onvmpoller via channel
	// connection.txchan <- tx_data
	dst_id := C.int(connection.dst_id)

	// Translate Go structure to C char *
	var buffer []byte
	var buffer_ptr *C.char

	buffer = EncodeTxChannelDataToBytes(tx_data)
	buffer_ptr = (*C.char)(C.CBytes(buffer))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, dst_id, buffer_ptr, C.int(len(buffer)))

	return len(b), nil
}

// For connection control message
func (connection Connection) WriteControlMessage(msg_type int) (int, error) {
	logger.Log.Tracef("Start Connection.Write, four-tuple: %v", connection.four_tuple)

	// Encapuslate HttpTransaction into TxChannelData
	var tx_data ChannelData
	tx_data.PacketType = msg_type
	tx_data.FourTuple = connection.four_tuple
	tx_data.Payload = MakeConnCtrlMsg(msg_type)

	// Send packet to onvmpoller via channel
	// connection.txchan <- tx_data
	dst_id := C.int(connection.dst_id)

	// Translate Go structure to C char *
	var buffer []byte
	var buffer_ptr *C.char

	buffer = EncodeTxChannelDataToBytes(tx_data)
	buffer_ptr = (*C.char)(C.CBytes(buffer))

	// Use CGO to call functions of NFLib
	C.onvm_send_pkt(nf_ctx, dst_id, buffer_ptr, C.int(len(buffer)))

	return len(tx_data.Payload), nil
}

// Close implements the net.Conn Close method.
func (connection Connection) Close() error {
	conn, err := onvmpoll.GetConnByReverseFourTuple(&connection.four_tuple)

	if err != nil {
		return err
	}

	logger.Log.Tracef("Close connection four-tuple: %v\n", conn.four_tuple)

	// Notify peer connection can be closed
	conn.WriteControlMessage(CLOSE_CONN)

	// Close local connection
	// close(conn.txchan)
	conn.is_txchan_closed = true
	err = onvmpoll.Delete(conn)

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

	logger.Log.Traceln("Receive one connection request")

	// Initialize the new connection
	new_conn = onvmpoll.Create()
	new_conn.four_tuple[SRC_IP_ADDR_IDX] = ol.laddr.ipv4_addr
	new_conn.four_tuple[SRC_PORT_IDX] = fmt.Sprint(ol.laddr.port)
	new_conn.four_tuple[DST_IP_ADDR_IDX] = rx_data.FourTuple[SRC_IP_ADDR_IDX]
	new_conn.four_tuple[DST_PORT_IDX] = rx_data.FourTuple[SRC_PORT_IDX]
	dst_id, _ := IpToID(rx_data.FourTuple[SRC_IP_ADDR_IDX])
	new_conn.dst_id = uint8(dst_id)

	// Add the connection to table
	// onvmpoll.AddEntryToTable(new_conn)
	onvmpoll.Add(new_conn)

	// Send ACK back to client
	_, err := new_conn.WriteControlMessage(REPLY_CONN)
	if err != nil {
		logger.Log.Errorln(err.Error())
		new_conn.Close()
		return new_conn, err
	} else {
		logger.Log.Tracef("Write connection response to (%v, %v)",
			new_conn.four_tuple[DST_IP_ADDR_IDX],
			new_conn.four_tuple[DST_PORT_IDX])
	}

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
	dst_id, _ := IpToID(ip_addr)
	conn.dst_id = uint8(dst_id)

	// Send connection request to server
	conn_response := make([]byte, 3)

	logger.Log.Traceln("Dial write connection create request")
	_, err := conn.WriteControlMessage(ESTABLISH_CONN)
	if err != nil {
		logger.Log.Errorln(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Tracef(fmt.Sprintf("Write connection request to (%v,%v)", ip_addr, port))
	}

	// Add the connection to table, otherwise it can't receive response
	// onvmpoll.AddEntryToTable(conn)
	onvmpoll.Add(conn)

	// Wait for response
	logger.Log.Traceln("Dial wait connection create response")
	_, err = conn.Read(conn_response)
	if err != nil {
		logger.Log.Errorln(err.Error())
		conn.Close()
		return conn, err
	} else {
		logger.Log.Traceln("Dial get connection create response")
	}

	return conn, nil
}

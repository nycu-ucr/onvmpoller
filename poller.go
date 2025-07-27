package onvmpoller

// #cgo CFLAGS: -m64 -pthread -O3 -march=native
// #cgo CFLAGS: -I/home/johnson/L25GC-plus/NFs/onvm-upf/onvm/onvm_nflib
// #cgo CFLAGS: -I/home/johnson/L25GC-plus/NFs/onvm-upf/onvm/lib
// #cgo CFLAGS: -I/usr/local/include/
// #cgo LDFLAGS: /home/johnson/L25GC-plus/NFs/onvm-upf/build/onvm/onvm_nflib/libonvm.a
// #cgo LDFLAGS: /home/johnson/L25GC-plus/NFs/onvm-upf/build/onvm/lib/libonvmhelper.a -lm
// #cgo LDFLAGS: -L/home/johnson/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/build/lib/
// #cgo LDFLAGS: -L/usr/local/lib -lrte_hash -lrte_mempool -lrte_eal -lrte_log -lrte_ring -lrte_ethdev
/*
#include <onvm_nflib.h>
#include "xio.h"

struct mbuf_list;
struct ipv4_4tuple;
struct xio_socket;

extern int onvm_init(struct onvm_nf_local_ctx **nf_local_ctx, char *nfName);
extern int payload_assemble(uint8_t *buffer_ptr, int buff_cap, struct mbuf_list *pkt_list, int start_offset, uint8_t protocol);
extern int onvm_send_pkt(struct onvm_nf_local_ctx *ctx, int service_id, int pkt_type,
                uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint8_t protocol,
                char *buffer, int buffer_length);
extern int xio_write(struct xio_socket *xs, uint8_t *buffer, int buffer_length, int *error_code);
extern int xio_read(struct xio_socket *xs, uint8_t *buffer, int buffer_length, int *error_code, uint8_t protocol, uint32_t *remote_ip, uint16_t *remote_port);
extern int xio_close(struct xio_socket *xs, int *error_code, uint8_t protocol);
extern struct xio_socket *xio_connect(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *sem, int *error_code);
extern struct xio_socket *xio_accept(struct xio_socket *listener, char *sem, int *error_code);
extern struct xio_socket *xio_listen(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *complete_chan_ptr, int *error_code);

extern struct xio_socket *xio_new_udp_socket(uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, char *sem);
extern int xio_write_udp(struct xio_socket *xs, uint8_t *buffer, int buffer_length, uint32_t remote_ip, uint16_t remote_port);

extern int trigger_paging(int service_id, uint32_t src_ip, uint32_t dst_ip);
*/
import "C"

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	BIG_FRAME      = 4
	// Port manager setting
	PM_CHANNEL_SIZE = 1024
	// Logger level
	LOG_LEVEL = logrus.WarnLevel
	// Error code
	END_OF_PKT = 87
	// Protocol Number
	UDP_PROTO_NUM = 0x11
	TCP_PROTO_NUM = 0x06
)

type Config struct {
	// Map the IP address to Service ID
	IPIDMap map[string]int32 `yaml:"IPIDMap,omitempty"`
}

type NFip struct {
	// Map the NF to IP address
	Map map[string]string `yaml:"NFIPMap,omitempty"`
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

// XIO UDP Connection
type UDP_Connection struct {
	xio_socket *C.struct_xio_socket
	four_tuple Four_tuple_rte
	sync_chan  *sema
	dst_id     uint8
}

// XIO TCP Connection
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

type Four_tuple_rte struct {
	Src_ip   uint32
	Src_port uint16
	Dst_ip   uint32
	Dst_port uint16
}

type OnvmAddr struct {
	service_id uint8 // Service ID of NF
	network    string
	ipv4_addr  string
	port       uint16
}

type PortManager struct {
	pool            map[uint16]bool
	get_port_ch     chan uint16
	release_port_ch chan uint16
}

/* Global Variables */
var (
	config        Config
	nfIP          NFip
	local_address string
	nf_ctx        *C.struct_onvm_nf_local_ctx
	xio_listener  *XIO_Listener
	port_manager  *PortManager
)

func init() {
	/* Initialize Global Variable */
	init_config()

	port_manager = &PortManager{
		pool:            make(map[uint16]bool),
		get_port_ch:     make(chan uint16, PM_CHANNEL_SIZE),
		release_port_ch: make(chan uint16, PM_CHANNEL_SIZE),
	}

	/* Setup Logger */
	logger.SetLogLevel(LOG_LEVEL)

	/* Parse NF Name */
	NfName := os.Getenv("NF_NAME")
	if NfName == "" {
		logger.Log.Warnln("Unable to get NF_NAME from env var.")
	} else {
		NfName = strings.ToLower(NfName)
	}
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
	logger.Log.Warnln("Init onvmpoller (XIO-refactor version)")
}

func runOnvmPoller() {
	go C.onvm_nflib_run(nf_ctx)
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

func TriggerPaging(service_id int, src_ip string, dst_ip string) {
	C.trigger_paging(C.int(service_id), C.uint32_t(inet_addr(src_ip)), C.uint32_t(inet_addr(dst_ip)))
}

/*********************************

	     Hepler functions

*********************************/

func init_config() {
	var ipid_fname string = os.Getenv("ONVMPOLLER_IPID_YAML")
	var nfip_fname string = os.Getenv("ONVMPOLLER_NFIP_YAML")

	if ipid_fname == "" {
		logger.Log.Panicln("Config file (ipid.yaml) is not exist")
	}
	if nfip_fname == "" {
		logger.Log.Panicln("Config file (NFip.yaml) is not exist")
	}

	logger.Log.Infof("Config file (ipid.yaml) is %s\n", ipid_fname)
	logger.Log.Infof("Config file (NFip.yaml) is %s\n", nfip_fname)

	// Read and decode the yaml content
	if yaml_content, err := os.ReadFile(ipid_fname); err != nil {
		panic(err)
	} else {
		if unMarshalErr := yaml.Unmarshal(yaml_content, &config); unMarshalErr != nil {
			panic(unMarshalErr)
		}
	}

	// Read and decode the yaml content
	if yaml_content, err := os.ReadFile(nfip_fname); err != nil {
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

func unMarshalIP(ip uint32) string {
	ipInt := int64(ip)
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((ipInt & 0xff), 10)
	return b3 + "." + b2 + "." + b1 + "." + b0
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

/*********************************

	Methods of packet handling

*********************************/

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

func TimeTrack(start time.Time) {
	elapsed := time.Since(start)

	// Skip this function, and fetch the PC and file for its parent.
	pc, _, _, _ := runtime.Caller(1)

	// Retrieve a function object this functions parent.
	funcObj := runtime.FuncForPC(pc)

	// Regex to extract just the function name (and not the module path).
	runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
	name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")

	logger.Log.Infoln((fmt.Sprintf("%s took %d(ns)", name, elapsed.Nanoseconds())))
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

	API for HTTP Server

********************************
*/

func DialONVM(network, address string) (net.Conn, error) {
	logger.Log.Panicln("ListenONVM is no loger used, use ListenXIO instead")

	return nil, nil
}

func ListenONVM(network, address string) (net.Listener, error) {
	logger.Log.Panicln("ListenONVM is no loger used, use ListenXIO instead")

	return nil, nil
}

func ListenXIO_UDP(network string, address *net.UDPAddr) (*UDP_Connection, error) {
	logger.Log.Traceln("Start ListenXIO_UDP")
	logger.Log.Debugf("Listen at %s", address.String())

	ip_addr := address.IP.String()
	port := uint16(address.Port)
	local_address = ip_addr

	// Initialize a connection
	var udp_conn UDP_Connection

	udp_conn.four_tuple.Src_ip = inet_addr(ip_addr)
	udp_conn.four_tuple.Src_port = port
	udp_conn.four_tuple.Dst_ip = 0
	udp_conn.four_tuple.Dst_port = 0

	condVar := newSema()
	condVarPtr := (*C.char)(unsafe.Pointer(condVar))
	udp_conn.sync_chan = condVar

	// Create udp socket in C
	xs := C.xio_new_udp_socket(C.uint32_t(udp_conn.four_tuple.Src_ip), C.uint16_t(udp_conn.four_tuple.Src_port),
		C.uint32_t(udp_conn.four_tuple.Dst_ip), C.uint16_t(udp_conn.four_tuple.Dst_port), condVarPtr)

	udp_conn.xio_socket = xs

	if udp_conn.xio_socket == nil {
		err := fmt.Errorf("[ListenXIO_UDP] Create udp socket failed")
		udp_conn.Close()

		return &udp_conn, err
	}

	return &udp_conn, nil
}

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

	logger.Log.Debugln("DialXIO done")
	// logger.Log.Warnf("[Dial] srcIP:%s, srcPort:%d, dstIP:%s, dstPort:%d",
	// 	unMarshalIP(conn.four_tuple.Src_ip), conn.four_tuple.Src_port,
	// 	unMarshalIP(conn.four_tuple.Dst_ip), conn.four_tuple.Dst_port)

	return conn, nil
}

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
		ret := C.xio_read(connection.xio_socket, buffer_ptr, C.int(buffer_len), err_code_ptr, TCP_PROTO_NUM, nil, nil)
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

	ret := C.xio_close(connection.xio_socket, nil, TCP_PROTO_NUM)
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

/*
********************************

	API for UDP connection

********************************
*/

func (udp_conn *UDP_Connection) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start UDP_Connection.WriteTo, four-tuple: %v\tremote: %v", udp_conn.four_tuple, addr.String())
	logger.Log.Debugf("Write %d data.", len(b))

	var length int
	var err error

	buffer_len := len(b)
	buffer_ptr := (*C.uint8_t)(unsafe.Pointer(&b[0]))
	remote_ip := C.uint32_t(inet_addr(addr.IP.String()))
	remote_port := C.uint16_t(addr.Port)

	ret := C.xio_write_udp(udp_conn.xio_socket, buffer_ptr, C.int(buffer_len), remote_ip, remote_port)
	length = int(ret)
	if length < 0 {
		err = fmt.Errorf("xio_write_udp error")
		return 0, err
	}

	runtime.KeepAlive(b)

	return length, nil
}

func (udp_conn *UDP_Connection) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	// defer TimeTrack(time.Now())
	logger.Log.Tracef("Start UDP_Connection.ReadFrom, four-tuple: %v, buffer (len, cap) = (%v, %v)", udp_conn.four_tuple, len(b), cap(b))

	var length int
	var err error
	var remote_ip uint32
	var remote_port uint16

	remote_ip_ptr := (*C.uint32_t)(unsafe.Pointer(&remote_ip))
	remote_port_ptr := (*C.uint16_t)(unsafe.Pointer(&remote_port))

	buffer_len := len(b)
	buffer_ptr := (*C.uint8_t)(unsafe.Pointer(&b[0]))

	err_code := 0
	err_code_ptr := (*C.int)(unsafe.Pointer(&err_code))
	for {
		err_code = 0
		ret := C.xio_read(udp_conn.xio_socket, buffer_ptr, C.int(buffer_len), err_code_ptr, UDP_PROTO_NUM, remote_ip_ptr, remote_port_ptr)
		length = int(ret)

		if err_code == int(syscall.EAGAIN) {
			// Wait for pkt
			ok := udp_conn.sync_chan.wait()
			runtime.KeepAlive(udp_conn.sync_chan)
			// logger.Log.Warnf("Reader wake-up")
			if ok {
				/* Socket closed */
				return 0, nil, io.EOF
			}
			continue
		} else if err_code == END_OF_PKT {
			err = errors.New("EOP")
			break
		} else if err_code != 0 {
			err := fmt.Errorf("Read: xio_read errno=%d", err_code)
			return 0, nil, err
		} else {
			break
		}
	}

	runtime.KeepAlive(b)

	udp_addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", unMarshalIP(remote_ip), remote_port))
	if err != nil {
		return 0, nil, err
	}

	return length, udp_addr, err
}

func (udp_conn *UDP_Connection) Close() error {
	var err error

	logger.Log.Tracef("Close UDP connection four-tuple: %v\n", udp_conn.four_tuple)

	ret := C.xio_close(udp_conn.xio_socket, nil, UDP_PROTO_NUM)
	if int(ret) == -1 {
		err = fmt.Errorf("xio_close failed")
	}

	return err
}

func (udp_conn *UDP_Connection) LocalAddr() *net.UDPAddr {
	udp_addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", unMarshalIP(udp_conn.four_tuple.Src_ip), udp_conn.four_tuple.Src_port))
	if err != nil {
		logger.Log.Error(err.Error())
	}

	return udp_addr
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

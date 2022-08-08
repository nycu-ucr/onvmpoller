package onvmpoller

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	// For Connection.state
	CONN_NULL          = 0
	CONN_READY_TO_SEND = 1
	CONN_READY_TO_RECV = 2
	CONN_READY_TO_BOTH = 3
	// For four_tuple
	SRC_IP_ADDR_IDX = 0
	SRC_PORT_IDX    = 1
	DST_IP_ADDR_IDX = 2
	DST_PORT_IDX    = 3
)

type Config struct {
	// Map the IP address to Service ID
	IPIDMap []struct {
		IP string `yaml:"IP"`
		ID int32  `yaml:"ID"`
	} `yaml:"IPIDMap"`
}

type HttpTransaction struct {
	four_tuple  [4]string
	http_packet []byte
}

type RxChannelData struct {
	transaction HttpTransaction
}

type TxChannelData struct {
	transaction HttpTransaction
}

type Connection struct {
	rxchan     chan (RxChannelData)
	txchan     chan (TxChannelData)
	src_nf     uint8 // Source NF Service ID
	dst_nf     uint8 // Destination NF Service ID
	conn_id    uint16
	state      uint8
	four_tuple [4]string
}

type OnvmListener struct {
	laddr OnvmAddr   // Local Address
	conn  Connection // This need to handle the incoming connection
}

type OnvmAddr struct {
	srevice_id uint8 // Service ID of NF
	network    string
	ipv4_addr  string
	port       uint16
}

type OnvmPoll struct {
	conn_table map[uint16]Connection // Connection_ID: Connection
	ready_list []uint16              // Store the connections ready to i/o
}

/* Global Variables */
var (
	config              Config
	conn_id             uint16
	onvmpoll            OnvmPoll
	nf_pkt_handler_chan chan (RxChannelData) // data type may change to pointer to buffer
	fourTuple_to_connID map[[4]string]uint16 // TODO: sync.Map or cmap
)

func init() {
	/* Initialize Global Variable */
	InitConfig()
	conn_id = 0
	onvmpoll.conn_table = make(map[uint16]Connection)
	onvmpoll.ready_list = make([]uint16, 0)
	nf_pkt_handler_chan = make(chan RxChannelData)
	fourTuple_to_connID = make(map[[4]string]uint16)

	/* Setup Logger */
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
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
	for {
		if _, isExist := onvmpoll.conn_table[conn_id]; !isExist {
			r := conn_id
			conn_id++
			return r
		} else {
			logrus.Info(conn_id, " ID is used.")
			conn_id++
		}
	}
}

func AddEntryToTable(conn Connection) {
	/* Add the connection to fourTuple_to_connID table */
	fourTuple_to_connID[conn.four_tuple] = conn.conn_id
}

func IpToID(ip string) (id int32, err error) {
	id = -1
	for i := range config.IPIDMap {
		if config.IPIDMap[i].IP == ip {
			id = int32(config.IPIDMap[i].ID)
			break
		}
	}
	if id == -1 {
		err = fmt.Errorf("no match id")
	}
	return
}

/*********************************
	Methods of OnvmPoll
*********************************/
// TODO: what parameters should Create need?
func (onvmpoll *OnvmPoll) Create() Connection {
	// Create a new connection with unique connection ID
	var conn Connection
	conn.state = CONN_NULL
	conn.rxchan = make(chan RxChannelData)
	conn.txchan = make(chan TxChannelData)
	conn.conn_id = GetConnID()

	// Add the connection into the table
	onvmpoll.conn_table[conn.conn_id] = conn

	return conn
}

func (onvmpoll *OnvmPoll) Add(id uint16, conn Connection) bool {
	if _, isExist := onvmpoll.conn_table[id]; !isExist {
		logrus.Debug("Add a connection to table")
		onvmpoll.conn_table[id] = conn
		return true
	}
	logrus.Fatal("Fail to add a connection to table")
	return false
}

func (onvmpoll *OnvmPoll) Delete(id uint16) error {
	if _, isExist := onvmpoll.conn_table[id]; !isExist {
		msg := fmt.Sprintf("This connID, %v, is not exist", id)
		err := errors.New(msg)
		logrus.Fatal(msg)
		return err
	}
	delete(onvmpoll.conn_table, id)
	return nil
}

func (onvmpoll OnvmPoll) String() string {
	result := "OnvmPoll has following connections:\n"
	for key, _ := range onvmpoll.conn_table {
		result += fmt.Sprintf("\tConnection ID: %d\n", key)
	}

	return result
}

func (onvmpoll *OnvmPoll) RecvFromONVM() {
	// This function receives the packet from NF's packet handler function
	// Then forward the packet to the HTTP server
	for rxData := range nf_pkt_handler_chan {
		conn_id := fourTuple_to_connID[rxData.transaction.four_tuple]
		conn := onvmpoll.conn_table[conn_id]
		conn.rxchan <- rxData
	}
}

func (onvmpoll *OnvmPoll) SendToONVM(id uint16, data TxChannelData) {
	// conn := onvmpoll.conn_table[id]

	// TODO: Use CGO to call functions of NFLib

}

// TODO: Check logic
func (onvmpoll OnvmPoll) polling() {
	// GoRoutint for receiving packet from pakcet handler
	go onvmpoll.RecvFromONVM()

	// Infinite loop checks ecah connection's state
	for {
		for conn_id, conn := range onvmpoll.conn_table {
			if conn.state == CONN_READY_TO_SEND {
				txData := <-conn.txchan
				onvmpoll.SendToONVM(conn_id, txData)
				conn.state = CONN_NULL
			} else if conn.state == CONN_READY_TO_BOTH {
				txData := <-conn.txchan
				onvmpoll.SendToONVM(conn_id, txData)
				conn.state = CONN_READY_TO_RECV
			}
		}
	}
}

/*********************************
	Methods of OnvmAddr
*********************************/
func (oa OnvmAddr) Network() string {
	return oa.network
}

func (oa OnvmAddr) String() string {
	s := fmt.Sprintf("Network: %s, Service ID: %2d, IP Address: %s, Port: %5d.")
	return s
}

/*********************************
	Methods of Connection
*********************************/
// Read implements the net.Conn Read method.
func (connection *Connection) Read(b []byte) (n int, err error) {

}

// Write implements the net.Conn Write method.
func (connection *Connection) Write(b []byte) (n int, err error) {

}

// Close implements the net.Conn Close method.
func (connection *Connection) Close() error {
	err := onvmpoll.Delete(connection.conn_id)
	return err
}

// LocalAddr implements the net.Conn LocalAddr method.
func (connection Connection) LocalAddr() OnvmAddr {
	var oa OnvmAddr
	v, _ := strconv.ParseUint(connection.four_tuple[SRC_PORT_IDX], 10, 64)
	oa.ipv4_addr = connection.four_tuple[SRC_IP_ADDR_IDX]
	oa.port = uint16(v)
	oa.network = "onvm"
	//oa.srevice_id = TODO

	return oa
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (connection Connection) RemoteAddr() OnvmAddr {
	var oa OnvmAddr
	v, _ := strconv.ParseUint(connection.four_tuple[DST_PORT_IDX], 10, 64)
	oa.ipv4_addr = connection.four_tuple[DST_IP_ADDR_IDX]
	oa.port = uint16(v)
	oa.network = "onvm"
	//oa.srevice_id = TODO

	return oa
}

// SetDeadline implements the net.Conn SetDeadline method.
func (connection *Connection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (connection *Connection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (connection *Connection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (connection *Connection) Send(data HttpTransaction) {
	txData := TxChannelData{transaction: data}
	connection.txchan <- txData

	if connection.state == CONN_READY_TO_RECV {
		connection.state = CONN_READY_TO_BOTH
	} else {
		connection.state = CONN_READY_TO_SEND
	}
}

func (connection *Connection) Recv() HttpTransaction {
	connection.state = CONN_READY_TO_RECV
	rxData := <-connection.rxchan

	return rxData.transaction
}

/*********************************
	Methods of OnvmListner
*********************************/

func (ol OnvmListener) Accept() (Connection, error) {
	rx_data := <-ol.conn.rxchan // Payload is our defined connection request, not HTTP payload
	// Create a new connection
	new_conn := onvmpoll.Create()
	new_conn.four_tuple[SRC_IP_ADDR_IDX] = ol.laddr.ipv4_addr
	new_conn.four_tuple[SRC_PORT_IDX] = string(ol.laddr.port)
	new_conn.four_tuple[DST_IP_ADDR_IDX] = rx_data.transaction.four_tuple[SRC_IP_ADDR_IDX]
	new_conn.four_tuple[DST_PORT_IDX] = rx_data.transaction.four_tuple[SRC_PORT_IDX]
	// Add the connection to table
	AddEntryToTable(new_conn)
	// TODO: Should we send the ACK back to client?

	return new_conn, nil
}

func (ol OnvmListener) Close() error {
	err := ol.conn.Close()
	return err
}

func (ol OnvmListener) Addr() OnvmAddr {
	return ol.laddr
}

/*********************************
	API for HTTP Server
*********************************/
func CreateConnection() Connection {
	conn := onvmpoll.Create()
	return conn
}

func ListenONVM(network, address string) (OnvmListener, error) {
	var ol OnvmListener
	if network != "onvm" {
		err := errors.New(fmt.Sprintf("Unsppourt network type: %v", network))
		return ol, err
	}
	addr := strings.Split(address, ":")
	v, _ := strconv.ParseUint(addr[1], 10, 64)
	ip_addr, port := addr[0], uint16(v)

	/* Initialize OnvmListener */
	ol.conn = onvmpoll.Create()
	ol.laddr.port = port
	ol.laddr.network = network
	ol.laddr.ipv4_addr = ip_addr
	// ol.laddr.srevice_id = TODO

	return ol, nil
}

func DialONVM(service_id uint8, ip_addr string, port uint16) (Connection, error) {

}

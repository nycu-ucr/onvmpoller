package onvmpoller

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
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
	conn_id    uint16
	rxchan     chan (RxChannelData)
	txchan     chan (TxChannelData)
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
	port_poll           map[uint16]bool      // The ports range from 49152 to 65535
	nf_pkt_handler_chan chan (RxChannelData) // data type may change to pointer to buffer
	fourTuple_to_connID map[[4]string]uint16 // TODO: sync.Map or cmap
)

func init() {
	/* Initialize Global Variable */
	InitConfig()
	conn_id = 0
	port_poll = make(map[uint16]bool)
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

func GetUnusedPort() uint16 {
	var base int32 = 49152
	var upper_limit int32 = 65536 - base
	var port uint16

	for {
		n := rand.Int31n(upper_limit)
		port = uint16(base + n)
		if _, isExist := port_poll[port]; !isExist {
			port_poll[port] = true
			break
		} else {
			continue
		}
	}

	return port
}

func DeletePort(port uint16) error {
	if _, isExist := port_poll[port]; !isExist {
		msg := fmt.Sprintf("Delete port fail, %d is not exist.", port)
		err := errors.New(msg)
		logrus.Fatal(msg)
		return err
	}
	delete(port_poll, port)
	return nil
}

func AddEntryToTable(conn Connection) {
	/* Add the connection to fourTuple_to_connID table */
	fourTuple_to_connID[conn.four_tuple] = conn.conn_id
}

func DeleteEntryFromTable(conn Connection) error {
	/* Delete the connection from fourTuple_to_connID table */
	if _, isExist := fourTuple_to_connID[conn.four_tuple]; !isExist {
		msg := fmt.Sprintf("Delete connection from fourTuple_to_connID fail, %v is not exsit", conn.four_tuple)
		err := errors.New(msg)
		logrus.Fatal(msg)
		return err
	}
	delete(fourTuple_to_connID, conn.four_tuple)

	return nil
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

func ParseAddress(address string) (string, uint16) {
	addr := strings.Split(address, ":")
	v, _ := strconv.ParseUint(addr[1], 10, 64)
	ip_addr, port := addr[0], uint16(v)

	return ip_addr, port
}

func MakeConnectionRequest(buf []byte) {
	req := []byte("SYN")
	copy(buf, req)
}

func MakeConnectionResponse(buf []byte) {
	res := []byte("ACK")
	copy(buf, res)
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

	conn := onvmpoll.conn_table[id]
	DeleteEntryFromTable(conn)
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
	s := fmt.Sprintf("Network: %s, Service ID: %2d, IP Address: %s, Port: %5d.", oa.network, oa.srevice_id, oa.ipv4_addr, oa.port)
	return s
}

/*********************************
	Methods of Connection
*********************************/
// Read implements the net.Conn Read method.
func (connection *Connection) Read(b []byte) (int, error) {
	// Receive packet from onvmpoller
	if connection.state == CONN_READY_TO_SEND {
		connection.state = CONN_READY_TO_BOTH
	} else {
		connection.state = CONN_READY_TO_RECV
	}
	rx_data := <-connection.rxchan

	// Get response
	copy(b, rx_data.transaction.http_packet)

	return len(b), nil
}

// Write implements the net.Conn Write method.
func (connection *Connection) Write(b []byte) (int, error) {
	// Encapsulate buffer into HttpTransaction
	var ht HttpTransaction
	ht.four_tuple = connection.four_tuple
	copy(ht.http_packet, b)

	// Encapuslate HttpTransaction into TxChannelData
	var tx_data TxChannelData
	tx_data.transaction = ht

	// Send packet to onvmpoller via channel
	connection.txchan <- tx_data

	if connection.state == CONN_READY_TO_RECV {
		connection.state = CONN_READY_TO_BOTH
	} else {
		connection.state = CONN_READY_TO_SEND
	}

	return len(b), nil
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

/*********************************
	Methods of OnvmListner
*********************************/

func (ol OnvmListener) Accept() (Connection, error) {
	var new_conn Connection

	rx_data := <-ol.conn.rxchan // Payload is our defined connection request, not HTTP payload

	if !bytes.Equal([]byte("SYN"), rx_data.transaction.http_packet) {
		msg := fmt.Sprintf("Payload is not SYN, is %v", rx_data.transaction.http_packet)
		err := errors.New(msg)
		logrus.Fatal(msg)
		return new_conn, err
	}

	// Initialize the new connection
	new_conn = onvmpoll.Create()
	new_conn.four_tuple[SRC_IP_ADDR_IDX] = ol.laddr.ipv4_addr
	new_conn.four_tuple[SRC_PORT_IDX] = fmt.Sprint(ol.laddr.port)
	new_conn.four_tuple[DST_IP_ADDR_IDX] = rx_data.transaction.four_tuple[SRC_IP_ADDR_IDX]
	new_conn.four_tuple[DST_PORT_IDX] = rx_data.transaction.four_tuple[SRC_PORT_IDX]

	// Send ACK back to client
	var conn_response []byte
	MakeConnectionResponse(conn_response)
	_, err := new_conn.Write(conn_response)
	if err != nil {
		logrus.Fatal(err.Error())
		new_conn.Close()
		return new_conn, err
	}

	// Add the connection to table
	AddEntryToTable(new_conn)

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
		msg := fmt.Sprintf("Unsppourt network type: %v", network)
		err := errors.New(msg)
		return ol, err
	}
	ip_addr, port := ParseAddress(address)

	/* Initialize OnvmListener */
	ol.conn = onvmpoll.Create()
	ol.conn.four_tuple[SRC_IP_ADDR_IDX] = ip_addr
	ol.conn.four_tuple[SRC_PORT_IDX] = fmt.Sprint(port)
	ol.laddr.port = port
	ol.laddr.network = network
	ol.laddr.ipv4_addr = ip_addr
	// ol.laddr.srevice_id = TODO

	return ol, nil
}

func DialONVM(network, address string) (Connection, error) {
	ip_addr, port := ParseAddress(address)

	// Initialize a connection
	conn := onvmpoll.Create()
	// conn.four_tuple[SRC_IP_ADDR_IDX] = TODO
	conn.four_tuple[SRC_PORT_IDX] = fmt.Sprint(GetUnusedPort())
	conn.four_tuple[DST_IP_ADDR_IDX] = ip_addr
	conn.four_tuple[DST_PORT_IDX] = fmt.Sprint(port)

	// Send connection request to server
	var conn_request, conn_response []byte
	MakeConnectionRequest(conn_request)
	_, err := conn.Write(conn_request)
	if err != nil {
		logrus.Fatal(err.Error())
		conn.Close()
		return conn, err
	}

	// Add the connection to table, otherwise it can't receive response
	AddEntryToTable(conn)

	// Wait for response
	_, err = conn.Read(conn_response)
	if err != nil {
		logrus.Fatal(err.Error())
		conn.Close()
		return conn, err
	}

	return conn, nil
}

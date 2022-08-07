package onvmpoller

import (
	"fmt"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// For Connection.state
	CONN_NULL          = 0
	CONN_READY_TO_SEND = 1
	CONN_READY_TO_RECV = 2
	CONN_READY_TO_BOTH = 3
	// For four_tuple
	SRC_IP_ADDR_IDX = 0
	SRC_IP_PORT_IDX = 1
	DST_IP_ADDR_IDX = 2
	DST_IP_PORT_IDX = 3
)

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

type OnvmListner struct {
	// TODO
}

type OnvmAddr struct {
	srevice_id uint8 // Service ID of NF
	ipv4_addr  string
	port       uint16
}

type OnvmPoll struct {
	conn_table map[uint16]Connection // Connection_ID: Connection
	ready_list []uint16              // Store the connections ready to i/o
}

/* Global Variables */
var (
	conn_id             uint16
	onvmpoll            OnvmPoll
	nf_pkt_handler_chan chan (RxChannelData) // data type may change to pointer to buffer
	fourTuple_to_connID map[[4]string]uint16 // TODO: sync.Map or cmap
)

func init() {
	/* Initialize Global Variable */
	conn_id = 0
	onvmpoll.conn_table = make(map[uint16]Connection)
	onvmpoll.ready_list = make([]uint16, 0)
	nf_pkt_handler_chan = make(chan RxChannelData)
	fourTuple_to_connID = make(map[[4]string]uint16)

	/* Setup Logger */
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

/*********************************
	Methods of OnvmPoll
*********************************/
// TODO: what parameters should Create need?
func (onvmpoll *OnvmPoll) Create() Connection {
	var conn Connection
	for {
		if _, isExist := onvmpoll.conn_table[conn_id]; !isExist {
			// Create a new connection with unique connection ID
			conn.rxchan = make(chan RxChannelData)
			conn.txchan = make(chan TxChannelData)
			conn.conn_id = conn_id
			conn.state = CONN_NULL
			conn_id++
			logrus.Debug("Create a connection with ID: ", conn.conn_id)
			break
		} else {
			logrus.Info(conn_id, " ID is used.")
			conn_id++
		}
	}
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

func (onvmpoll *OnvmPoll) Delete(id uint16) bool {
	if _, isExist := onvmpoll.conn_table[id]; !isExist {
		logrus.Fatal(id, " is not exist")
		return false
	}
	delete(onvmpoll.conn_table, id)
	return true
}

func (onvmpoll OnvmPoll) String() string {
	result := "OnvmPoll has following connections:\n"
	for key, _ := range onvmpoll.conn_table {
		result += "\tConnection ID: " + strconv.Itoa(int(key)) + "\n"
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
	return "onvm"
}

func (oa OnvmAddr) String() string {
	s := fmt.Sprintf("Service ID: %2d, IP Address: %s, Port: %5d.")
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
	onvmpoll.Delete(connection.conn_id)
	return nil
}

// LocalAddr implements the net.Conn LocalAddr method.
func (connection Connection) LocalAddr() OnvmAddr {

}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (connection Connection) RemoteAddr() OnvmAddr {

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
	API for HTTP Server
*********************************/
func CreateConnection() Connection {
	conn := onvmpoll.Create()
	return conn
}

func ListenONVM() (OnvmListner, error) {

}

func (ol OnvmListner) AcceptONVM() (Connection, error) {

}

func DialONVM(service_id uint8, ip_addr string, port uint16) (Connection, error) {

}

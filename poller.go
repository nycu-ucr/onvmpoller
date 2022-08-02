package onvmpoller

import (
	"strconv"

	"github.com/sirupsen/logrus"
)

const (
	CONN_NULL          = 0
	CONN_READY_TO_SEND = 1
	CONN_READY_TO_RECV = 2
	CONN_READY_TO_BOTH = 3
)

type HttpTransaction struct {
	streamID   uint32
	src_nf     uint8  // Source NF Service ID
	dst_nf     uint8  // Destination NF Service ID
	nf_handler string // Handle this transaction
	request    string
	response   string
}

type RxChannelData struct {
	transaction HttpTransaction
}

type TxChannelData struct {
	transaction HttpTransaction
}

type Connection struct {
	rxchan  chan (RxChannelData)
	txchan  chan (TxChannelData)
	conn_id uint16
	state   uint8
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
	streamID_to_connID  map[uint32]uint16
)

func init() {
	/* Initialize Global Variable */
	conn_id = 0
	onvmpoll.conn_table = make(map[uint16]Connection)
	onvmpoll.ready_list = make([]uint16, 0)
	nf_pkt_handler_chan = make(chan RxChannelData)
	streamID_to_connID = make(map[uint32]uint16)

	/* Setup Logger */
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

/* Methods of OnvmPoll */
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
		conn_id := streamID_to_connID[rxData.transaction.streamID]
		conn := onvmpoll.conn_table[conn_id]
		conn.rxchan <- rxData
	}
}

func (onvmpoll *OnvmPoll) SendToONVM(id uint16, data TxChannelData) {
	// conn := onvmpoll.conn_table[id]

	// TODO: Use CGO to call functions of NFLib

}

func (onvmpoll OnvmPoll) polling() {
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

/* Methods of Connection */
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

func (connection *Connection) Close() {
	onvmpoll.Delete(connection.conn_id)
}

/* API for HTTP Server */
func CreateConnection() Connection {
	conn := onvmpoll.Create()
	return conn
}

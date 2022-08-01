package onvmpoller

import (
	"strconv"

	"github.com/sirupsen/logrus"
)

type HttpTransaction struct {
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
}

type OnvmPoll struct {
	conn_table map[uint16]Connection // Connection_ID: Connection
	ready_list []uint16              // Store the connections ready to i/o
}

var (
	conn_id  uint16
	onvmpoll OnvmPoll
)

func init() {
	/* Initialize Global Variable */
	conn_id = 0
	onvmpoll.conn_table = make(map[uint16]Connection)
	onvmpoll.ready_list = make([]uint16, 0)

	/* Setup Logger */
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func (onvmpoll *OnvmPoll) Create() Connection {
	var conn Connection
	for {
		if _, isExist := onvmpoll.conn_table[conn_id]; !isExist {
			// Create a new connection with unique connection ID
			conn.rxchan = make(chan RxChannelData)
			conn.txchan = make(chan TxChannelData)
			conn.conn_id = conn_id
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

/*
TODO
func (onvmpoll *OnvmPoll) FindExecutable() {}

func (connection *Connection) Send(data TxChannelData) bool {}

func (connection *Connection) Recv() RxChannelData {}
*/

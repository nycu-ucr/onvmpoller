package onvmpoller

import (
	"fmt"
	"net"
)

func listen(ip_addr string, port uint16) (net.Listener, error) {
	var l net.Listener
	var err error
	l, err = listenONVM(ip_addr, port)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func listenONVM(ip_addr string, port uint16) (*OnvmListener, error) {
	c := &Connection{
		// conn_id: listener_conn_id,
		rxchan: make(chan ChannelData, 1),
		// txchan:  make(chan TxChannelData, 1),
		four_tuple: fmt.Sprintf("%s,%s,%s,%s", ip_addr, fmt.Sprint(port), "", 0),
	}
	listener_four_tuple = &c.four_tuple
	onvmpoll.Add(c)

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

	return &OnvmListener{laddr: laddr, conn: c}, nil
}

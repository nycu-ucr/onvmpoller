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
		rxchan: make(chan RxChannelData, 1),
		// txchan:  make(chan TxChannelData, 1),
	}
	c.four_tuple[SRC_IP_ADDR_IDX] = ip_addr
	c.four_tuple[SRC_PORT_IDX] = fmt.Sprint(port)
	c.four_tuple[DST_IP_ADDR_IDX] = ""
	c.four_tuple[DST_PORT_IDX] = "0"
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

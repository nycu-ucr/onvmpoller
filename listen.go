package onvmpoller

import (
	"encoding/binary"
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
	var c Connection
	c.rxchan = make(chan ChannelData, 100)
	c.four_tuple.Src_ip = binary.BigEndian.Uint32(net.ParseIP(ip_addr)[12:16])
	c.four_tuple.Src_port = port
	c.four_tuple.Dst_ip = binary.BigEndian.Uint32(net.ParseIP("0.0.0.0")[12:16])
	c.four_tuple.Dst_port = uint16(0)

	listener_four_tuple = &c.four_tuple
	onvmpoll.Add(&c)
	listener_conn = &c

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

	return &OnvmListener{laddr: laddr, conn: &c}, nil
}

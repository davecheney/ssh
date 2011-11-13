// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
)
// Dial initiates a connection to the addr from the remote host.
func (c *ClientConn) Dial(n, addr string) (net.Conn, error) {
       a, err := net.ResolveTCPAddr(n, addr)
       if err != nil {
               return nil, err
       }
       return c.DialTCP(n, nil, a)
}

// DialTCP connects to the remote address raddr on the network net,
// which must be "tcp", "tcp4", or "tcp6".  If laddr is not nil, it is used
// as the local address for the connection.
func (c *ClientConn) DialTCP(n string, laddr, raddr *net.TCPAddr) (net.Conn, error) {

	// RFC 4254 7.2
	type channelOpenDirectMsg struct {
		ChanType      string
		PeersId       uint32
		PeersWindow   uint32
		MaxPacketSize uint32
		raddr         string
		rport         uint32
		laddr         string
		lport         uint32
	}
	if laddr == nil {
		laddr = &net.TCPAddr{
			IP:   net.IP{127, 0, 0, 1},
			Port: 7777,
		}
	}
	ch := c.newChan(c.transport)
	if err := c.writePacket(marshal(msgChannelOpen, channelOpenDirectMsg{
		ChanType:      "direct-tcpip",
		PeersId:       ch.id,
		PeersWindow:   1 << 14,
		MaxPacketSize: 1 << 15, // RFC 4253 6.1
		raddr:         raddr.IP.String(),
		rport:         uint32(raddr.Port),
		laddr:         laddr.IP.String(),
		lport:         uint32(laddr.Port),
	})); err != nil {
		c.chanlist.remove(ch.id)
		return nil, err
	}
	// wait for response
	msg := <-ch.msg
	fmt.Printf("DialTCP: %#v\n", msg)
	switch msg := msg.(type) {
	case *channelOpenConfirmMsg:
		ch.peersId = msg.MyId
		ch.win <- int(msg.MyWindow)
	case *channelOpenFailureMsg:
		c.chanlist.remove(ch.id)
		return nil, errors.New(msg.Message)
	default:
		c.chanlist.remove(ch.id)
		return nil, errors.New("ssh: unexpected packet")
	}
	return &tcpchan{
		clientChan: ch,
		laddr:      laddr,
		raddr:      raddr,
		Reader: &chanReader{
			packetWriter: ch,
			id:           ch.id,
			data:         ch.data,
		},
		Writer: &chanWriter{
			packetWriter: ch,
			id:           ch.id,
			win:          ch.win,
		},
	}, nil
}

type tcpchan struct {
	*clientChan // the backing channel
	io.Reader
	io.Writer
	laddr, raddr net.Addr
}

// LocalAddr returns the local network address.
func (t *tcpchan) LocalAddr() net.Addr {
	return t.laddr
}

// RemoteAddr returns the remote network address.
func (t *tcpchan) RemoteAddr() net.Addr {
	return t.raddr
}

// SetTimeout sets the read and write deadlines associated
// with the connection.
func (t *tcpchan) SetTimeout(nsec int64) error {
	if err := t.SetReadTimeout(nsec); err != nil {
		return err
	}
	return t.SetWriteTimeout(nsec)
}

// SetReadTimeout sets the time (in nanoseconds) that
// Read will wait for data before returning an error with Timeout() == true.
// Setting nsec == 0 (the default) disables the deadline.
func (t *tcpchan) SetReadTimeout(nsec int64) error {
	return errors.New("tcpchan: timeout not supported")
}

// SetWriteTimeout sets the time (in nanoseconds) that
// Write will wait to send its data before returning an error with Timeout() == true.
// Setting nsec == 0 (the default) disables the deadline.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
func (t *tcpchan) SetWriteTimeout(nsec int64) error {
	return errors.New("tcpchan: timeout not supported")
}

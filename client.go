// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
)

// clientVersion is the fixed identification string that the client will use.
var clientVersion = []byte("SSH-2.0-Go\r\n")

// ClientConn represents the client side of an SSH connection.
type ClientConn struct {
	*transport
	config *ClientConfig
	chanlist
}

// Client returns a new SSH client connection using c as the underlying transport.
func Client(c net.Conn, config *ClientConfig) (*ClientConn, error) {
	conn := &ClientConn{
		transport: newTransport(c, config.rand()),
		config:    config,
	}
	if err := conn.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	go conn.mainloop()
	return conn, nil
}

// handshake performs the client side key exchange. See RFC 4253 Section 7.
func (c *ClientConn) handshake() error {
	var magics handshakeMagics

	if _, err := c.Write(clientVersion); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return err
	}
	magics.clientVersion = clientVersion[:len(clientVersion)-2]

	// read remote server version
	version, err := readVersion(c)
	if err != nil {
		return err
	}
	magics.serverVersion = version
	clientKexInit := kexInitMsg{
		KexAlgos:                supportedKexAlgos,
		ServerHostKeyAlgos:      supportedHostKeyAlgos,
		CiphersClientServer:     c.config.Crypto.ciphers(),
		CiphersServerClient:     c.config.Crypto.ciphers(),
		MACsClientServer:        supportedMACs,
		MACsServerClient:        supportedMACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	kexInitPacket := marshal(msgKexInit, clientKexInit)
	magics.clientKexInit = kexInitPacket

	if err := c.writePacket(kexInitPacket); err != nil {
		return err
	}
	packet, err := c.readPacket()
	if err != nil {
		return err
	}

	magics.serverKexInit = packet

	var serverKexInit kexInitMsg
	if err = unmarshal(&serverKexInit, packet, msgKexInit); err != nil {
		return err
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, &clientKexInit, &serverKexInit)
	if !ok {
		return errors.New("ssh: no common algorithms")
	}

	if serverKexInit.FirstKexFollows && kexAlgo != serverKexInit.KexAlgos[0] {
		// The server sent a Kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := c.readPacket(); err != nil {
			return err
		}
	}

	var H, K []byte
	var hashFunc crypto.Hash
	switch kexAlgo {
	case kexAlgoDH14SHA1:
		hashFunc = crypto.SHA1
		dhGroup14Once.Do(initDHGroup14)
		H, K, err = c.kexDH(dhGroup14, hashFunc, &magics, hostKeyAlgo)
	default:
		err = fmt.Errorf("ssh: unexpected key exchange algorithm %v", kexAlgo)
	}
	if err != nil {
		return err
	}

	if err = c.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	if err = c.transport.writer.setupKeys(clientKeys, K, H, H, hashFunc); err != nil {
		return err
	}
	if packet, err = c.readPacket(); err != nil {
		return err
	}
	if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}
	if err := c.transport.reader.setupKeys(serverKeys, K, H, H, hashFunc); err != nil {
		return err
	}
	return c.authenticate(H)
}

// kexDH performs Diffie-Hellman key agreement on a ClientConn. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *ClientConn) kexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) ([]byte, []byte, error) {
	x, err := rand.Int(c.config.rand(), group.p)
	if err != nil {
		return nil, nil, err
	}
	X := new(big.Int).Exp(group.g, x, group.p)
	kexDHInit := kexDHInitMsg{
		X: X,
	}
	if err := c.writePacket(marshal(msgKexDHInit, kexDHInit)); err != nil {
		return nil, nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, nil, err
	}

	var kexDHReply = new(kexDHReplyMsg)
	if err = unmarshal(kexDHReply, packet, msgKexDHReply); err != nil {
		return nil, nil, err
	}

	if kexDHReply.Y.Sign() == 0 || kexDHReply.Y.Cmp(group.p) >= 0 {
		return nil, nil, errors.New("server DH parameter out of bounds")
	}

	kInt := new(big.Int).Exp(kexDHReply.Y, x, group.p)
	h := hashFunc.New()
	writeString(h, magics.clientVersion)
	writeString(h, magics.serverVersion)
	writeString(h, magics.clientKexInit)
	writeString(h, magics.serverKexInit)
	writeString(h, kexDHReply.HostKey)
	writeInt(h, X)
	writeInt(h, kexDHReply.Y)
	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum()

	return H, K, nil
}

// openChan opens a new client channel. The most common session type is "session". 
// The full set of valid session types are listed in RFC 4250 4.9.1.
func (c *ClientConn) openChan(typ string) (*clientChan, error) {
	ch := c.newChan(c.transport)
	if err := c.writePacket(marshal(msgChannelOpen, channelOpenMsg{
		ChanType:      typ,
		PeersId:       ch.id,
		PeersWindow:   1 << 14,
		MaxPacketSize: 1 << 15, // RFC 4253 6.1
	})); err != nil {
		c.chanlist.remove(ch.id)
		return nil, err
	}
	// wait for response
	switch msg := (<-ch.msg).(type) {
	case *channelOpenConfirmMsg:
		ch.peersId = msg.MyId
		ch.win <- int(msg.MyWindow)
	case *channelOpenFailureMsg:
		c.chanlist.remove(ch.id)
		return nil, errors.New(msg.Message)
	default:
		c.chanlist.remove(ch.id)
		return nil, errors.New("Unexpected packet")
	}
	return ch, nil
}

// mainloop reads incoming messages and routes channel messages
// to their respective ClientChans.
func (c *ClientConn) mainloop() {
	defer c.Close()
	for {
		packet, err := c.readPacket()
		if err != nil {
			break
		}
		// TODO(dfc) A note on blocking channel use. 
		// The msg, win, data and dataExt channels of a clientChan can 
		// cause this loop to block indefinately if the consumer does 
		// not service them. 
		switch packet[0] {
		case msgChannelData:
			if len(packet) < 9 {
				// malformed data packet
				break
			}
			peersId := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
			if length := int(packet[5])<<24 | int(packet[6])<<16 | int(packet[7])<<8 | int(packet[8]); length > 0 {
				packet = packet[9:]
				c.getChan(peersId).handleData(packet[:length])
			}
		case msgChannelExtendedData:
			if len(packet) < 13 {
				// malformed data packet
				break
			}
			peersId := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
			datatype := uint32(packet[5])<<24 | uint32(packet[6])<<16 | uint32(packet[7])<<8 | uint32(packet[8])
			if length := int(packet[9])<<24 | int(packet[10])<<16 | int(packet[11])<<8 | int(packet[12]); length > 0 {
				packet = packet[13:]
				// RFC 4254 5.2 defines data_type_code 1 to be data destined 
				// for stderr on interactive sessions. Other data types are
				// silently discarded.
				if datatype == 1 {
					c.getChan(peersId).handleDataExt(packet[:length])
				}
			}
		case msgChannelWindowAdjust:
			if len(packet) < 9 {
				// malformed window packet
				break
			}
			peersId := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
			win := uint32(packet[5])<<24 | uint32(packet[6])<<16 | uint32(packet[7])<<8 | uint32(packet[8])
			if win > 0 {
				c.getChan(peersId).handleWin(win)
			}
		default:
			switch msg := decode(packet).(type) {
			case *channelOpenMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelOpenConfirmMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelOpenFailureMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelCloseMsg:
				fmt.Println("close received")
				ch := c.getChan(msg.PeersId)
				ch.closeWin()
				ch.closeData()
				ch.closeDataExt()
				if ch.closeSent {
					c.chanlist.remove(msg.PeersId)
					continue
				}
				ch.sendClose()
			case *channelEOFMsg:
				fmt.Printf("mainloop: eof received\n")
				ch := c.getChan(msg.PeersId)
				ch.closeData()
				ch.closeDataExt()
			case *channelRequestSuccessMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestFailureMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *disconnectMsg:
				fmt.Println("disconnect")
				break
			default:
				fmt.Printf("mainloop: unhandled %#v\n", msg)
			}
		}
	}
}

// Dial connects to the given network address using net.Dial and 
// then initiates a SSH handshake, returning the resulting client connection.
func Dial(network, addr string, config *ClientConfig) (*ClientConn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return Client(conn, config)
}

// A ClientConfig structure is used to configure a ClientConn. After one has 
// been passed to an SSH function it must not be modified.
type ClientConfig struct {
	// Rand provides the source of entropy for key exchange. If Rand is 
	// nil, the cryptographic random reader in package crypto/rand will 
	// be used.
	Rand io.Reader

	// The username to authenticate.
	User string

	// A slice of ClientAuth methods. Only the first instance 
	// of a particular RFC 4252 method will be used during authentication.
	Auth []ClientAuth

	// Cryptographic-related configuration.
	Crypto CryptoConfig
}

func (c *ClientConfig) rand() io.Reader {
	if c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

// A clientChan represents a single RFC 4254 channel that is multiplexed 
// over a single SSH connection.
type clientChan struct {
	packetWriter
	id, peersId   uint32
	data          *readbuf // receives the payload of channelData messages
	dataExt       *readbuf // receives the payload of channelExtendedData messages
	win           chan int // receives window adjustments
	winClosed     bool
	msg           chan interface{} // incoming messages
	closeSent     bool
}

func newClientChan(t *transport, id uint32) *clientChan {
	return &clientChan{
		packetWriter: t,
		id:           id,
		data:         newReadBuf(),
		dataExt:      newReadBuf(),
		win:          make(chan int, 16),
		msg:          make(chan interface{}, 16),
	}
}

func (c *clientChan) Close() error {
	c.closeWin()
	c.closeData()
	c.closeDataExt()
	if !c.closeSent {
		return c.sendClose()
	}
	return nil
}

func (c *clientChan) sendClose() error {
	println("close sent")
	c.closeSent = true
	return c.writePacket(marshal(msgChannelClose, channelCloseMsg{
		PeersId: c.id,
	}))
}

func (c *clientChan) handleData(data []byte) {
	c.data.write(data)
}

func (c *clientChan) handleDataExt(data []byte) {
	c.dataExt.write(data)
}

func (c *clientChan) handleWin(win uint32) {
	c.win <- int(win)
}

func (c *clientChan) closeData() {
	c.data.close()
}

func (c *clientChan) closeDataExt() {
	c.dataExt.close()
}

func (c *clientChan) closeWin() {
	if !c.winClosed {
		close(c.win)
		c.winClosed = true
	}
}

func (c *clientChan) sendChanReq(req channelRequestMsg) error {
	if err := c.writePacket(marshal(msgChannelRequest, req)); err != nil {
		return err
	}
	msg := <-c.msg
	if _, ok := msg.(*channelRequestSuccessMsg); ok {
		return nil
	}
	return fmt.Errorf("failed to complete request: %s, %#v", req.Request, msg)
}

// Thread safe channel list.
type chanlist struct {
	// protects concurrent access to chans
	sync.Mutex
	// chans are indexed by the local id of the channel, clientChan.id.
	// The PeersId value of messages received by ClientConn.mainloop is
	// used to locate the right local clientChan in this slice.
	chans []*clientChan
}

// Allocate a new ClientChan with the next avail local id.
func (c *chanlist) newChan(t *transport) *clientChan {
	c.Lock()
	defer c.Unlock()
	for i := range c.chans {
		if c.chans[i] == nil {
			ch := newClientChan(t, uint32(i))
			c.chans[i] = ch
			return ch
		}
	}
	i := len(c.chans)
	ch := newClientChan(t, uint32(i))
	c.chans = append(c.chans, ch)
	return ch
}

func (c *chanlist) getChan(id uint32) *clientChan {
	c.Lock()
	defer c.Unlock()
	return c.chans[int(id)]
}

func (c *chanlist) remove(id uint32) {
	c.Lock()
	defer c.Unlock()
	c.chans[int(id)] = nil
}

// A chanWriter represents the stdin of a remote process.
type chanWriter struct {
	win          chan int // receives window adjustments
	id           uint32   // this channel's id
	rwin         int      // current rwin size
	packetWriter          // for sending channelDataMsg
}

// Write writes data to the remote process's standard input.
func (w *chanWriter) Write(data []byte) (n int, err error) {
	for {
		select {
		// test to see the channel is still open for writing
		case win, ok := <-w.win:
			if !ok {
				return 0, io.EOF
			}
			w.rwin += win
		default:
			if w.rwin == 0 {
				win, ok := <-w.win
				if !ok {
					return 0, io.EOF
				}
				w.rwin += win
			}
		}
		n = len(data)
		packet := make([]byte, 0, 9+n)
		packet = append(packet, msgChannelData,
			byte(w.id)>>24, byte(w.id)>>16, byte(w.id)>>8, byte(w.id),
			byte(n)>>24, byte(n)>>16, byte(n)>>8, byte(n))
		err = w.writePacket(append(packet, data...))
		w.rwin -= n
		return
	}
	panic("unreachable")
}

// A chanReader represents stdout or stderr of a remote process.
type chanReader struct {
	// TODO(dfc) a fixed size channel may not be the right data structure.
	// If writes to this channel block, they will block mainloop, making
	// it unable to receive new messages from the remote side.
	id           uint32
	packetWriter // for sending windowAdjustMsg
	buf          *readbuf
}

// Read reads data from the remote process's stdout or stderr.
func (r *chanReader) Read(data []byte) (int, error) {
	n, err := r.buf.read(data)
	if err != nil {
		return n, err
	}
	msg := windowAdjustMsg{
		PeersId:         r.id,
		AdditionalBytes: uint32(n),
	}
	return n, r.writePacket(marshal(msgChannelWindowAdjust, msg))
}

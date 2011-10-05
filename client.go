// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"big"
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"net"
	"sync"
)

// clientVersion is the fixed identification string that the 
// client will use.
var clientVersion = []byte("SSH-2.0-Go\r\n")

// ClientConn represents the client side of an SSH connection.
type ClientConn struct {
	*transport
	config *ClientConfig
	chanlist
}

// Construct a new ClientConn
func newClientConn(c net.Conn, config *ClientConfig) *ClientConn {
	conn := &ClientConn{
		transport: newTransport(c),
		config:    config,
		chanlist: chanlist{
			Mutex: new(sync.Mutex),
			chans: make(map[uint32]*ClientChan),
		},
	}
	return conn
}

func (c *ClientConn) handshake() os.Error {
	var magics handshakeMagics

	if _, err := c.Write(clientVersion); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return err
	}

	magics.clientVersion = clientVersion[:len(clientVersion)-2]

	// read remote server version
	version, ok := readVersion(c)
	if !ok {
		return os.NewError("failed to read version string from string")
	}
	magics.serverVersion = version

	clientKexInit := kexInitMsg{
		KexAlgos:                c.config.SupportedKexAlgos,
		ServerHostKeyAlgos:      c.config.SupportedHostKeyAlgos,
		CiphersClientServer:     c.config.SupportedCiphers,
		CiphersServerClient:     c.config.SupportedCiphers,
		MACsClientServer:        c.config.SupportedMACs,
		MACsServerClient:        c.config.SupportedMACs,
		CompressionClientServer: c.config.SupportedCompressions,
		CompressionServerClient: c.config.SupportedCompressions,
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
		return os.NewError("ssh: no common algorithms")
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
		err = os.NewError("ssh: internal error")
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

	return c.transport.reader.setupKeys(serverKeys, K, H, H, hashFunc)
}

func (c *ClientConn) authenticate() os.Error {
	if err := c.writePacket(marshal(msgServiceRequest, serviceRequestMsg{serviceUserAuth})); err != nil {
		return err
	}
	packet, err := c.readPacket()
	if err != nil {
		return err
	}

	var serviceAccept serviceAcceptMsg
	if err = unmarshal(&serviceAccept, packet, msgServiceAccept); err != nil {
		return err
	}

	// TODO(dfc) support proper authentication method negotation
	method := "none"
	if c.config.Password != "" {
		method = "password"
	}
	if err := c.sendUserAuthReq(method); err != nil {
		return err
	}

	if packet, err = c.readPacket(); err != nil {
		return err
	}

	if packet[0] != msgUserAuthSuccess {
		return UnexpectedMessageError{msgUserAuthSuccess, packet[0]}
	}
	return nil
}

func (c *ClientConn) sendUserAuthReq(method string) os.Error {
	length := stringLength([]byte(c.config.Password)) + 1
	payload := make([]byte, length)
	marshalString(payload[1:], []byte(c.config.Password)) // payload[0] = boolean:false

	return c.writePacket(marshal(msgUserAuthRequest, userAuthRequestMsg{
		User:    c.config.User,
		Service: serviceSSH,
		Method:  method,
		Payload: payload,
	}))
}

// kexDH performs Diffie-Hellman key agreement on a ClientConnection. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *ClientConn) kexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) ([]byte, []byte, os.Error) {
	x, err := rand.Int(rand.Reader, group.p)
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
		return nil, nil, os.NewError("server DH parameter out of bounds")
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

// Open a new client side channel. Valid types are listed in RFC 4250 4.9.1.
func (c *ClientConn) OpenChan(typ string) (*ClientChan, os.Error) {
	ch := c.newChan(c.transport)
	if err := c.writePacket(marshal(msgChannelOpen, channelOpenMsg{
		ChanType:      typ,
		PeersId:       ch.id,
		PeersWindow:   0,
		MaxPacketSize: 16384,
	})); err != nil {
		// remove channel reference
		c.chanlist.remove(ch.id)
		return nil, err
	}
	// wait for response
	switch msg := (<-ch.msg).(type) {
	case *channelOpenConfirmMsg:
		ch.peerId = msg.MyId
	case *channelOpenFailureMsg:
		return nil, os.NewError(msg.Message)
	default:
		return nil, os.NewError("Unexpected packet")
	}
	return ch, nil
}

// Drain incoming messages and route channel messages to their
// respective ClientChans.
func (c *ClientConn) mainloop() {
	// make readPacket() non blocking
	read := make(chan interface{}, 16)
	go func() {
		for {
			packet, err := c.readPacket()
			if err != nil {
				// we can't recover from an error in readPacket
				read <- err
				return
			}
			read <- packet
		}
	}()
	for {
		switch in := (<-read).(type) {
		case []byte:
			// incoming packet, decode and dispatch
			switch msg := decode(in).(type) {
			case *channelOpenMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelOpenConfirmMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelOpenFailureMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelCloseMsg:
				c.chanlist.remove(msg.PeersId)
			case *channelEOFMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestSuccessMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestFailureMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *windowAdjustMsg:
				c.getChan(msg.PeersId).stdinWriter.win <- msg.AdditionalBytes
			case *channelData:
				c.getChan(msg.PeersId).stdoutReader.data <- msg.Payload
			case *channelExtendedData:
				c.getChan(msg.PeersId).stderrReader.dataExt <- msg.Data
			default:
				fmt.Printf("mainloop: unhandled %#v\n", msg)
			}
		case os.Error:
			// on any error close the connection
			defer c.Close()
			return
		default:
			panic("Unknown operation")
		}
	}
}

// Dial connects to the given network address using net.Dial
// and then initiates a SSH handshake, returning the resulting
// SSH client connection.
func Dial(addr string, config *ClientConfig) (*ClientConn, os.Error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := newClientConn(conn, config)
	if err := client.handshake(); err != nil {
		defer client.Close()
		return nil, err
	}
	if err := client.authenticate(); err != nil {
		defer client.Close()
		return nil, err
	}
	go client.mainloop()
	return client, nil
}

// A ClientConfig structure is used to configure a ClientConn. After one
// has been passed to an SSH function it must not be modified.
type ClientConfig struct {
	User     string
	Password string // used for "password" method authentication

	SupportedKexAlgos, SupportedHostKeyAlgos, SupportedCiphers, SupportedMACs, SupportedCompressions []string
}

// Represents a single SSH channel that is multiplexed over an SSH connection.
type ClientChan struct {
	packetWriter
	*stdinWriter
	*stdoutReader
	*stderrReader
	id, peerId uint32
	msg        chan interface{} // incoming messages 
	data       chan []byte      // data from msgChannelData
	dataExt    chan string      // data from msgChannelExtendedData

}

func newClientChan(t *transport, id uint32) *ClientChan {
	return &ClientChan{
		packetWriter: t,
		stdinWriter: &stdinWriter{
			packetWriter: t,
		},
		stdoutReader: &stdoutReader{
			packetWriter: t,
			data: make(chan []byte, 16),
		},
		stderrReader: &stderrReader{
			dataExt: make(chan string, 16),
		},

		id:       id,
		msg:      make(chan interface{}, 16),
	}
}

func (c *ClientChan) Close() os.Error {
	if err := c.writePacket(marshal(msgChannelClose, channelCloseMsg{
		PeersId: c.id,
	})); err != nil {
		return err
	}
	return nil
}

// Pass an environment variable to a channel to be applied
// to any shell/command started later
func (c *ClientChan) Setenv(name, value string) os.Error {
	namLen := stringLength([]byte(name))
	valLen := stringLength([]byte(value))
	payload := make([]byte, namLen+valLen)
	marshalString(payload[:namLen], []byte(name))
	marshalString(payload[namLen:], []byte(value))

	return c.sendChanReq(channelRequestMsg{
		PeersId:             c.peerId,
		Request:             "env",
		WantReply:           true,
		RequestSpecificData: payload,
	})
}

func (c *ClientChan) sendChanReq(req channelRequestMsg) os.Error {
	if err := c.writePacket(marshal(msgChannelRequest, req)); err != nil {
		return err
	}
	for {
		switch msg := (<-c.msg).(type) {
		case *channelRequestSuccessMsg:
			return nil
		case *channelRequestFailureMsg:
			return os.NewError(req.Request)
		default:
			return fmt.Errorf("%#v", msg)
		}
	}
	panic("unreachable")
}

// Request a pty to be allocated on the remote side for this channel
func (c *ClientChan) Ptyreq(term string, h, w int) os.Error {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, uint32(len(term)))
	binary.Write(b, binary.BigEndian, term)
	binary.Write(b, binary.BigEndian, uint32(h))
	binary.Write(b, binary.BigEndian, uint32(w))
	binary.Write(b, binary.BigEndian, uint32(h*8))
	binary.Write(b, binary.BigEndian, uint32(w*8))
	b.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0}) // empty mode list

	return c.sendChanReq(channelRequestMsg{
		PeersId:             c.peerId,
		Request:             "pty-req",
		WantReply:           true,
		RequestSpecificData: b.Bytes(),
	})
}

func (c *ClientChan) Exec(command string) os.Error {
	cmdLen := stringLength([]byte(command))
	payload := make([]byte, cmdLen)
	marshalString(payload, []byte(command))
	return c.sendChanReq(channelRequestMsg{
		PeersId:             c.peerId,
		Request:             "exec",
		WantReply:           true,
		RequestSpecificData: payload,
	})
}

func (c *ClientChan) Shell() (io.WriteCloser, io.ReadCloser, io.Reader, os.Error) {
	err := c.sendChanReq(channelRequestMsg{
		PeersId:   c.peerId,
		Request:   "shell",
		WantReply: true,
	})

	return c.stdinWriter, c.stdoutReader, c.stderrReader, err
}

type chanlist struct {
	*sync.Mutex
	chans map[uint32]*ClientChan
}

func (c *chanlist) newChan(t *transport) *ClientChan {
	c.Lock()
	defer c.Unlock()

	for i := uint32(0); i < 2^31; i++ {
		if _, ok := c.chans[i]; !ok {
			ch := newClientChan(t, i)
			c.chans[i] = ch
			return ch
		}
	}
	panic("unable to find free channel")
}

func (c *chanlist) getChan(id uint32) *ClientChan {
	c.Lock()
	defer c.Unlock()
	return c.chans[id]
}

func (c *chanlist) remove(id uint32) {
	c.Lock()
	defer c.Unlock()
	c.chans[id] = nil, false
}

type stdinWriter struct {
	win          chan uint32 // recieves window adjustments
	id           uint32
	rwin         uint32 // current rwin size
	packetWriter        // for sending channeDataMsg
}

func (w *stdinWriter) Write(data []byte) (n int, err os.Error) {
	for {
		if w.rwin == 0 {
			w.rwin += <-w.win
			continue
		}
		packet := make([]byte, 1+4+4+len(data))
		packet[0] = msgChannelData
		packet[1] = byte(w.id) >> 24
		packet[2] = byte(w.id) >> 16
		packet[3] = byte(w.id) >> 8
		packet[4] = byte(w.id)
		packet[5] = byte(len(data)) >> 24
		packet[6] = byte(len(data)) >> 16
		packet[7] = byte(len(data)) >> 8
		packet[8] = byte(len(data))
		copy(packet[9:], data)

		if err = w.writePacket(packet); err != nil {
			return
		}

		err = w.writePacket(packet)
		w.rwin -= uint32(n)
		return
	}
	panic("unreachable")
}

func (w *stdinWriter) Close() os.Error {
	return w.writePacket(marshal(msgChannelEOF, &channelEOFMsg{w.id}))
}

type stdoutReader struct {
	data         chan []byte // receives data from remote
	id           uint32
	win          int // current win size
	packetWriter     // for sending windowAdjustMsg
	buf          []byte
}

func (r *stdoutReader) Read(data []byte) (int, os.Error) {
	for {
		if len(r.buf) > 0 {
			n := copy(data, r.buf)
			r.buf = r.buf[n:]
			r.win += n
			err := r.writePacket(marshal(msgChannelWindowAdjust, &windowAdjustMsg{
				PeersId:         r.id,
				AdditionalBytes: uint32(n),
			}))
			return n, err
		}
		r.buf = []byte(<-r.data)
		r.win -= len(r.buf)
	}
	panic("unreachable")
}

func (r *stdoutReader) Close() os.Error {
	return r.writePacket(marshal(msgChannelEOF, &channelEOFMsg{r.id}))
}

type stderrReader struct {
	dataExt chan string // receives dataExt from remote
	buf     []byte      // buffer current dataExt
}

func (r *stderrReader) Read(data []byte) (int, os.Error) {
	for {
		if len(r.buf) > 0 {
			n := copy(data, r.buf)
			r.buf = r.buf[n:]
			return n, nil
		}
		r.buf = []byte(<-r.dataExt)
	}
	panic("unreachable")
}

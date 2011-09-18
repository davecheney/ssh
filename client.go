// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"big"
	"bufio"
	"bytes"
	"encoding/binary"
	"crypto"
	"crypto/rand"
	"net"
	"os"
	"sync/atomic"
)

// clientVersion is the fixed identification string that Client will use.
var clientVersion = []byte("SSH-2.0-Go\r\n")

func Dial(addr string, config Config) (*Client, os.Error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := &Client{
		transport: &transport{
			reader: reader{
				Reader: bufio.NewReader(conn),
			},
			writer: writer{
				Writer:          bufio.NewWriter(conn),
				rand:            rand.Reader,
				paddingMultiple: 16,
			},
		},
		Config:      config,
		channels:    make(map[uint32]*ClientChan),
		stop:        make(chan bool),
		in:          make(chan []byte, 1),
		inErr:       make(chan os.Error),
		openChannel: make(chan chan interface{}, 1),
	}
	if err := client.handshake(); err != nil {
		return nil, err
	}
	go client.mainloop()
	return client, nil
}

type Client struct {
	*transport
	in          chan []byte // decrpted packets
	inErr       chan os.Error
	Config      Config
	magics      handshakeMagics
	channels    map[uint32]*ClientChan
	nextId      uint32                // net channel id
	stop        chan bool             // callled on Client.Close()
	openChannel chan chan interface{} // request new channels
}

func (c *Client) nextChanId() uint32 {
	return atomic.AddUint32(&c.nextId, 1)
}

func (c *Client) mainloop() {
	// read incoming packets in a goroutine 
	go func() {
		for {
			packet, err := c.readPacket()
			if err != nil {
				// we can't recover from an error in readPacket
				c.inErr <- err // blocks until err is received
				return
			}
			c.in <- packet
		}
	}()
	for {
		select {
		case packet := <-c.in:
			switch msg := decode(packet).(type) {
			case channelOpenConfirmMsg:
				ch := c.channels[msg.PeersId]
				ch.peerId = msg.MyId
				ch.resp <- ch // send self back to requestor
			case channelOpenFailureMsg:
				ch := c.channels[msg.PeersId]
				ch.resp <- os.NewError("failed")
			case windowAdjustMsg:
				ch := c.channels[msg.PeersId]
				ch.resp <- msg
			case channelRequestSuccessMsg:
				ch := c.channels[msg.PeersId]
				ch.resp <- msg
			case channelRequestFailureMsg:
				ch := c.channels[msg.PeersId]
				ch.resp <- msg
			case channelCloseMsg:
				ch := c.channels[msg.PeersId]
				ch.resp <- msg
			default:
				debug("mainloop: unhandled packet type", packet[0])
			}
		case <-c.inErr:
			// on any error close the connection
			c.stop <- true
		case <-c.stop:
			c.transport.Close()
		case resp := <-c.openChannel:
			id := c.nextChanId()
			ch := &ClientChan{
				client: c,
				resp:   resp,
			}
			c.channels[id] = ch
			if err := c.sendMessage(msgChannelOpen, channelOpenMsg{
				ChanType:      "session",
				PeersId:       id,
				PeersWindow:   8192,
				MaxPacketSize: 16384,
			}); err != nil {
				// remove channel reference
				c.channels[id] = ch, false
				resp <- err
			}
		}
	}
}

func (c *Client) handshake() os.Error {
	// send client version
	if _, err := c.transport.writer.Writer.Write(clientVersion); err != nil {
		return err
	}
	c.magics.clientVersion = clientVersion[:len(serverVersion)-2]

	// recv server version
	version, ok := readVersion(c.transport.reader.Reader)
	if !ok {
		return os.NewError("failed to read version string from string")
	}
	c.magics.serverVersion = version

	clientKexInit := kexInitMsg{
		KexAlgos:                supportedKexAlgos,
		ServerHostKeyAlgos:      supportedHostKeyAlgos,
		CiphersClientServer:     supportedCiphers,
		CiphersServerClient:     supportedCiphers,
		MACsClientServer:        supportedMACs,
		MACsServerClient:        supportedMACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	kexInitPacket := marshal(msgKexInit, clientKexInit)
	c.magics.clientKexInit = kexInitPacket

	if err := c.writePacket(kexInitPacket); err != nil {
		return err
	}

	packet, err := c.readPacket()
	if err != nil {
		return err
	}

	c.magics.serverKexInit = packet

	var serverKexInit kexInitMsg
	if err = unmarshal(&serverKexInit, packet, msgKexInit); err != nil {
		return err
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, c.transport, &clientKexInit, &serverKexInit)
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

	H, K, hashFunc, err := c.kexInit(kexAlgo, hostKeyAlgo)
	if err != nil {
		return err
	}

	packet = []byte{msgNewKeys}
	if err = c.writePacket(packet); err != nil {
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

	c.transport.reader.setupKeys(serverKeys, K, H, H, hashFunc)

	if err := c.sendServiceReq(serviceUserAuth); err != nil {
		return err
	}

	packet, err = c.readPacket()
	if err != nil {
		return err
	}

	var serviceAccept serviceAcceptMsg
	if err = unmarshal(&serviceAccept, packet, msgServiceAccept); err != nil {
		return err
	}

	if err := c.sendUserAuthReq("password"); err != nil {
		return err
	}

	packet, err = c.readPacket()
	if err != nil {
		return err
	}
	if packet[0] != msgUserAuthSuccess {
		return UnexpectedMessageError{msgUserAuthSuccess, packet[0]}
	}

	return nil
}

func (c *Client) sendServiceReq(name string) os.Error {
	packet := marshal(msgServiceRequest, serviceRequestMsg{name})
	return c.writePacket(packet)
}

func (c *Client) sendUserAuthReq(method string) os.Error {
	length := stringLength(c.Config.Password) + 1
	payload := make([]byte, length)
	marshalString(payload[1:], c.Config.Password) // payload[0] == 0 == boolean:false

	return c.sendMessage(msgUserAuthRequest, userAuthRequestMsg{
		User:    c.Config.User,
		Service: serviceSSH,
		Method:  method,
		Payload: payload,
	})
}

func (c *Client) kexInit(kexAlgo, hostKeyAlgo string) (H, K []byte, hashFunc crypto.Hash, err os.Error) {
	switch kexAlgo {
	case kexAlgoDH14SHA1:
		hashFunc = crypto.SHA1
		dhGroup14Once.Do(initDHGroup14)
		H, K, err = c.kexDH(dhGroup14, hashFunc, &c.magics, hostKeyAlgo)
	default:
		err = os.NewError("ssh: internal error")
	}
	return
}

// kexDH performs Diffie-Hellman key agreement on a ClientConnection. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *Client) kexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) (H, K []byte, err os.Error) {
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
		return
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
	K = make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H = h.Sum()

	return
}

func (c *Client) OpenChannel() (*ClientChan, os.Error) {
	resp := make(chan interface{}, 1) // response
	c.openChannel <- resp
	switch ch := <-resp; ch.(type) {
	case *ClientChan:
		return ch.(*ClientChan), nil
	case os.Error:
		return nil, ch.(os.Error)
	}
	panic("unpossible")
}

func (c *Client) Close() {
	c.stop <- true
}

type ClientChan struct {
	client *Client
	peerId uint32
	resp   chan interface{} // used for communicating the open msg
}

func (c *ClientChan) Close() os.Error {
	if err := c.client.sendMessage(msgChannelClose, channelCloseMsg{
		PeersId: c.peerId,
	}); err != nil {
		return err
	}
	switch resp := <-c.resp; resp.(type) {
	case channelCloseMsg:
		return nil
	}
	panic("error")
}

// Pass an environment variable to a channel to be applied
// to any shell/command started later
func (c *ClientChan) Setenv(name, value string) os.Error {
	namLen := stringLength(name)
	valLen := stringLength(value)
	payload := make([]byte, namLen+valLen)
	marshalString(payload[:namLen], name)
	marshalString(payload[namLen:], value)

	if err := c.client.sendMessage(msgChannelRequest, channelRequestMsg{
		PeersId:             c.peerId,
		Request:             "env",
		WantReply:           true,
		RequestSpecificData: payload,
	}); err != nil {
		return err
	}
	switch resp := <-c.resp; resp.(type) {
	case channelRequestSuccessMsg:
		return nil
	case channelRequestFailureMsg:
		return os.NewError("unable to set env var \"" + name + "\"")
	}
	panic("unreachable")
}

// Request a pty to be allocated on the remote side for this channel
func (c *ClientChan) PtyReq(term string, h, w int) os.Error {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, uint32(len(term)))
	binary.Write(b, binary.BigEndian, term)
	binary.Write(b, binary.BigEndian, uint32(h))
	binary.Write(b, binary.BigEndian, uint32(w))
	binary.Write(b, binary.BigEndian, uint32(h*8))
	binary.Write(b, binary.BigEndian, uint32(w*8))
	b.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0}) // empty mode list

	if err := c.client.sendMessage(msgChannelRequest, channelRequestMsg{
		PeersId:             c.peerId,
		Request:             "pty-req",
		WantReply:           true,
		RequestSpecificData: b.Bytes(),
	}); err != nil {
		return err
	}
	switch resp := <-c.resp; resp.(type) {
	case channelRequestSuccessMsg:
		return nil
	case channelRequestFailureMsg:
		return os.NewError("unable to request a pty")
	}
	panic("unreachable")
}

func (c *ClientChan) Exec(command string) os.Error {
	cmdLen := stringLength(command)
	payload := make([]byte, cmdLen)
	marshalString(payload, command)
        if err := c.client.sendMessage(msgChannelRequest, channelRequestMsg{
                PeersId:             c.peerId,
                Request:             "exec",
                WantReply:           true,
                RequestSpecificData: payload,
        }); err != nil {
                return err
        }
        switch resp := <-c.resp; resp.(type) {
        case channelRequestSuccessMsg:
                return nil
        case channelRequestFailureMsg:
                return os.NewError("unable to execure \""+command+"\"")
        }
        panic("unreachable")
}

func debug(args ...interface{}) {
        fmt.Println(args...)
}

type Config struct {
        User     string
        Password string // used for "password" method authentication
}


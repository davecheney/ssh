// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"big"
	"bufio"
	"crypto"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

// clientVersion is the fixed identification string that Client will use.
var clientVersion = []byte("SSH-2.0-Go\r\n")

func Dial(addr string, config Config) (*Client, os.Error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := newClient(conn, config)
	if err := client.handshake(); err != nil {
		// don't leak client if the handshake failed
		client.Close()
		return nil, err
	}
	go client.mainloop()
	return client, nil
}

func newClient(conn net.Conn, config Config) *Client {
	return &Client{
                transport: &transport{
                        reader: reader{
                                Reader: bufio.NewReader(conn),
                        },
                        writer: writer{
                                Writer: bufio.NewWriter(conn),
                                rand:   rand.Reader,
				Mutex: new(sync.Mutex),
                        },
                        Close: func() os.Error {
                                return conn.Close()
                        },
                },
                Config:      config,
                channels:    make(map[uint32]chan interface{}),
		op:	make(chan interface{}, 4),
        }
}

type Client struct {
	*transport
	Config      Config
	magics      handshakeMagics
	channels    map[uint32]chan interface{}
	op    chan interface{}
	nextId      uint32                // net channel id
}

func (c *Client) nextChanId() uint32 {
	return atomic.AddUint32(&c.nextId, 1)
}

func (c *Client) mainloop() {
	// make readPacket() non blocking
	go func() {
		for {
			packet, err := c.readPacket()
			if err != nil {
				// we can't recover from an error in readPacket
				c.op <- err // blocks until err is received
				return
			}
			c.op <- packet
		}
	}()
	for {
		switch in := (<- c.op).(type) {
		case []byte:
			// operation is a []byte, a raw message
			switch msg := decode(in).(type) {
			case channelMsg:
				ch := c.channels[msg.peerId()]
				ch <- msg 
			default:
				debug("mainloop: unhandled packet type", in[0])
			}
		case os.Error:
			// on any error close the connection
			defer c.Close()
			return
		case openChannelRequest:
			
		default:
			panic("Unknown operation")
		}
	}
}

func (c *Client) handshake() os.Error {
	// send client version
	if _, err := c.transport.writer.Writer.Write(clientVersion); err != nil {
		return err
	}
	c.magics.clientVersion = clientVersion[:len(clientVersion)-2]

	// read remote server version
	version, ok := readVersion(c.transport)
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
	length := stringLength([]byte(c.Config.Password)) + 1
	payload := make([]byte, length)
	marshalString(payload[1:], []byte(c.Config.Password)) // payload[0] == 0 == boolean:false

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

type openChannelRequest struct {
	id uint32
	c chan interface{}
}

func (c *Client) openChannel() (*channel, os.Error) {
	r := make(chan interface{}, 16)
	c.op <- openChannelRequest{ c.nextChanId(), r }
	switch msg := (<- r).(type) {

	}
	panic("Unknown message")
}

func (c *Client) Close() {
	c.transport.Close()
}

func debug(args ...interface{}) {
	fmt.Println(args...)
}

func decode(packet []byte) interface{} {
	switch packet[0] {
	case msgDisconnect:
	case msgIgnore:
	case msgUnimplemented:
	case msgDebug:
	case msgServiceRequest:
		var msg serviceRequestMsg
		if err := unmarshal(msg, packet, msgServiceRequest); err != nil {
			return err
		}
		return msg
	case msgServiceAccept:
		var msg serviceAcceptMsg
		if err := unmarshal(msg, packet, msgServiceAccept); err != nil {
			return err
		}
		return msg
	case msgKexInit:
	case msgNewKeys:
	case msgKexDHInit:
	case msgKexDHReply:
	case msgUserAuthRequest:
	case msgUserAuthFailure:
	case msgUserAuthSuccess:
	case msgUserAuthBanner:
	case msgUserAuthPubKeyOk:
	case msgGlobalRequest:
	case msgRequestSuccess:
		var msg channelRequestSuccessMsg
		if err := unmarshal(&msg, packet, msgRequestSuccess); err != nil {
			return err
		}
		return msg
	case msgRequestFailure:
		var msg channelRequestFailureMsg
		if err := unmarshal(&msg, packet, msgRequestFailure); err != nil {
			return err
		}
		return msg
	case msgChannelOpen:
		var msg channelOpenMsg
		if err := unmarshal(&msg, packet, msgChannelOpen); err != nil {
			return err
		}
		return msg
	case msgChannelOpenConfirm:
		var msg channelOpenConfirmMsg
		if err := unmarshal(&msg, packet, msgChannelOpenConfirm); err != nil {
			return err
		}
		return msg
	case msgChannelOpenFailure:
		var msg channelOpenFailureMsg
		if err := unmarshal(&msg, packet, msgChannelOpenFailure); err != nil {
			return err
		}
		return msg
	case msgChannelWindowAdjust:
		var msg windowAdjustMsg
		if err := unmarshal(&msg, packet, msgChannelWindowAdjust); err != nil {
			return err
		}
		return msg
	case msgChannelData:
	case msgChannelExtendedData:
	case msgChannelEOF:
	case msgChannelClose:
		var msg channelCloseMsg
		if err := unmarshal(&msg, packet, msgChannelClose); err != nil {
			return err
		}
		return msg
	case msgChannelRequest:
		var msg channelRequestMsg
		if err := unmarshal(&msg, packet, msgChannelRequest); err != nil {
			return err
		}
		return msg
	case msgChannelSuccess:
		var msg channelRequestSuccessMsg
		if err := unmarshal(&msg, packet, msgChannelSuccess); err != nil {
			return err
		}
		return msg
	case msgChannelFailure:
		var msg channelRequestFailureMsg
		if err := unmarshal(&msg, packet, msgChannelFailure); err != nil {
			return err
		}
		return msg
	}
	return UnexpectedMessageError{0, packet[0]}
}

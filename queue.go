// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"sync"
)

// buffer provides a linked list buffer for data exchange
// between producer and consumer. Theoretically the buffer is
// of unlimited capacity as it does no allocation of its own.
type buffer struct {
	// protects concurrent access to head, tail and eof
	*sync.Cond

	head *element // the buffer that will be read first
	tail *element // the buffer that will be read last

	eof bool // 
}

// An element represents a single link in a linked list.
type element struct {
	buf  []byte
	next *element
}

// newBuffer returns an empty buffer that is not closed.
func newBuffer() *buffer {
	e := new(element)
	b := &buffer{
		Cond: sync.NewCond(new(sync.Mutex)),
		head: e,
		tail: e,
	}
	return b
}

// push makes buf available for Read to receive.
// buf must not be modified after the call to Write.
func (b *buffer) push(buf []byte) (int, error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	e := &element{buf: buf}
	b.tail.next = e
	b.tail = e
	b.Cond.Signal()
	return len(buf), nil
}

// Close closes the buffer. Reads from the buffer 
// after all the data has been consumed wiil receive
// os.EOF.
func (b *buffer) Close() error {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	b.eof = true
	b.Cond.Signal()
	return nil
}

func (b *buffer) pop() (buf []byte, err error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	for {
		if b.eof {
			err = io.EOF
			break
		}
		if b.head.buf != nil {
			buf, b.head = b.head.buf, b.head.next
			break
		}
		b.Cond.Wait()
	}
	return
}

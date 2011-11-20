// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"sync"
)

// readbuf provides a linked list readbuf for data exchange
// between producer and consumer. Theoretically the readbuf is
// of unlimited capacity as it does no allocation of its own.
type readbuf struct {
	// protects concurrent access to head, tail and eof
	*sync.Cond

	head *element // the readbuf that will be read first
	tail *element // the readbuf that will be read last

	eof bool // 
}

// An element represents a single link in a linked list.
type element struct {
	buf  []byte
	next *element
}

func newReadBuf() *readbuf {
	e := new(element)
	b := &readbuf{
		Cond: sync.NewCond(new(sync.Mutex)),
		head: e,
		tail: e,
	}
	return b
}

// write makes buf available for Read to receive.
// buf must not be modified after the call to write.
func (b *readbuf) write(buf []byte) (int, error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	e := &element{buf: buf}
	b.tail.next = e
	b.tail = e
	b.Cond.Signal()
	return len(buf), nil
}

func (b *readbuf) close() {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	b.eof = true
	b.Cond.Signal()
}

// read reads data from the internal readbuf in buf. 
// Reads will block if not data is available, or until
// Close is called.
func (b *readbuf) read(buf []byte) (n int, err error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	for {
		// if there is data in b.head, copy it
		if len(b.head.buf) > 0 {
			r := copy(buf, b.head.buf)
			buf, b.head.buf = buf[r:], b.head.buf[r:]
			n += r
			if len(buf) == 0 {
				// dest full
				break
			}
			continue
		}
		// if there is a next readbuf, make it the head
		if len(b.head.buf) == 0 && b.head != b.tail {
			b.head = b.head.next
			continue
		}
		// if at least one byte has been copied return
		if n > 0 {
			break
		}
		// out of readbufs, wait for producer
		if b.eof {
			err = io.EOF
			break
		}
		b.Cond.Wait()
	}
	return
}

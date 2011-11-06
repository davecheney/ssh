// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"testing"
)

var BYTES = []byte("abcdefghijklmnopqrstuvwxyz")

func TestBufferReadWrite(t *testing.T) {
	b := newBuffer()
	w, _ := b.Write(BYTES[:10])
	r, _ := b.Read(make([]byte, 10))
	if w != r || r != 10 {
		t.Fatalf("Expected written == read == 10, written: %d, read %d", w, r)
	}

	b = newBuffer()
	w, _ = b.Write(BYTES[:5])
	r, _ = b.Read(make([]byte, 10))
	if w != 5 || r != 5 {
		t.Fatalf("Expected written == read == 5, written: %d, read %d", w, r)
	}

	b = newBuffer()
	w, _ = b.Write(BYTES[:10])
	r, _ = b.Read(make([]byte, 5))
	if w != 10 || r != 5 {
		t.Fatalf("Expected written == 10, read == 5, written: %d, read %d", w, r)
	}

	b = newBuffer()
	w, _ = b.Write(BYTES[:5])
	w2, _ := b.Write(BYTES[5:15])
	r, _ = b.Read(make([]byte, 10))
	r2, _ := b.Read(make([]byte, 10))
	if r != 10 || r2 != 5 || w+w2 != r+r2 {
		t.Fatal("Expected written == read == 15")
	}
}

func TestBufferClose(t *testing.T) {
	b := newBuffer()
	w, _ := b.Write(BYTES[:10])
	b.Close()
	_, err := b.Read(make([]byte, 5))
	if err != nil {
		t.Fatal("expected read of 5 to not return EOF")
	}
	b = newBuffer()
	w, _ = b.Write(BYTES[:10])
	b.Close()
	r, err := b.Read(make([]byte, 5))
	r2, err2 := b.Read(make([]byte, 10))
	if r != 5 || r2 != 5 || err != nil || err2 != nil {
		t.Fatal("expected reads of 5 and 5")
	}

	b = newBuffer()
	w, _ = b.Write(BYTES[:10])
	b.Close()
	r, err = b.Read(make([]byte, 5))
	r2, err2 = b.Read(make([]byte, 10))
	r3, err3 := b.Read(make([]byte, 10))
	if r != 5 || r2 != 5 || r3 != 0 || err != nil || err2 != nil || err3 != io.EOF {
		t.Fatal("expected reads of 5 and 5 and 0, with EOF")
	}

	b = newBuffer()
	w, _ = b.Write(make([]byte, 5))
	w2, _ := b.Write(make([]byte, 10))
	b.Close()
	r, err = b.Read(make([]byte, 9))
	r2, err2 = b.Read(make([]byte, 3))
	r3, err3 = b.Read(make([]byte, 3))
	r4, err4 := b.Read(make([]byte, 10))
	if err != nil || err2 != nil || err3 != nil || err4 != io.EOF {
		t.Fatalf("Expected EOF on forth read only, err=%v, err2=%v, err3=%v, err4=%v", err, err2, err3, err4)
	}
	if r != 9 || r2 != 3 || r3 != 3 || r4 != 0 || w != 5 || w2 != 10 {
		t.Fatal("Expected written == read == 15", r, r2, r3, r4)
	}
}

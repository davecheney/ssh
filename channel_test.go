// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"testing"
	"os"
)

var (
	config = Config{
		User: os.Getenv("USER"),
		Password: os.Getenv("PASSWORD"),
	}
)

func TestOpenChannel(t *testing.T) {
	client, err := Dial("localhost:22", config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ch, err := client.openChannel()
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	
}


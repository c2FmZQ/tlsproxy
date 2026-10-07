// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package passkeys

import (
	"bytes"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestAssertionOptionsUnknownEmail(t *testing.T) {
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateAESMasterKeyForTest: %v", err)
	}
	store := storage.New(t.TempDir(), mk)
	tm, err := tokenmanager.New(store, nil, nil)
	if err != nil {
		t.Fatalf("tokenmanager.New: %v", err)
	}
	m, err := NewManager(Config{Store: store, TokenManager: tm})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	fakeID := func(email string) Bytes {
		t.Helper()
		opts, err := m.assertionOptions(email)
		if err != nil {
			t.Fatalf("assertionOptions: %v", err)
		}
		if len(opts.AllowCredentials) != 1 {
			t.Fatalf("AllowCredentials = %v", opts.AllowCredentials)
		}
		return opts.AllowCredentials[0].ID
	}

	id1 := fakeID("alice@example.com")
	if len(id1) != 32 {
		t.Errorf("len(id) = %d, want 32", len(id1))
	}
	if id2 := fakeID("alice@example.com"); !bytes.Equal(id1, id2) {
		t.Errorf("fake ID changed: %x != %x", id1, id2)
	}
	if id3 := fakeID("bob@example.com"); bytes.Equal(id1, id3) {
		t.Errorf("fake IDs are the same for different emails: %x", id1)
	}
}

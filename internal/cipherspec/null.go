package cipherspec

import "hash"

func newNullHash() hash.Hash {
	return &NullHash{}
}

type NullHash struct {
}

func (n2 NullHash) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (n2 NullHash) Sum(b []byte) []byte {
	return []byte{}
}

func (n2 NullHash) Reset() {
}

func (n2 NullHash) Size() int {
	return 0
}

func (n2 NullHash) BlockSize() int {
	return 0
}

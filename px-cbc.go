package aespxcbc

import (
	"crypto/cipher"
	"crypto/subtle"
)

type pxcbcEncrypter struct {
	block     cipher.Block
	iv        []byte
	blockSize int
}

func NewPXCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		panic("cipher.NewPXCBCEncrypter: IV length must equal block size")
	}
	return &pxcbcEncrypter{
		block:     block,
		iv:        iv,
		blockSize: blockSize,
	}
}

func (x *pxcbcEncrypter) BlockSize() int {
	return x.blockSize
}

func (x *pxcbcEncrypter) CryptBlocks(dst []byte, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	if len(x.iv) != x.blockSize {
		panic("invalid IV length")
	}
	iv := x.iv
	block := make([]byte, x.blockSize)
	for len(src) > 0 {
		subtle.ConstantTimeCopy(1, block, src[:x.blockSize])
		src = src[x.blockSize:]

		subtle.XORBytes(dst[:x.blockSize], block, iv)

		x.block.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		subtle.ConstantTimeCopy(1, iv, block)
		dst = dst[x.blockSize:]
	}
	subtle.ConstantTimeCopy(1, x.iv, iv)
}

func (x *pxcbcEncrypter) SetIV(iv []byte) {
	if len(iv) != x.blockSize {
		panic("cipher: incorrect length IV")
	}
	subtle.ConstantTimeCopy(1, x.iv, iv)
}

type pxcbcDecrypter struct {
	block     cipher.Block
	iv        []byte
	blockSize int
}

func NewPXCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		panic("cipher.NewPXCBCDecrypter: IV length must equal block size")
	}
	return &pxcbcDecrypter{
		block:     block,
		iv:        iv,
		blockSize: blockSize,
	}
}

func (x *pxcbcDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *pxcbcDecrypter) CryptBlocks(dst []byte, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	iv := x.iv

	for len(src) > 0 {
		block := src[:x.blockSize]
		src = src[x.blockSize:]

		x.block.Decrypt(dst[:x.blockSize], block)
		subtle.XORBytes(dst[:x.blockSize], dst[:x.blockSize], iv)
		subtle.ConstantTimeCopy(1, iv, dst[:x.blockSize])
		dst = dst[x.blockSize:]
	}
	subtle.ConstantTimeCopy(1, x.iv, iv)
}

func (x *pxcbcDecrypter) SetIV(iv []byte) {
	if len(iv) != x.blockSize {
		panic("cipher: incorrect length IV")
	}
	subtle.ConstantTimeCopy(1, x.iv, iv)
}

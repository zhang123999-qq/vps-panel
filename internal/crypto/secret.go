// Package crypto 负责 SSH 凭证的加密存储。
// 主密钥存放在数据目录的 master.key（0600），数据库被拷走也无法直接解密。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type Box struct{ aead cipher.AEAD }

func LoadOrCreate(dir string) (*Box, error) {
	p := filepath.Join(dir, "master.key")
	key, err := os.ReadFile(p)
	if err != nil {
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, key, 0o600); err != nil {
			return nil, err
		}
	}
	if len(key) != 32 {
		return nil, errors.New("master.key 长度错误：需要 32 字节")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal 返回 base64(nonce || ciphertext)。
func (b *Box) Seal(plain []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (b *Box) Open(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("密文长度不足")
	}
	return b.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

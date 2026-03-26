package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "io"

    "golang.org/x/crypto/curve25519"

)

func GenerateKeyPair() (publicKey, privateKey [32]byte, err error) {
    if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
        return
    }
    curve25519.ScalarBaseMult(&publicKey, &privateKey)
    return
}

func ComputeSharedSecret(privateKey, peerPublicKey [32]byte) ([]byte, error) {
    // Compute Curve25519 shared secret
    secret, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
    if err != nil {
        return nil, err
    }

    // Derive a stable symmetric key (AES key) using SHA-256
    digest := sha256.Sum256(secret)
    return digest[:], nil
}


func Encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := ciphertext[:gcm.NonceSize()]
    ciphertext = ciphertext[gcm.NonceSize():]

    return gcm.Open(nil, nonce, ciphertext, nil)
}
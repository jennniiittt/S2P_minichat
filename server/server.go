package server

import (
    "bufio"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"

	"s2p_minichat/crypto"
//    "s2p_minichat/"
//    "s2p_minichat/auth"
//    "s2p_minichat/utils"
//    "s2p_minichat/config"
)

func StartServer() {
    ln, err := net.Listen("tcp", ":9000")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Server started on port 9000...")

    conn, err := ln.Accept()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Client connected!")

    // Generate server key pair
    pub, priv, _ := crypto.GenerateKeyPair()

    // Send server public key
    conn.Write(pub[:])

    // Read client public key
    var clientPub [32]byte
    _, err = conn.Read(clientPub[:])
    if err != nil {
        log.Fatal("Failed to read client pubkey:", err)
    }

    shared, err := crypto.ComputeSharedSecret(priv, clientPub)
    if err != nil {
        log.Fatal("Shared secret error:", err)
    }

    fmt.Println("Shared secret established.")

    go serverReceive(conn, shared)
    serverSend(conn, shared)
}

// read encrypted message with length prefix
func ServerReadMessage(conn net.Conn) ([]byte, error) {
    lenBuf := make([]byte, 4)
    _, err := conn.Read(lenBuf)
    if err != nil {
        return nil, err
    }

    msgLen := binary.BigEndian.Uint32(lenBuf)
    msg := make([]byte, msgLen)

    _, err = conn.Read(msg)
    return msg, err
}

func ServerSendMessage(conn net.Conn, data []byte) error {
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

    _, err := conn.Write(lenBuf)
    if err != nil {
        return err
    }
    _, err = conn.Write(data)
    return err
}

func serverReceive(conn net.Conn, key []byte) {
    for {
        encMsg, err := ServerReadMessage(conn)
        if err != nil {
            fmt.Println("Client disconnected.")
            os.Exit(0)
        }

        dec, err := crypto.Decrypt(key, encMsg)
        if err != nil {
            fmt.Println("Decrypt error:", err)
            continue
        }

        fmt.Println("Client:", string(dec))
    }
}

func serverSend(conn net.Conn, key []byte) {
    scanner := bufio.NewScanner(os.Stdin)

    for {
        fmt.Print("Server: ")
        scanner.Scan()
        msg := scanner.Text()

        if msg == "exit" {
            conn.Close()
            os.Exit(0)
        }

        enc, err := crypto.Encrypt(key, []byte(msg))
        if err != nil {
            fmt.Println("Encrypt error:", err)
            continue
        }

        ServerSendMessage(conn, enc)
    }
}
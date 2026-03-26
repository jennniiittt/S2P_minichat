/*
fmt.Print("Choose mode (SIGNUP / LOGIN): ")
scanner.Scan()
mode := scanner.Text()
ClientSendMessage(conn, []byte(mode))

fmt.Print("Username: ")
scanner.Scan()
username := scanner.Text()

fmt.Print("Password: ")
scanner.Scan()
password := scanner.Text()

ClientSendMessage(conn, []byte(username+"|"+password))

resp, _ := ClientReadMessage(conn)
fmt.Println(string(resp))

if strings.Contains(string(resp), "FAILED") {
    return // exit if failed
}
*/

package client

import (
    "bufio"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "strings"

    "s2p_minichat/crypto"
)

func StartClient() {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Server IP (Tailscale IP works): ")
    serverIP, _ := reader.ReadString('\n')
    serverIP = strings.TrimSpace(serverIP)

    conn, err := net.Dial("tcp", serverIP+":9000")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Connected to server!")

    pub, priv, _ := crypto.GenerateKeyPair()
    var serverPub [32]byte
    _, _ = conn.Read(serverPub[:])
    conn.Write(pub[:])
    shared, _ := crypto.ComputeSharedSecret(priv, serverPub)

    fmt.Print("Choose SIGNUP or LOGIN: ")
    action, _ := reader.ReadString('\n')
    action = strings.TrimSpace(action)

    fmt.Print("Username: ")
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    fmt.Print("Password: ")
    password, _ := reader.ReadString('\n')
    password = strings.TrimSpace(password)

    payload := fmt.Sprintf("%s|%s|%s", action, username, password)
    encPayload, _ := crypto.Encrypt(shared, []byte(payload))
    sendMessage(conn, encPayload)

    resp, _ := readMessage(conn)
    decResp, _ := crypto.Decrypt(shared, resp)
    fmt.Println("Server response:", string(decResp))

    if !strings.HasPrefix(string(decResp), "SUCCESS") {
        fmt.Println("Authentication failed, exiting...")
        return
    }

    go receiveLoop(conn, shared)
    sendLoop(conn, shared)
}

func readMessage(conn net.Conn) ([]byte, error) {
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

func sendMessage(conn net.Conn, data []byte) error {
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
    _, err := conn.Write(lenBuf)
    if err != nil {
        return err
    }
    _, err = conn.Write(data)
    return err
}

func receiveLoop(conn net.Conn, key []byte) {
    for {
        msg, err := readMessage(conn)
        if err != nil {
            fmt.Println("Server disconnected.")
            os.Exit(0)
        }
        dec, _ := crypto.Decrypt(key, msg)
        fmt.Println("\nServer:", string(dec))
        fmt.Print("You: ")
    }
}

func sendLoop(conn net.Conn, key []byte) {
    scanner := bufio.NewScanner(os.Stdin)
    for {
        fmt.Print("You: ")
        scanner.Scan()
        text := scanner.Text()
        if text == "exit" {
            conn.Close()
            os.Exit(0)
        }
        enc, _ := crypto.Encrypt(key, []byte(text))
        sendMessage(conn, enc)
    }
}




















/*package client

import (
    "bufio"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"

	"s2p_minichat/crypto"
)

func StartClient() {
    conn, err := net.Dial("tcp", "localhost:9000")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Connected to server!")

    pub, priv, _ := crypto.GenerateKeyPair()

    // Read server pubkey
    var serverPub [32]byte
    _, err = conn.Read(serverPub[:])
    if err != nil {
        log.Fatal("Failed to read server pubkey:", err)
    }

    conn.Write(pub[:])

    shared, err := crypto.ComputeSharedSecret(priv, serverPub)
    if err != nil {
        log.Fatal("Shared secret error:", err)
    }

    fmt.Println("Shared secret established.")

    go clientReceive(conn, shared)
    clientSend(conn, shared)
}

// read encrypted message with length prefix
func ClientReadMessage(conn net.Conn) ([]byte, error) {
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

func ClientSendMessage(conn net.Conn, data []byte) error {
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

    _, err := conn.Write(lenBuf)
    if err != nil {
        return err
    }
    _, err = conn.Write(data)
    return err
}


func clientReceive(conn net.Conn, key []byte) {
    for {
        encMsg, err := ClientReadMessage(conn)
        if err != nil {
            fmt.Println("Server disconnected.")
            os.Exit(0)
        }

        dec, err := crypto.Decrypt(key, encMsg)
        if err != nil {
            fmt.Println("Decrypt error:", err)
            continue
        }

        fmt.Println("\nServer:", string(dec))
        fmt.Print("You: ")
    }
}

func clientSend(conn net.Conn, key []byte) {
    scanner := bufio.NewScanner(os.Stdin)

    for {
        fmt.Print("You: ")
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

        ClientSendMessage(conn, enc)
    }
}
*/
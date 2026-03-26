package server

import (
    "bufio"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"

    "golang.org/x/crypto/bcrypt"
    "s2p_minichat/crypto"
)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"` // bcrypt hashed
}

var usersFile = "users.json"
var users = map[string]string{} // username -> hashed password

func loadUsers() {
    f, err := os.Open(usersFile)
    if err != nil {
        return
    }
    defer f.Close()
    json.NewDecoder(f).Decode(&users)
}

func saveUsers() {
    f, _ := os.Create(usersFile)
    defer f.Close()
    json.NewEncoder(f).Encode(users)
}

func StartServer() {
    loadUsers()

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

    pub, priv, _ := crypto.GenerateKeyPair()
    conn.Write(pub[:])

    var clientPub [32]byte
    _, err = conn.Read(clientPub[:])
    if err != nil {
        log.Fatal(err)
    }

    shared, err := crypto.ComputeSharedSecret(priv, clientPub)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Shared secret established.")

    // Authentication first
    if !authenticateClient(conn, shared) {
        fmt.Println("Authentication failed. Closing connection.")
        conn.Close()
        return
    }

    fmt.Println("User authenticated! Starting chat...")
    go serverReceive(conn, shared)
    serverSend(conn, shared)
}

func authenticateClient(conn net.Conn, key []byte) bool {
    encMsg, _ := ServerReadMessage(conn)
    msg, _ := crypto.Decrypt(key, encMsg)
    input := string(msg)

    parts := []string{}
    for _, v := range input {
        if v == '|' {
            parts = append(parts, "")
        } else {
            if len(parts) == 0 {
                parts = append(parts, "")
            }
            parts[len(parts)-1] += string(v)
        }
    }

    if len(parts) < 3 {
        ServerSendMessage(conn, mustEncrypt(key, []byte("FAIL|Invalid input")))
        return false
    }

    action, username, password := parts[0], parts[1], parts[2]

    switch action {
    case "SIGNUP":
        if _, ok := users[username]; ok {
            ServerSendMessage(conn, mustEncrypt(key, []byte("FAIL|Username exists")))
            return false
        }
        hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        users[username] = string(hash)
        saveUsers()
        ServerSendMessage(conn, mustEncrypt(key, []byte("SUCCESS|Signed up")))
        return true
    case "LOGIN":
        hash, ok := users[username]
        if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
            ServerSendMessage(conn, mustEncrypt(key, []byte("FAIL|Wrong credentials")))
            return false
        }
        ServerSendMessage(conn, mustEncrypt(key, []byte("SUCCESS|Logged in")))
        return true
    default:
        ServerSendMessage(conn, mustEncrypt(key, []byte("FAIL|Unknown action")))
        return false
    }
}

// Utility for encryption
func mustEncrypt(key, msg []byte) []byte {
    enc, _ := crypto.Encrypt(key, msg)
    return enc
}

// === Existing chat logic ===
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
        dec, _ := crypto.Decrypt(key, encMsg)
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
        enc, _ := crypto.Encrypt(key, []byte(msg))
        ServerSendMessage(conn, enc)
    }
}
package server

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

    // KEY EXCHANGE PART
    pub, priv, _ := crypto.GenerateKeyPair()
    var serverPub [32]byte
    _, _ = conn.Read(serverPub[:])
    conn.Write(pub[:])
    shared, _ := crypto.ComputeSharedSecret(priv, serverPub)

    // AUTHENTICATION LOOP
    const maxAttempts = 3
    authenticated := false

    for i := 0; i < maxAttempts && !authenticated; i++ {
        fmt.Print("Choose SIGNUP or LOGIN: ")
        action, _ := reader.ReadString('\n')
        action = strings.TrimSpace(strings.ToLower(action))

        fmt.Print("Username: ")
        username, _ := reader.ReadString('\n')
        username = strings.TrimSpace(username)

        fmt.Print("Password: ")
        password, _ := reader.ReadString('\n')
        password = strings.TrimSpace(password)

        // Send encrypted payload to server
        payload := fmt.Sprintf("%s|%s|%s", action, username, password)
        encPayload, _ := crypto.Encrypt(shared, []byte(payload))
        sendMessage(conn, encPayload)

        resp, _ := readMessage(conn)
        decResp, _ := crypto.Decrypt(shared, resp)
        message := string(decResp)
        fmt.Println("Server response:", message)

        // Check response
        if strings.HasPrefix(message, "Authentication successful") {
            authenticated = true
        } else {
            attemptsLeft := maxAttempts - i - 1
            if attemptsLeft > 0 {
                fmt.Printf("Login failed. Attempts left: %d\n", attemptsLeft)
            } else {
                fmt.Println("Too many failed attempts. Exiting...")
                return
            }
        }
    }

    // Start chat loops after successful authentication
    go receiveLoop(conn, shared)
    sendLoop(conn, shared)
}

// --- Helper functions ---
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





/*package server

import (
    "bufio"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "strings"

    "s2p_minichat/auth"
    "s2p_minichat/crypto"
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

    // AUTHENTICATION PART
    const maxAttempts = 3
    authenticated := false

    for i := 0; i < maxAttempts && !authenticated; i++ {
        conn.Write([]byte("Type 'signup' or 'login': "))
        authTypeBuf := make([]byte, 1024)
        n, _ := conn.Read(authTypeBuf)
        authType := strings.TrimSpace(string(authTypeBuf[:n]))

        conn.Write([]byte("Username: "))
        userBuf := make([]byte, 1024)
        n, _ = conn.Read(userBuf)
        username := strings.TrimSpace(string(userBuf[:n]))

        conn.Write([]byte("Password: "))
        passBuf := make([]byte, 1024)
        n, _ = conn.Read(passBuf)
        password := strings.TrimSpace(string(passBuf[:n]))

        path := "users.json"

        switch authType {
        case "signup":
            err := auth.Signup(path, username, password)
            if err != nil {
                conn.Write([]byte("Signup failed: " + err.Error() + "\n"))
            } else {
                conn.Write([]byte("Signup successful! Now login.\n"))
            }
            // i is not incremented here because signup doesn't count as a failed login
            i--
        case "login":
            err := auth.Authenticate(path, username, password)
            if err != nil {
                attemptsLeft := maxAttempts - i - 1
                msg := fmt.Sprintf("Login failed. Attempts left: %d\n", attemptsLeft)
                conn.Write([]byte(msg))
            } else {
                conn.Write([]byte("Authentication successful!\n"))
                authenticated = true
            }
        default:
            conn.Write([]byte("Invalid option, try again.\n"))
            i-- // invalid choice doesn't count as attempt
        }
    }

    if !authenticated {
        conn.Write([]byte("Too many failed attempts. Connection closed.\n"))
        conn.Close()
        return
    }

    // KEY EXCHANGE PART
    pub, priv, _ := crypto.GenerateKeyPair()
    conn.Write(pub[:])

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

*/









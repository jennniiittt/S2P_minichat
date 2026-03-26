package main

import (
    "bufio"
    "fmt"
    "os"
    "strings"

	"s2p_minichat/server"
	"s2p_minichat/client"
)

func main() {
    fmt.Println("Choose mode: server or client")
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Mode: ")
    mode, _ := reader.ReadString('\n')
    mode = strings.TrimSpace(mode)

    switch mode {
		case "server":
			server.StartServer()
		case "client":
			client.StartClient()
		default:
			fmt.Println("Invalid mode. Choose 'server' or 'client'.")
	}

}
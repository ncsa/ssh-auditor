package sshauditor

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func promptCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprintf(os.Stderr, "Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Fprintf(os.Stderr, "Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		panic(err)
	}
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

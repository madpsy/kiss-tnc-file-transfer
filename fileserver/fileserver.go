// fileserver.go
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go.bug.st/serial"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"sort"
)

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global variable for server's callsign.
var serverCallsign string

// Command-line arguments structure.
type Arguments struct {
	MyCallsign     string // your own callsign
	Connection     string // "tcp" or "serial"
	Host           string // used with TCP
	Port           int    // used with TCP
	SerialPort     string // used with serial
	Baud           int    // used with serial
	GetCallsigns   string // comma-delimited list for filtering GET sender callsigns (supports wildcards)
	PutCallsigns   string // comma-delimited list for filtering PUT sender callsigns (supports wildcards)
	ServeDirectory string // directory to serve files from (mandatory)
	SaveDirectory  string // where received files should be saved (default current directory)
	SenderBinary   string // path to the binary used to send files (mandatory)
	ReceiverBinary string // path to the binary used to receive files (default "receiver")
	SenderPort     int    // TCP port for transparent passthrough (default 5011)
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host (if connection is tcp)")
	flag.IntVar(&args.Port, "port", 9001, "TCP port (if connection is tcp)")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g., COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial connection")
	flag.StringVar(&args.GetCallsigns, "get-callsigns", "", "Comma delimited list of allowed sender callsign patterns for GET command (supports wildcards, e.g. MM5NDH-*,*-15)")
	flag.StringVar(&args.PutCallsigns, "put-callsigns", "", "Comma delimited list of allowed sender callsign patterns for PUT command (supports wildcards)")
	flag.StringVar(&args.ServeDirectory, "serve-directory", "", "Directory to serve files from (mandatory)")
	flag.StringVar(&args.SaveDirectory, "save-directory", ".", "Directory where received files should be saved (default current directory)")
	flag.StringVar(&args.SenderBinary, "sender-binary", "", "Path to the binary used to send files (mandatory)")
	flag.StringVar(&args.ReceiverBinary, "receiver-binary", "receiver", "Path to the binary used to receive files (default 'receiver')")
	flag.IntVar(&args.SenderPort, "sender-port", 5011, "TCP port for transparent passthrough (default 5011)")
	flag.Parse()

	if args.MyCallsign == "" {
		log.Fatalf("--my-callsign is required.")
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	if args.ServeDirectory == "" {
		log.Fatalf("--serve-directory is required.")
	}
	if args.SenderBinary == "" {
		log.Fatalf("--sender-binary is required.")
	}
	return args
}

// KISSConnection is the minimal interface we need.
type KISSConnection interface {
	RecvData(timeout time.Duration) ([]byte, error)
	Write([]byte) (int, error)
	Close() error
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn net.Conn
	lock sync.Mutex
}

func newTCPKISSConnection(host string, port int) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("[TCP] Connected to %s", addr)
	return &TCPKISSConnection{conn: conn}, nil
}

func (t *TCPKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := t.conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			return []byte{}, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (t *TCPKISSConnection) Write(b []byte) (int, error) {
	return t.conn.Write(b)
}

func (t *TCPKISSConnection) Close() error {
	return t.conn.Close()
}

// SerialKISSConnection implements KISSConnection over serial.
type SerialKISSConnection struct {
	ser serial.Port
}

func newSerialKISSConnection(portName string, baud int) (*SerialKISSConnection, error) {
	mode := &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	ser, err := serial.Open(portName, mode)
	if err != nil {
		return nil, err
	}
	if err := ser.SetReadTimeout(100 * time.Millisecond); err != nil {
		return nil, err
	}
	log.Printf("[Serial] Opened %s at %d baud", portName, baud)
	return &SerialKISSConnection{ser: ser}, nil
}

func (s *SerialKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := s.ser.Read(buf)
	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, err
	}
	return buf[:n], nil
}

func (s *SerialKISSConnection) Write(b []byte) (int, error) {
	return s.ser.Write(b)
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// Helper: unescapeData reverses KISS escaping.
func unescapeData(data []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(data); {
		b := data[i]
		if b == 0xDB && i+1 < len(data) {
			nxt := data[i+1]
			if nxt == 0xDC {
				out.WriteByte(KISS_FLAG)
				i += 2
				continue
			} else if nxt == 0xDD {
				out.WriteByte(0xDB)
				i += 2
				continue
			}
		}
		out.WriteByte(b)
		i++
	}
	return out.Bytes()
}

// Helper: escapeData applies KISS escaping.
func escapeData(data []byte) []byte {
	var out bytes.Buffer
	for _, b := range data {
		if b == KISS_FLAG {
			out.WriteByte(0xDB)
			out.WriteByte(0xDC)
		} else if b == 0xDB {
			out.WriteByte(0xDB)
			out.WriteByte(0xDD)
		} else {
			out.WriteByte(b)
		}
	}
	return out.Bytes()
}

// sendResponse wraps the payload in a KISS frame and writes it directly to the connection.
func sendResponse(conn KISSConnection, responsePayload []byte) error {
	escaped := escapeData(responsePayload)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	_, err := conn.Write(frame)
	return err
}

// sendResponseWithDetails builds the response packet, logs the details, and sends it.
func sendResponseWithDetails(conn KISSConnection, cmdID, command string, status int, msg string) error {
	responsePayload := createResponsePacket(cmdID, status, msg)
	escaped := escapeData(responsePayload)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)

	statusText := "FAILED"
	if status == 1 {
		statusText = "SUCCESS"
	}
	log.Printf("Sending RSP packet for command '%s' (ID: %s): %s - %s", command, cmdID, statusText, msg)
	_, err := conn.Write(frame)
	return err
}

// Helper: extractKISSFrames extracts complete KISS frames from a buffer.
func extractKISSFrames(data []byte) ([][]byte, []byte) {
	var frames [][]byte
	for {
		start := bytes.IndexByte(data, KISS_FLAG)
		if start == -1 {
			break
		}
		end := bytes.IndexByte(data[start+1:], KISS_FLAG)
		if end == -1 {
			break
		}
		end = start + 1 + end
		frame := data[start : end+1]
		frames = append(frames, frame)
		data = data[end+1:]
	}
	return frames, data
}

// encodeAX25Address now supports SSIDs.
func encodeAX25Address(callsign string, isLast bool) []byte {
	parts := strings.Split(callsign, "-")
	base := strings.ToUpper(strings.TrimSpace(parts[0]))
	var ssid int
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &ssid)
	}
	if len(base) < 6 {
		base = base + strings.Repeat(" ", 6-len(base))
	} else if len(base) > 6 {
		base = base[:6]
	}
	addr := make([]byte, 7)
	for i := 0; i < 6; i++ {
		addr[i] = base[i] << 1
	}
	addr[6] = byte((ssid & 0x0F) << 1) | 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// decodeAX25Address decodes a 7-byte AX.25 address field.
func decodeAX25Address(addr []byte) string {
	if len(addr) < 7 {
		return ""
	}
	var call bytes.Buffer
	for i := 0; i < 6; i++ {
		call.WriteByte(addr[i] >> 1)
	}
	base := strings.TrimSpace(call.String())
	ssid := (addr[6] >> 1) & 0x0F
	if ssid != 0 {
		return fmt.Sprintf("%s-%d", base, ssid)
	}
	return base
}

// parseCommandPacket now extracts the 2-character ID after "CMD:".
func parseCommandPacket(packet []byte) (sender, cmdID, command string, ok bool) {
	if len(packet) < 80 {
		return "", "", "", false
	}
	header := packet[:16]
	dest := decodeAX25Address(header[0:7])
	if dest != serverCallsign {
		log.Printf("Dropping packet: destination %s does not match our callsign %s", dest, serverCallsign)
		return "", "", "", false
	}
	infoField := packet[16:80]
	infoStr := strings.TrimSpace(string(infoField))
	if !strings.HasPrefix(infoStr, "CMD:") {
		return "", "", "", false
	}
	// Ensure there is room for a 2-character ID
	if len(infoStr) < 6 {
		return "", "", "", false
	}
	cmdID = infoStr[4:6]
	command = strings.TrimSpace(infoStr[6:])
	sender = decodeAX25Address(header[7:14])
	return sender, cmdID, command, true
}

// createResponsePacket builds the response payload.
// The response format is "RSP:<cmdID> <status> <message>" padded or truncated to 64 bytes.
func createResponsePacket(cmdID string, status int, msg string) []byte {
	responseText := fmt.Sprintf("RSP:%s %d %s", cmdID, status, msg)
	if len(responseText) > 64 {
		responseText = responseText[:64]
	} else {
		responseText = responseText + strings.Repeat(" ", 64-len(responseText))
	}
	return []byte(responseText)
}

// Global slices for allowed sender callsigns for GET and PUT.
var getAllowedCallsigns []string
var putAllowedCallsigns []string

func callsignAllowedForGet(cs string) bool {
	// If no restrictions provided, allow all.
	if len(getAllowedCallsigns) == 0 {
		return true
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range getAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

func callsignAllowedForPut(cs string) bool {
	// If no restrictions provided, allow all.
	if len(putAllowedCallsigns) == 0 {
		return true
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range putAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

func listFiles(dir string) (string, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	// Filter out directories and files starting with a dot.
	var files []os.FileInfo
	for _, entry := range entries {
		if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			files = append(files, entry)
		}
	}

	// Sort files alphanumerically by filename.
	sort.Slice(files, func(i, j int) bool {
		return strings.ToLower(files[i].Name()) < strings.ToLower(files[j].Name())
	})

	var output strings.Builder

	// Write header.
	output.WriteString(fmt.Sprintf("%-30s %-20s %10s\n", "File Name", "Modified Date", "Size"))
	output.WriteString(strings.Repeat("-", 65) + "\n")

	// Write file details.
	for _, file := range files {
		modTime := file.ModTime().Format("2006-01-02 15:04:05")
		output.WriteString(fmt.Sprintf("%-30s %-20s %10d\n", file.Name(), modTime, file.Size()))
	}
	return output.String(), nil
}

// --- Broadcaster ---
// This helper will allow multiple goroutines (the command processor and transparent passthrough)
// to receive the same data coming from the underlying KISS connection.
type Broadcaster struct {
	subscribers map[chan []byte]struct{}
	lock        sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan []byte]struct{}),
	}
}

func (b *Broadcaster) Subscribe() chan []byte {
	ch := make(chan []byte, 100)
	b.lock.Lock()
	b.subscribers[ch] = struct{}{}
	b.lock.Unlock()
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan []byte) {
	b.lock.Lock()
	delete(b.subscribers, ch)
	close(ch)
	b.lock.Unlock()
}

func (b *Broadcaster) Broadcast(data []byte) {
	b.lock.Lock()
	defer b.lock.Unlock()
	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
		}
	}
}

// startKISSReader continuously reads from the underlying connection and broadcasts data.
func startKISSReader(conn KISSConnection, b *Broadcaster) {
	for {
		data, err := conn.RecvData(100 * time.Millisecond)
		if err != nil {
			if err != io.EOF {
				log.Printf("Underlying read error: %v", err)
			}
			break
		}
		if len(data) > 0 {
			b.Broadcast(data)
		}
	}
}

// --- Transparent Passthrough Handler ---
// This function relays data in both directions between the connected client and the underlying KISS connection.
func handleTransparentConnection(remoteConn net.Conn, b *Broadcaster, conn KISSConnection) {
	defer remoteConn.Close()
	log.Printf("Accepted transparent connection from %s", remoteConn.RemoteAddr())
	// Start forwarding data from the transparent connection to the underlying KISS connection.
	go func() {
		_, err := io.Copy(conn, remoteConn)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Error copying from transparent client to underlying: %v", err)
		}
	}()
	// Subscribe to the broadcaster to forward underlying data to the transparent client.
	sub := b.Subscribe()
	defer b.Unsubscribe(sub)
	for data := range sub {
		_, err := remoteConn.Write(data)
		if err != nil {
			return
		}
	}
}

// startTransparentListener listens on the SenderPort and handles transparent connections.
func startTransparentListener(port int, b *Broadcaster, conn KISSConnection) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Transparent listener error: %v", err)
	}
	defer listener.Close()
	log.Printf("Transparent sender listener active on %s", addr)
	for {
		remoteConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting transparent connection: %v", err)
			continue
		}
		go handleTransparentConnection(remoteConn, b, conn)
	}
}

// --- Invoking the Sender Binary ---
// This function is still used for sending files (for GET file transfers) via the sender binary.
func invokeSenderBinary(args *Arguments, receiverCallsign, fileName, inputData, cmdID string) {
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-connection=tcp", "-host=localhost", fmt.Sprintf("-port=%d", args.SenderPort))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-receiver-callsign=%s", receiverCallsign))
	cmdArgs = append(cmdArgs, "-stdin", "-file-name="+fileName)
	cmdArgs = append(cmdArgs, fmt.Sprintf("-fileid=%s", cmdID))
	fullCmd := fmt.Sprintf("%s %s", args.SenderBinary, strings.Join(cmdArgs, " "))
	log.Printf("Invoking sender binary: %s", fullCmd)

	cmd := exec.Command(args.SenderBinary, cmdArgs...)
	if inputData != "" {
		cmd.Stdin = strings.NewReader(inputData)
	} else {
		cmd.Stdin = os.Stdin
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Error obtaining stdout pipe: %v", err)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Error obtaining stderr pipe: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Error starting sender binary: %v", err)
		return
	}
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			log.Printf("[sender stdout] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading sender stdout: %v", err)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[sender stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading sender stderr: %v", err)
		}
	}()
	if err := cmd.Wait(); err != nil {
		log.Printf("Sender binary exited with error: %v", err)
	} else {
		log.Printf("Sender binary completed successfully.")
	}
}

// --- Invoking the Receiver Binary ---
// For a PUT command, this function attempts to start the receiver binary.
// It first tries to obtain stdout and stderr pipes and calls cmd.Start().
// If starting fails (for example, if the binary is not found), it returns an error.
// If starting succeeds, it spawns a goroutine to capture stdout (the received file)
// and write it to a file in the save directory.
func invokeReceiverBinary(args *Arguments, senderCallsign, fileName, cmdID string) error {
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-connection=tcp", "-host=localhost", fmt.Sprintf("-port=%d", args.SenderPort))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-callsigns=%s", senderCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-fileid=%s", cmdID))
        cmdArgs = append(cmdArgs, fmt.Sprintf("-one-file"))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-stdout"))
	fullCmd := fmt.Sprintf("%s %s", args.ReceiverBinary, strings.Join(cmdArgs, " "))
	log.Printf("Invoking receiver binary: %s", fullCmd)

	cmd := exec.Command(args.ReceiverBinary, cmdArgs...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Error obtaining stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("Error obtaining stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Error starting receiver binary: %v", err)
	}

	// Spawn goroutine to log any stderr output.
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[receiver stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading receiver stderr: %v", err)
		}
	}()

	// Spawn goroutine to capture stdout and save the file.
	go func() {
		output, err := io.ReadAll(stdoutPipe)
		if err != nil {
			log.Printf("Error reading receiver stdout: %v", err)
			return
		}
		if err := cmd.Wait(); err != nil {
			log.Printf("Receiver binary exited with error: %v", err)
			return
		}
		// Write the output to the specified file in the save directory.
		savePath := filepath.Join(args.SaveDirectory, fileName)
		// If the file exists, append _1, _2, etc. before the extension.
		if _, err := os.Stat(savePath); err == nil {
			baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
			ext := filepath.Ext(fileName)
			counter := 1
			for {
				newFileName := fmt.Sprintf("%s_%d%s", baseName, counter, ext)
				newPath := filepath.Join(args.SaveDirectory, newFileName)
				if _, err := os.Stat(newPath); os.IsNotExist(err) {
					savePath = newPath
					break
				}
				counter++
			}
		}
		err = ioutil.WriteFile(savePath, output, 0644)
		if err != nil {
			log.Printf("Error writing received file to %s: %v", savePath, err)
			return
		}
		log.Printf("Received file saved to %s", savePath)

	}()
	return nil
}

func main() {
	args := parseArguments()
	serverCallsign = strings.ToUpper(args.MyCallsign)
	log.Printf("Serving files from directory: %s", args.ServeDirectory)
	log.Printf("Sender binary set to: %s", args.SenderBinary)
	log.Printf("Receiver binary set to: %s", args.ReceiverBinary)

	// Populate allowed GET callsigns.
	if args.GetCallsigns != "" {
		for _, cs := range strings.Split(args.GetCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				getAllowedCallsigns = append(getAllowedCallsigns, cs)
			}
		}
		log.Printf("Allowed GET sender callsign patterns: %v", getAllowedCallsigns)
	} else {
		log.Printf("No GET callsign filtering enabled.")
	}

	// Populate allowed PUT callsigns.
	if args.PutCallsigns != "" {
		for _, cs := range strings.Split(args.PutCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				putAllowedCallsigns = append(putAllowedCallsigns, cs)
			}
		}
		log.Printf("Allowed PUT sender callsign patterns: %v", putAllowedCallsigns)
	} else {
		log.Printf("No PUT callsign filtering enabled.")
	}

	// Establish the underlying KISS connection.
	var conn KISSConnection
	var err error
	if strings.ToLower(args.Connection) == "tcp" {
		conn, err = newTCPKISSConnection(args.Host, args.Port)
		if err != nil {
			log.Fatalf("TCP connection error: %v", err)
		}
	} else {
		conn, err = newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("Serial connection error: %v", err)
		}
	}
	defer conn.Close()

	log.Printf("File Server started. My callsign: %s", serverCallsign)

	// Create a broadcaster to distribute data read from the underlying connection.
	broadcaster := NewBroadcaster()
	go startKISSReader(conn, broadcaster)
	// Start the transparent passthrough listener.
	go startTransparentListener(args.SenderPort, broadcaster, conn)

	// Command processing: subscribe to the broadcaster.
	cmdSub := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(cmdSub)
	var buffer []byte
	for data := range cmdSub {
		buffer = append(buffer, data...)
		frames, remaining := extractKISSFrames(buffer)
		buffer = remaining
		for _, frame := range frames {
			if len(frame) < 2 || frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
				continue
			}
			inner := frame[2 : len(frame)-1]
			unesc := unescapeData(inner)
			sender, cmdID, command, ok := parseCommandPacket(unesc)
			if !ok {
				continue
			}
			upperCmd := strings.ToUpper(command)
			// Process GET command
			if strings.HasPrefix(upperCmd, "GET ") {
    if !callsignAllowedForGet(sender) {
        log.Printf("Dropping GET command from sender %s: not allowed.", sender)
        
        // Send a response packet indicating the GET request is not allowed.
        sendResponseWithDetails(conn, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
        
        continue
    }
    fileName := strings.TrimSpace(command[4:])
    fullPath := filepath.Join(args.ServeDirectory, fileName)
    content, err := ioutil.ReadFile(fullPath)
    if err != nil {
        log.Printf("Requested file '%s' does not exist in directory %s", fileName, args.ServeDirectory)
        sendResponseWithDetails(conn, cmdID, command, 0, "CANNOT FIND/READ FILE")
        continue
    }
    // Double-check file read.
    _, err = ioutil.ReadFile(fullPath)
    if err != nil {
        log.Printf("Error reading file '%s': %v", fullPath, err)
        sendResponseWithDetails(conn, cmdID, command, 0, "GET FAILED")
        continue
    }
    sendResponseWithDetails(conn, cmdID, command, 1, "GET OK")
    go invokeSenderBinary(args, sender, fileName, string(content), cmdID)
} else if strings.HasPrefix(upperCmd, "LIST") {
				listing, err := listFiles(args.ServeDirectory)
				if err != nil {
					log.Printf("Error listing files: %v", err)
					sendResponseWithDetails(conn, cmdID, command, 0, "LIST CANNOT READ")
					continue
				}
				// Send the RSP packet indicating LIST is OK.
				sendResponseWithDetails(conn, cmdID, command, 1, "LIST OK")
				// Invoke the sender binary to send the listing as LIST.txt.
				go invokeSenderBinary(args, sender, "LIST.txt", listing, cmdID)
			} else if strings.HasPrefix(upperCmd, "PUT ") {
				// Process PUT command for receiving files.
				if !callsignAllowedForPut(sender) {
					log.Printf("PUT command from sender %s not allowed.", sender)
					sendResponseWithDetails(conn, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				fileName := strings.TrimSpace(command[4:])
				// Attempt to start the receiver binary synchronously.
				err := invokeReceiverBinary(args, sender, fileName, cmdID)
				if err != nil {
					log.Printf("Receiver binary error: %v", err)
					sendResponseWithDetails(conn, cmdID, command, 0, "PUT FAILED: CANNOT START RECEIVER")
				} else {
					sendResponseWithDetails(conn, cmdID, command, 1, "PUT OK - WAITING FOR FILE")
				}
			} else {
				log.Printf("Unrecognized command: %s", command)
				sendResponseWithDetails(conn, cmdID, command, 0, "UNKNOWN COMMAND. AVAILABLE: LIST, GET, PUT")
			}
		}
	}
}

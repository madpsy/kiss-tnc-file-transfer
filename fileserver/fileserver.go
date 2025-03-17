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
	"sort"
	"strings"
	"sync"
	"time"
	"regexp"
)

// --- Global Constants and Variables ---

var disallowedFilenames = []string{
	"LIST.txt", // used internally for file lists
}

// KISS framing constants.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global variable for server's callsign.
var serverCallsign string

var globalArgs *Arguments

// Control connection globals and reconnection logic.
var (
	lastDataTime   time.Time
	reconnectMutex sync.Mutex
	reconnecting   bool
	// globalConn is the control (command) connection.
	globalConn KISSConnection
	// broadcaster is used for command/control messages.
	broadcaster *Broadcaster
	connLock    sync.RWMutex // Protects access to globalConn.
)

// File transfer connection globals and reconnection logic.
var (
	fileConn         KISSConnection
	fileConnLock     sync.RWMutex
	fileReconnectMux sync.Mutex
	fileReconnecting bool
)

// Allowed sender callsigns.
var getAllowedCallsigns []string
var putAllowedCallsigns []string
// Allowed ADMIN callsigns – if empty, admin commands are denied.
var adminAllowedCallsigns []string

// Maximum allowed file name length.
const maxFileNameLen = 58

// Absolute paths for directories.
var absServeDir string
var absSaveDir string

// Global maps for tracking running sender/receiver processes.
var runningSender sync.Map
var runningReceiver sync.Map

var allowedDirName = regexp.MustCompile(`^[A-Za-z0-9._()\-]+$`)
var allowedFileName = regexp.MustCompile(`^[A-Za-z0-9._()/\-]+$`)

// --- Duplicate Response Cache ---
type cachedResponse struct {
	timestamp time.Time
	frame     []byte
}

var (
	rspCache     = make(map[string]cachedResponse)
	rspCacheLock sync.Mutex
)

// cacheCleanup periodically removes cache entries older than 30 seconds.
func cacheCleanup() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		rspCacheLock.Lock()
		for key, cached := range rspCache {
			if now.Sub(cached.timestamp) > 30*time.Second {
				delete(rspCache, key)
			}
		}
		rspCacheLock.Unlock()
	}
}

// --- In-progress Command Tracking ---
var (
	processingCommands     = make(map[string]chan struct{})
	processingCommandsLock sync.Mutex
)

// --- Active Transfer Tracking ---
var (
	activeTransfers     = make(map[string]string)
	activeTransfersLock sync.Mutex
)

// --- Thread-safe Connection Accessor Functions ---

func isFilenameDisallowed(fileName string) bool {
	for _, disallowed := range disallowedFilenames {
		if strings.EqualFold(fileName, disallowed) {
			return true
		}
	}
	return false
}

func getConn() KISSConnection {
	connLock.RLock()
	defer connLock.RUnlock()
	return globalConn
}

func setConn(newConn KISSConnection) {
	connLock.Lock()
	if globalConn != nil {
		globalConn.Close()
	}
	globalConn = newConn
	connLock.Unlock()
}

func getFileConn() KISSConnection {
	fileConnLock.RLock()
	defer fileConnLock.RUnlock()
	return fileConn
}

func setFileConn(newConn KISSConnection) {
	fileConnLock.Lock()
	if fileConn != nil {
		fileConn.Close()
	}
	fileConn = newConn
	fileConnLock.Unlock()
}

func activeTransferExists() bool {
    active := false
    runningSender.Range(func(key, value interface{}) bool {
        active = true
        return false // exit early once one is found
    })
    if active {
        return true
    }
    runningReceiver.Range(func(key, value interface{}) bool {
        active = true
        return false
    })
    return active
}

// --- Command-line Arguments Structure ---

type Arguments struct {
	MyCallsign        string // your own callsign
	Connection        string // "tcp" or "serial"
	Host              string // used with TCP
	Port              int    // used with TCP
	SerialPort        string // used with serial
	Baud              int    // used with serial
	GetCallsigns      string // comma-delimited list for allowed GET sender callsigns
	PutCallsigns      string // comma-delimited list for allowed PUT sender callsigns
	AdminCallsigns    string // comma-delimited list for allowed ADMIN commands
	ServeDirectory    string // directory to serve files from (unless -per-callsign is used)
	SaveDirectory     string // where received files should be saved
	SenderBinary      string // path to the binary used to send files
	ReceiverBinary    string // path to the binary used to receive files
	PassthroughPort   int    // TCP port for transparent passthrough
	IdPeriod          int    // Minutes between sending an ID packet (0 means never)
	PerCallsignDir    string // base directory for per-callsign subdirectories
	OverwriteExisting bool   // if true, overwrite existing files instead of appending _x
	MaxConcurrency    int    // Maximum concurrent transfers allowed (default 1)
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host (if connection is tcp)")
	flag.IntVar(&args.Port, "port", 9001, "TCP port (if connection is tcp)")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g., COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial connection")
	flag.StringVar(&args.GetCallsigns, "get-callsigns", "", "Comma delimited list for allowed GET sender callsigns")
	flag.StringVar(&args.PutCallsigns, "put-callsigns", "", "Comma delimited list for allowed PUT sender callsigns")
	flag.StringVar(&args.AdminCallsigns, "admin-callsigns", "", "Comma delimited list for allowed ADMIN commands")
	flag.StringVar(&args.ServeDirectory, "serve-directory", "", "Directory to serve files from (unless -per-callsign is used)")
	flag.StringVar(&args.SaveDirectory, "save-directory", ".", "Directory where received files should be saved")
	flag.StringVar(&args.SenderBinary, "sender-binary", "sender", "Path to the binary used to send files")
	flag.StringVar(&args.ReceiverBinary, "receiver-binary", "receiver", "Path to the binary used to receive files")
	flag.IntVar(&args.PassthroughPort, "passthrough-port", 5011, "TCP port for transparent passthrough")
	flag.IntVar(&args.IdPeriod, "id-period", 30, "Minutes between sending an ID packet (0 means never)")
	flag.StringVar(&args.PerCallsignDir, "per-callsign", "", "Base directory for per-callsign subdirectories")
	flag.BoolVar(&args.OverwriteExisting, "overwrite-existing", false, "Overwrite existing files instead of appending _x")
	flag.IntVar(&args.MaxConcurrency, "max-concurrency", 1, "Maximum concurrent transfers allowed (GET/PUT)")
	flag.Parse()

	if args.PerCallsignDir != "" {
		if args.ServeDirectory != "" || args.SaveDirectory != "." || args.GetCallsigns != "" || args.PutCallsigns != "" || args.AdminCallsigns != "" {
			log.Fatalf("When using -per-callsign, do not specify serve-directory, save-directory, get-callsigns, put-callsigns or admin-callsigns.")
		}
	} else if args.ServeDirectory == "" {
		log.Fatalf("--serve-directory is required.")
	}
	if args.MyCallsign == "" {
		log.Fatalf("--my-callsign is required.")
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	return args
}

// --- KISSConnection Interface and Implementations ---

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
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.conn.Write(b)
}

func (t *TCPKISSConnection) Close() error {
	return t.conn.Close()
}

// SerialKISSConnection implements KISSConnection over serial.
type SerialKISSConnection struct {
	ser  serial.Port
	lock sync.Mutex
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
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.ser.Write(b)
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// --- KISS Frame Functions ---

func createRSPPacket(destCallsign, srcCallsign, cmdID string, status int, msg string) []byte {
	destAddr := encodeAX25Address(destCallsign, false)
	srcAddr := encodeAX25Address(srcCallsign, true)
	header := append(append(destAddr, srcAddr...), 0x03, 0xF0)
	responseText := fmt.Sprintf("%s:RSP:%d:%s", cmdID, status, msg)
	infoField := []byte(responseText)
	return append(header, infoField...)
}

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

func sendResponse(responsePayload []byte) error {
	conn := getConn()
	escaped := escapeData(responsePayload)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	_, err := conn.Write(frame)
	return err
}

func sendResponseWithDetails(sender, cmdID, command string, status int, msg string) ([]byte, error) {
	conn := getConn()
	rspPacket := createRSPPacket(sender, serverCallsign, cmdID, status, msg)
	escaped := escapeData(rspPacket)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	statusText := "FAILED"
	if status == 1 {
		statusText = "SUCCESS"
	}
	log.Printf("Sending RSP packet to sender %s for command '%s' (ID: %s): %s - %s", sender, command, cmdID, statusText, msg)
	_, err := conn.Write(frame)
	cacheKey := sender + ":" + cmdID
	rspCacheLock.Lock()
	rspCache[cacheKey] = cachedResponse{timestamp: time.Now(), frame: frame}
	rspCacheLock.Unlock()
	return frame, err
}

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

func parseCommandPacket(packet []byte) (sender, cmdID, command string, ok bool) {
	if len(packet) < 16 {
		return "", "", "", false
	}
	header := packet[:16]
	dest := decodeAX25Address(header[0:7])
	if dest != serverCallsign {
		log.Printf("Dropping packet: destination %s does not match our callsign %s", dest, serverCallsign)
		return "", "", "", false
	}
	infoField := packet[16:]
	infoStr := strings.TrimSpace(string(infoField))
	parts := strings.SplitN(infoStr, ":", 3)
	if len(parts) != 3 {
		log.Printf("Invalid CMD format: %s", infoStr)
		return "", "", "", false
	}
	cmdID = parts[0]
	if strings.ToUpper(parts[1]) != "CMD" {
		return "", "", "", false
	}
	command = parts[2]
	sender = decodeAX25Address(header[7:14])
	return sender, cmdID, command, true
}

func createResponsePacket(cmdID string, status int, msg string) []byte {
	responseText := fmt.Sprintf("%s:RSP:%d:%s", cmdID, status, msg)
	return []byte(responseText)
}

func callsignAllowedForGet(cs string) bool {
	if len(getAllowedCallsigns) == 0 {
		return false
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
	if len(putAllowedCallsigns) == 0 {
		return false
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range putAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

func callsignAllowedForAdmin(cs string) bool {
	if len(adminAllowedCallsigns) == 0 {
		return false
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range adminAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

// Modified listFiles: list directories (with trailing "/") and files.
func listFiles(root string) (string, error) {
    // Define a struct to hold file information.
    type fileEntry struct {
        relPath string
        modTime time.Time
        size    int64
        isDir   bool
    }

    var entries []fileEntry

    // Walk the directory tree starting at root.
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        // Skip the root directory itself.
        if path == root {
            return nil
        }
        // Skip hidden files or directories.
       	base := filepath.Base(path)
        if strings.HasPrefix(base, ".") {
            if info.IsDir() {
                return filepath.SkipDir
            }
            return nil
        }
        // Compute the relative path from the root.
        relPath, err := filepath.Rel(root, path)
        if err != nil {
            return err
        }
        entries = append(entries, fileEntry{
            relPath: relPath,
            modTime: info.ModTime(),
            size:    info.Size(),
            isDir:   info.IsDir(),
        })
        return nil
    })
    if err != nil {
        return "", err
    }

    // Sort the entries by relative path, case-insensitive.
    sort.Slice(entries, func(i, j int) bool {
        return strings.ToLower(entries[i].relPath) < strings.ToLower(entries[j].relPath)
    })

    var output strings.Builder
    output.WriteString("Name,Modified Date,Size\n")
    for _, entry := range entries {
        name := entry.relPath
        if entry.isDir {
            name += string(os.PathSeparator)
        }
        modTimeStr := entry.modTime.Format("2006-01-02 15:04:05")
        sizeStr := ""
        if !entry.isDir {
            sizeStr = fmt.Sprintf("%d", entry.size)
        }
        output.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\"\n", name, modTimeStr, sizeStr))
    }
    return output.String(), nil
}



// --- Broadcaster for Command Frames ---

type Broadcaster struct {
	subscribers map[chan []byte]struct{}
	lock        sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subscribers: make(map[chan []byte]struct{})}
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

func startKISSReader(conn KISSConnection, b *Broadcaster) {
	for {
		data, err := conn.RecvData(100 * time.Millisecond)
		if err != nil {
			if err != io.EOF {
				log.Printf("Underlying read error: %v", err)
				go doReconnect()
			}
			break
		}
		if len(data) == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		lastDataTime = time.Now()
		b.Broadcast(data)
	}
}

func monitorInactivity(timeout time.Duration) {
	for {
		time.Sleep(1 * time.Second)
		if time.Since(lastDataTime) > timeout {
			log.Println("No data received for the inactivity deadline; triggering reconnect")
			go doReconnect()
		}
	}
}

func doReconnect() {
	reconnectMutex.Lock()
	if reconnecting {
		reconnectMutex.Unlock()
		return
	}
	reconnecting = true
	reconnectMutex.Unlock()

	log.Println("Triggering reconnect...")

	for {
		log.Println("Attempting to reconnect in 5 seconds...")
		time.Sleep(5 * time.Second)
		var err error
		var newConn KISSConnection
		if strings.ToLower(globalArgs.Connection) == "tcp" {
			newConn, err = newTCPKISSConnection(globalArgs.Host, globalArgs.Port)
		} else {
			newConn, err = newSerialKISSConnection(globalArgs.SerialPort, globalArgs.Baud)
		}
		if err != nil {
			log.Printf("Reconnect failed: %v", err)
			continue
		}
		setConn(newConn)
		resetState()
		lastDataTime = time.Now()
		log.Println("Reconnected successfully to the underlying device")
		go startKISSReader(newConn, broadcaster)
		go monitorInactivity(600 * time.Second)
		break
	}

	reconnectMutex.Lock()
	reconnecting = false
	reconnectMutex.Unlock()
}

func doFileReconnect() {
	fileReconnectMux.Lock()
	if fileReconnecting {
		fileReconnectMux.Unlock()
		return
	}

	if activeTransferExists() {
	    log.Println("Active sender/receiver binary detected; skipping file reconnect.")
	    fileReconnectMux.Unlock()
	    return
	} else {
	    log.Println("No active sender/receiver binary detected; proceeding with reconnect.")
	}


	fileReconnecting = true
	fileReconnectMux.Unlock()

	log.Println("File transfer connection: Triggering reconnect...")

	for {
		log.Println("File transfer connection: Attempting to reconnect in 5 seconds...")
		time.Sleep(5 * time.Second)
		var newConn KISSConnection
		var err error
		if strings.ToLower(globalArgs.Connection) == "tcp" {
			newConn, err = newTCPKISSConnection(globalArgs.Host, globalArgs.Port)
		} else {
			newConn, err = newSerialKISSConnection(globalArgs.SerialPort, globalArgs.Baud)
		}
		if err != nil {
			log.Printf("File transfer reconnect failed: %v", err)
			continue
		}
		setFileConn(newConn)
		log.Println("File transfer connection: Reconnected successfully")
		break
	}

	fileReconnectMux.Lock()
	fileReconnecting = false
	fileReconnectMux.Unlock()
}

func handleTransparentConnection(remoteConn net.Conn, b *Broadcaster) {
	defer remoteConn.Close()
	log.Printf("Accepted transparent connection from %s", remoteConn.RemoteAddr())

	go func() {
		currentConn := getFileConn()
		if currentConn == nil {
			return
		}
		n, err := io.Copy(currentConn, remoteConn)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Error copying from transparent client to file transfer connection: %v", err)
			}
			go doFileReconnect()
			return
		}
		if n == 0 {
			return
		}
	}()

	sub := b.Subscribe()
	defer b.Unsubscribe(sub)
	for data := range sub {
		_, err := remoteConn.Write(data)
		if err != nil {
			return
		}
	}
}

func startTransparentListener(port int, b *Broadcaster) {
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
		go handleTransparentConnection(remoteConn, b)
	}
}

func invokeSenderBinary(args *Arguments, receiverCallsign, fileName, inputData, cmdID string) {
	if v, exists := runningSender.Load(receiverCallsign); exists {
		if existingCmd, ok := v.(*exec.Cmd); ok {
			log.Printf("Killing existing sender process for callsign %s", receiverCallsign)
			if err := existingCmd.Process.Kill(); err != nil {
				log.Printf("Error killing sender process: %v", err)
			}
			existingCmd.Wait()
		}
		runningSender.Delete(receiverCallsign)
	}

	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-connection=tcp", "-host=localhost", fmt.Sprintf("-port=%d", args.PassthroughPort))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-receiver-callsign=%s", receiverCallsign))
	cmdArgs = append(cmdArgs, "-stdin", "-file-name="+fileName)
	cmdArgs = append(cmdArgs, fmt.Sprintf("-fileid=%s", cmdID))
	cmdArgs = append(cmdArgs, "-timeout-seconds=5", "-timeout-retries=3")
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
	runningSender.Store(receiverCallsign, cmd)
	if err := cmd.Start(); err != nil {
		log.Printf("Error starting sender binary: %v", err)
		runningSender.Delete(receiverCallsign)
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
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("Sender binary exited with error: %v", err)
		} else {
			log.Printf("Sender binary completed successfully.")
		}
		runningSender.Delete(receiverCallsign)
		activeTransfersLock.Lock()
		if current, ok := activeTransfers[receiverCallsign]; ok && current == cmdID {
			delete(activeTransfers, receiverCallsign)
		}
		activeTransfersLock.Unlock()
	}()
}

func invokeReceiverBinary(args *Arguments, senderCallsign, fileName, cmdID, baseDir string) error {
	if v, exists := runningReceiver.Load(senderCallsign); exists {
		if existingCmd, ok := v.(*exec.Cmd); ok {
			log.Printf("Killing existing receiver process for callsign %s", senderCallsign)
			if err := existingCmd.Process.Kill(); err != nil {
				log.Printf("Error killing receiver process: %v", err)
			}
			existingCmd.Wait()
		}
		runningReceiver.Delete(senderCallsign)
	}

	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-connection=tcp", "-host=localhost", fmt.Sprintf("-port=%d", args.PassthroughPort))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-callsigns=%s", senderCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-fileid=%s", cmdID))
	cmdArgs = append(cmdArgs, "-one-file", "-one-file-header-timeout=10", "-stdout")
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
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[receiver stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading receiver stderr: %v", err)
		}
	}()
	runningReceiver.Store(senderCallsign, cmd)
	if err := cmd.Start(); err != nil {
		runningReceiver.Delete(senderCallsign)
		return fmt.Errorf("Error starting receiver binary: %v", err)
	}
	go func() {
		defer func() {
			activeTransfersLock.Lock()
			if current, ok := activeTransfers[senderCallsign]; ok && current == cmdID {
				delete(activeTransfers, senderCallsign)
			}
			activeTransfersLock.Unlock()
		}()
		output, err := io.ReadAll(stdoutPipe)
		if err != nil {
			log.Printf("Error reading receiver stdout: %v", err)
		}
		waitErr := cmd.Wait()
		runningReceiver.Delete(senderCallsign)
		if waitErr != nil {
			log.Printf("Receiver binary exited with error: %v", waitErr)
			return
		} else {
			log.Printf("Receiver binary completed successfully.")
		}
		savePath := filepath.Join(baseDir, fileName)
		cleanSavePath := filepath.Clean(savePath)
		if !strings.HasPrefix(cleanSavePath, baseDir) {
			log.Printf("PUT command: attempted directory traversal in file name '%s'", fileName)
		} else {
			if !globalArgs.OverwriteExisting {
				if _, err := os.Stat(cleanSavePath); err == nil {
					baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
					ext := filepath.Ext(fileName)
					counter := 1
					for {
						newFileName := fmt.Sprintf("%s_%d%s", baseName, counter, ext)
						newPath := filepath.Join(baseDir, newFileName)
						newPath = filepath.Clean(newPath)
						if _, err := os.Stat(newPath); os.IsNotExist(err) {
							cleanSavePath = newPath
							break
						}
						counter++
					}
				}
			}
			err = ioutil.WriteFile(cleanSavePath, output, 0644)
			if err != nil {
				log.Printf("Error writing received file to %s: %v", cleanSavePath, err)
			} else {
				log.Printf("Received file saved to %s", cleanSavePath)
			}
		}
	}()
	return nil
}

func createIDPacket() []byte {
	dest := encodeAX25Address("BEACON", false)
	src := encodeAX25Address(serverCallsign, true)
	header := append(append(dest, src...), 0x03, 0xF0)
	info := ">KISS File Server https://github.com/madpsy/kiss-tnc-file-transfer"
	return append(header, []byte(info)...)
}

func sendIDPacket() {
	conn := getConn()
	packet := createIDPacket()
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	if _, err := conn.Write(frame); err != nil {
		log.Printf("Error sending ID packet: %v", err)
	} else {
		log.Printf("Sent ID packet")
	}
}

func resetState() {
    lastDataTime = time.Now()
    rspCacheLock.Lock()
    rspCache = make(map[string]cachedResponse)
    rspCacheLock.Unlock()
    processingCommandsLock.Lock()
    processingCommands = make(map[string]chan struct{})
    processingCommandsLock.Unlock()
    activeTransfersLock.Lock()
    activeTransfers = make(map[string]string)
    activeTransfersLock.Unlock()
}

func main() {
	args := parseArguments()
	globalArgs = args
	serverCallsign = strings.ToUpper(args.MyCallsign)

	var absPerCallsignDir string
	if args.PerCallsignDir != "" {
		var err error
		absPerCallsignDir, err = filepath.Abs(args.PerCallsignDir)
		if err != nil {
			log.Fatalf("Error resolving per-callsign directory: %v", err)
		}
		log.Printf("Per-callsign mode active. Base directory: %s", absPerCallsignDir)
	} else {
		var err error
		absServeDir, err = filepath.Abs(args.ServeDirectory)
		if err != nil {
			log.Fatalf("Error resolving serve directory: %v", err)
		}
		absSaveDir, err = filepath.Abs(args.SaveDirectory)
		if err != nil {
			log.Fatalf("Error resolving save directory: %v", err)
		}
		log.Printf("Serving files from directory: %s", absServeDir)
		log.Printf("Received files will be saved to: %s", absSaveDir)
	}

	log.Printf("Sender binary set to: %s", args.SenderBinary)
	log.Printf("Receiver binary set to: %s", args.ReceiverBinary)

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

	if args.AdminCallsigns != "" {
		for _, cs := range strings.Split(args.AdminCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				adminAllowedCallsigns = append(adminAllowedCallsigns, cs)
			}
		}
		log.Printf("Allowed ADMIN sender callsign patterns: %v", adminAllowedCallsigns)
	} else {
		log.Printf("No ADMIN callsign filtering enabled; admin commands will be denied.")
	}

	var conn, fConn KISSConnection
	var err error
	if strings.ToLower(args.Connection) == "tcp" {
		conn, err = newTCPKISSConnection(args.Host, args.Port)
		if err != nil {
			log.Fatalf("TCP connection error: %v", err)
		}
		fConn, err = newTCPKISSConnection(args.Host, args.Port)
		if err != nil {
			log.Fatalf("File transfer connection error: %v", err)
		}
	} else {
		conn, err = newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("Serial connection error: %v", err)
		}
		fConn, err = newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("File transfer connection error: %v", err)
		}
	}
	setConn(conn)
	setFileConn(fConn)
	defer conn.Close()
	defer fConn.Close()

	log.Printf("File Server started. My callsign: %s", serverCallsign)

	if args.IdPeriod > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(args.IdPeriod) * time.Minute)
			defer ticker.Stop()
			sendIDPacket()
			for range ticker.C {
				sendIDPacket()
			}
		}()
	}

	go cacheCleanup()
	broadcaster = NewBroadcaster()
	lastDataTime = time.Now()
	go startKISSReader(getConn(), broadcaster)
	go monitorInactivity(600 * time.Second)
	go startTransparentListener(args.PassthroughPort, broadcaster)

	cmdSub := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(cmdSub)
	var buffer []byte
	for data := range cmdSub {
		buffer = append(buffer, data...)
		frames, remaining := extractKISSFrames(buffer)
		buffer = remaining
		for _, frame := range frames {
			if len(frame) < 3 || frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
				continue
			}
			inner := frame[2 : len(frame)-1]
			unesc := unescapeData(inner)
			sender, cmdID, command, ok := parseCommandPacket(unesc)
			if !ok {
				continue
			}
			cacheKey := sender + ":" + cmdID

			rspCacheLock.Lock()
			if cached, exists := rspCache[cacheKey]; exists && time.Since(cached.timestamp) < 30*time.Second {
				rspCacheLock.Unlock()
				conn := getConn()
				_, err := conn.Write(cached.frame)
				if err != nil {
					log.Printf("Error sending cached response for duplicate command: %v", err)
				} else {
					log.Printf("Duplicate CMD received. Resent cached response for key %s", cacheKey)
				}
				continue
			}
			rspCacheLock.Unlock()

			processingCommandsLock.Lock()
			if ch, exists := processingCommands[cacheKey]; exists {
				processingCommandsLock.Unlock()
				<-ch
				rspCacheLock.Lock()
				if cached, exists := rspCache[cacheKey]; exists && time.Since(cached.timestamp) < 30*time.Second {
					rspCacheLock.Unlock()
					conn := getConn()
					_, err := conn.Write(cached.frame)
					if err != nil {
						log.Printf("Error sending cached response for duplicate command: %v", err)
					} else {
						log.Printf("Duplicate CMD received while processing. Resent cached response for key %s", cacheKey)
					}
					continue
				}
				rspCacheLock.Unlock()
			} else {
				ch := make(chan struct{})
				processingCommands[cacheKey] = ch
				processingCommandsLock.Unlock()
				defer func(key string, ch chan struct{}) {
					processingCommandsLock.Lock()
					close(ch)
					delete(processingCommands, key)
					processingCommandsLock.Unlock()
				}(cacheKey, ch)
			}

			upperCmd := strings.ToUpper(command)
			var baseDir string
			if globalArgs.PerCallsignDir != "" {
				baseDir = filepath.Join(absPerCallsignDir, sender)
				os.MkdirAll(baseDir, 0755)
				readmePath := filepath.Join(baseDir, "README.txt")
				if _, err := os.Stat(readmePath); os.IsNotExist(err) {
					readmeContent := fmt.Sprintf("Welcome %s to your personal file store!\n\nYou have full permissions to all files here.\n\nHave fun!", sender)
					if err := ioutil.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
						log.Printf("Error creating README.txt: %v", err)
					}
				}
			}

			if strings.HasPrefix(upperCmd, "GET ") {
			    if globalArgs.PerCallsignDir == "" && !callsignAllowedForGet(sender) {
			        log.Printf("Dropping GET command from sender %s: not allowed.", sender)
			        activeTransfersLock.Lock()
			        delete(activeTransfers, sender)
			        activeTransfersLock.Unlock()
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
			        continue
			    }
			    activeTransfersLock.Lock()
			    if _, exists := activeTransfers[sender]; !exists && len(activeTransfers) >= globalArgs.MaxConcurrency {
			        activeTransfersLock.Unlock()
			        sendResponseWithDetails(sender, cmdID, command, 0, "TRANSFER ALREADY IN PROGRESS. PLEASE WAIT.")
			        continue
			    }
			    activeTransfers[sender] = cmdID
			    activeTransfersLock.Unlock()
			
			    fileName := strings.TrimSpace(command[4:])
			    if len(fileName) > maxFileNameLen {
			        log.Printf("GET command from sender %s: file name '%s' too long", sender, fileName)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
			        continue
			    }
			    if isFilenameDisallowed(fileName) {
			        log.Printf("GET command from sender %s: access to file '%s' is forbidden", sender, fileName)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
			        continue
			    }
			    var dir string
			    if globalArgs.PerCallsignDir != "" {
			        dir = baseDir
			    } else {
			        dir = absServeDir
			    }
			    requestedPath := filepath.Join(dir, fileName)
			    cleanPath := filepath.Clean(requestedPath)
			    if !strings.HasPrefix(cleanPath, dir) {
			        log.Printf("GET command from sender %s: attempted directory traversal in '%s'", sender, fileName)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
			        continue
			    }
			
			    var content []byte
if strings.EqualFold(filepath.Base(fileName), "index.html") {
    content, err = ioutil.ReadFile(cleanPath)
    if err != nil {
        content = []byte("<html><body><h3>No site configured here yet. Upload index.html to get started.</h3></body></html>")
    }
} else {
			        // Regular file: first check that it exists and is not a directory.
			        info, err := os.Stat(cleanPath)
			        if err != nil {
			            log.Printf("GET command from sender %s: error stating '%s': %v", sender, fileName, err)
			            _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CANNOT FIND/READ FILE")
			            continue
			        }
			        if info.IsDir() {
			            log.Printf("GET command from sender %s: '%s' is a directory", sender, fileName)
			            _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CANNOT GET DIRECTORY")
			            continue
			        }
			        content, err = ioutil.ReadFile(cleanPath)
			        if err != nil {
			            log.Printf("GET command from sender %s: error reading '%s': %v", sender, fileName, err)
			            _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CANNOT FIND/READ FILE")
			            continue
			        }
			    }
			    _, _ = sendResponseWithDetails(sender, cmdID, command, 1, "GET OK")
			    go invokeSenderBinary(globalArgs, sender, fileName, string(content), cmdID)
			} else if strings.HasPrefix(upperCmd, "LIST") {
				if globalArgs.PerCallsignDir != "" {
					baseDir = filepath.Join(absPerCallsignDir, sender)
				} else {
					baseDir = absServeDir
				}
				listing, err := listFiles(baseDir)
				if err != nil {
					log.Printf("LIST command from sender %s: error listing files: %v", sender, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "LIST CANNOT READ")
					continue
				}
				_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "LIST OK")
				go invokeSenderBinary(args, sender, "LIST.txt", listing, cmdID)
			} else if strings.HasPrefix(upperCmd, "PUT ") {
  			  if globalArgs.PerCallsignDir == "" && !callsignAllowedForPut(sender) {
			        log.Printf("PUT command from sender %s not allowed.", sender)
			        activeTransfersLock.Lock()
			        delete(activeTransfers, sender)
			        activeTransfersLock.Unlock()
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
			        continue
			    }
			    activeTransfersLock.Lock()
			    if _, exists := activeTransfers[sender]; !exists && len(activeTransfers) >= globalArgs.MaxConcurrency {
			        activeTransfersLock.Unlock()
			        sendResponseWithDetails(sender, cmdID, command, 0, "TRANSFER ALREADY IN PROGRESS. PLEASE WAIT.")
			        continue
			    }
			    activeTransfers[sender] = cmdID
			    activeTransfersLock.Unlock()
			
			    fileName := strings.TrimSpace(command[4:])
			    if len(fileName) > maxFileNameLen {
			        log.Printf("PUT command from sender %s: file name '%s' too long", sender, fileName)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
			        continue
			    }
			    if !allowedFileName.MatchString(fileName) {
				log.Printf("PUT command from sender %s: file name '%s' contains invalid characters", sender, fileName)
				_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE NAME CHARACTERS")
				continue
			    }
			    if isFilenameDisallowed(fileName) {
			        log.Printf("PUT command from sender %s: access to file '%s' is forbidden", sender, fileName)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
			        continue
			    }
			    var dir string
			    if globalArgs.PerCallsignDir != "" {
			        dir = baseDir
			    } else {
			        dir = absSaveDir
			    }
			    // Check if the base target directory exists.
			    if _, err := os.Stat(dir); os.IsNotExist(err) {
			        log.Printf("PUT command from sender %s: target directory '%s' does not exist", sender, dir)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DIRECTORY DOES NOT EXIST")
			        continue
			    }
			    savePath := filepath.Join(dir, fileName)
			    cleanSavePath := filepath.Clean(savePath)
			    if !strings.HasPrefix(cleanSavePath, dir) {
			        log.Printf("PUT command from sender %s: attempted directory traversal in '%s'", sender, fileName)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
			        continue
			    }
			    // NEW: If the fileName includes directory components, ensure that the target directory exists.
			    if strings.Contains(fileName, string(os.PathSeparator)) {
			        targetDir := filepath.Dir(cleanSavePath)
			        if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			            log.Printf("PUT command from sender %s: directory '%s' does not exist", sender, targetDir)
			            _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DIRECTORY NOT FOUND. CREATE PATH FIRST.")
			            continue
			        }
			    }
			    err := invokeReceiverBinary(args, sender, fileName, cmdID, dir)
			    if err != nil {
			        log.Printf("PUT command from sender %s: receiver binary error: %v", sender, err)
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 0, "PUT FAILED: CANNOT START RECEIVER")
			    } else {
			        _, _ = sendResponseWithDetails(sender, cmdID, command, 1, "PUT OK - WAITING FOR FILE")
			    }
			} else if strings.HasPrefix(upperCmd, "DEL ") {
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForAdmin(sender) {
					log.Printf("Admin command DEL from sender %s not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				fileName := strings.TrimSpace(command[4:])
				if len(fileName) > maxFileNameLen {
					log.Printf("DEL command from sender %s: file name '%s' too long", sender, fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
					continue
				}
				if isFilenameDisallowed(fileName) {
					log.Printf("DEL command from sender %s: access to file '%s' is forbidden", sender, fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
					continue
				}
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absServeDir
				}
				fullPath := filepath.Join(dir, fileName)
				cleanPath := filepath.Clean(fullPath)
				if !strings.HasPrefix(cleanPath, dir) {
					log.Printf("DEL command from sender %s: attempted directory traversal in '%s'", sender, fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
					continue
				}
				if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
					log.Printf("DEL command from sender %s: file/directory '%s' does not exist", sender, fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE DOES NOT EXIST")
					continue
				}
				// If it's a directory, remove it recursively; otherwise, remove the file.
				info, err := os.Stat(cleanPath)
				if err != nil {
					log.Printf("DEL command from sender %s: error stating '%s': %v", sender, fileName, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DEL FAILED")
					continue
				}
				if info.IsDir() {
					err = os.RemoveAll(cleanPath)
				} else {
					err = os.Remove(cleanPath)
				}
				if err != nil {
					log.Printf("DEL command from sender %s: error deleting '%s': %v", sender, fileName, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DEL FAILED")
				} else {
					log.Printf("DEL command from sender %s: '%s' deleted successfully", sender, fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "DEL OK")
				}
			} else if strings.HasPrefix(upperCmd, "REN ") {
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForAdmin(sender) {
					log.Printf("Admin command REN from sender %s not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				params := strings.TrimSpace(command[4:])
				parts := strings.SplitN(params, "|", 2)
				if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
					log.Printf("REN command from sender %s: new filename not specified in '%s'", sender, params)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "NEW FILENAME NOT SPECIFIED")
					continue
				}
				currentFile := strings.TrimSpace(parts[0])
				newFile := strings.TrimSpace(parts[1])
				if len(currentFile) > maxFileNameLen || len(newFile) > maxFileNameLen {
					log.Printf("REN command from sender %s: one or both filenames ('%s', '%s') are too long", sender, currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
					continue
				}
				if isFilenameDisallowed(currentFile) || isFilenameDisallowed(newFile) {
					log.Printf("REN command from sender %s: renaming of '%s' or '%s' is forbidden", sender, currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
					continue
				}
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absServeDir
				}
				currentPath := filepath.Join(dir, currentFile)
				newPath := filepath.Join(dir, newFile)
				cleanCurrent := filepath.Clean(currentPath)
				cleanNew := filepath.Clean(newPath)
				if !strings.HasPrefix(cleanCurrent, dir) || !strings.HasPrefix(cleanNew, dir) {
					log.Printf("REN command from sender %s: attempted directory traversal with '%s' or '%s'", sender, currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
					continue
				}
				if _, err := os.Stat(cleanCurrent); os.IsNotExist(err) {
					log.Printf("REN command from sender %s: '%s' does not exist", sender, currentFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CURRENT FILE DOES NOT EXIST")
					continue
				}
				if _, err := os.Stat(cleanNew); err == nil {
					log.Printf("REN command from sender %s: '%s' already exists", sender, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "NEW FILE ALREADY EXISTS")
					continue
				}
				err := os.Rename(cleanCurrent, cleanNew)
				if err != nil {
					log.Printf("REN command from sender %s: error renaming '%s' to '%s': %v", sender, currentFile, newFile, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "REN FAILED")
				} else {
					log.Printf("REN command from sender %s: '%s' renamed to '%s' successfully", sender, currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "REN OK")
				}
			} else if strings.HasPrefix(upperCmd, "MKD ") {
				// New command: Make Directory (MKD)
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForAdmin(sender) {
					log.Printf("MKD command from sender %s not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				dirName := strings.TrimSpace(command[4:])
				// Check each component of the directory name (split by "/")
				parts := strings.Split(dirName, "/")
				invalid := false
				for _, part := range parts {
					if part == "" {
						continue
					}
					if len(part) > 15 {
						log.Printf("MKD command from sender %s: directory component '%s' exceeds 15 characters", sender, part)
						_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DIRECTORY NAME COMPONENT TOO LONG")
						invalid = true
						break
					}
					if !allowedDirName.MatchString(part) {
						log.Printf("MKD command from sender %s: directory component '%s' contains invalid characters", sender, part)
						_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID DIRECTORY NAME CHARACTERS")
						invalid = true
						break
					}
				}
				if invalid {
					continue
				}
				var base string
				if globalArgs.PerCallsignDir != "" {
					base = baseDir
				} else {
					base = absServeDir
				}
				targetPath := filepath.Join(base, dirName)
				cleanPath := filepath.Clean(targetPath)
				if !strings.HasPrefix(cleanPath, base) {
					log.Printf("MKD command from sender %s: attempted directory traversal in '%s'", sender, dirName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID DIRECTORY PATH")
					continue
				}
				// If a file (not directory) exists with the same name, return error.
				if info, err := os.Stat(cleanPath); err == nil {
					if !info.IsDir() {
						log.Printf("MKD command from sender %s: a file named '%s' already exists", sender, dirName)
						_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE ALREADY EXISTS")
						continue
					} else {
						log.Printf("MKD command from sender %s: directory '%s' already exists", sender, dirName)
						_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DIRECTORY ALREADY EXISTS")
						continue
					}
				}
				// Create the directory (supporting multiple depths)
				if err := os.MkdirAll(cleanPath, 0755); err != nil {
					log.Printf("MKD command from sender %s: error creating directory '%s': %v", sender, dirName, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "MKD FAILED")
				} else {
					log.Printf("MKD command from sender %s: directory '%s' created successfully", sender, dirName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "MKD OK")
				}
			} else {
				log.Printf("Unrecognized command from sender %s: %s", sender, command)
				_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "AVAILABLE: LIST, GET [FILE], PUT [FILE], DEL [FILE/DIR], REN [CUR]|[NEW], MKD [DIR]")
			}
		}
	}
}

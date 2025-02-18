// passthrough.go
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"go.bug.st/serial"
)

// -----------------------------------------------------------------------------
// KISS Framing Constants and Helper Functions
// -----------------------------------------------------------------------------

const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// extractKISSFrames scans the given data buffer for complete frames.
// A complete frame is defined as one that starts and ends with KISS_FLAG.
// It returns a slice of complete frames and any leftover (incomplete) bytes.
func extractKISSFrames(data []byte) ([][]byte, []byte) {
	var frames [][]byte
	for {
		start := bytes.IndexByte(data, KISS_FLAG)
		if start == -1 {
			break
		}
		// Look for the closing flag.
		end := bytes.IndexByte(data[start+1:], KISS_FLAG)
		if end == -1 {
			break // no complete frame found yet
		}
		end = start + 1 + end
		frame := data[start : end+1]
		frames = append(frames, frame)
		data = data[end+1:]
	}
	return frames, data
}

// -----------------------------------------------------------------------------
// TNCConnection Interface and Implementations
// -----------------------------------------------------------------------------

// TNCConnection abstracts a connection to a TNC device.
type TNCConnection interface {
	Send(data []byte) error
	Recv(timeout time.Duration) ([]byte, error)
	Close() error
}

// TCPTNCConnection is a TCP-based TNC connection.
type TCPTNCConnection struct {
	conn net.Conn
	lock sync.Mutex
}

func newTCPTNCConnection(host string, port int) (TNCConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to TNC via TCP at %s", addr)
	return &TCPTNCConnection{conn: conn}, nil
}

func (t *TCPTNCConnection) Send(data []byte) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	_, err := t.conn.Write(data)
	return err
}

func (t *TCPTNCConnection) Recv(timeout time.Duration) ([]byte, error) {
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := t.conn.Read(buf)
	if err != nil {
		// Ignore timeouts; they just mean no data was received.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (t *TCPTNCConnection) Close() error {
	return t.conn.Close()
}

// SerialTNCConnection is a serial-based TNC connection.
type SerialTNCConnection struct {
	port serial.Port
	lock sync.Mutex
}

func newSerialTNCConnection(portName string, baud int) (TNCConnection, error) {
	mode := &serial.Mode{BaudRate: baud}
	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to TNC via Serial at %s (baud %d)", portName, baud)
	return &SerialTNCConnection{port: port}, nil
}

func (s *SerialTNCConnection) Send(data []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, err := s.port.Write(data)
	return err
}

func (s *SerialTNCConnection) Recv(timeout time.Duration) ([]byte, error) {
	// Note: The serial package may not support setting timeouts directly.
	// Here we simply try to read up to 1024 bytes.
	buf := make([]byte, 1024)
	n, err := s.port.Read(buf)
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (s *SerialTNCConnection) Close() error {
	return s.port.Close()
}

// -----------------------------------------------------------------------------
// Global Variables for TNC and Client Connections
// -----------------------------------------------------------------------------

var (
	// Global pointer to the current TNC connection (protected by tncConnMutex)
	tncConn      TNCConnection
	tncConnMutex sync.Mutex

	// Global list of connected TCP clients and its mutex
	clients     []net.Conn
	clientsLock sync.Mutex

	// Global list of connected broadcast clients (if --tcp-broadcast-port is set)
	broadcastClients     []net.Conn
	broadcastClientsLock sync.Mutex

	// Global variable to track the last time a complete frame was received from the TNC.
	lastTNCRecv      time.Time
	lastTNCRecvMutex sync.Mutex

	// The configured turnaround delay before sending data to the TNC.
	sendDelay time.Duration

	// Application-level timeout for inactivity (applies only for TCP TNC connections).
	tcpReadDeadline time.Duration

	// Optional TCP broadcast port (if non‑zero, we also send all frames to clients connected here)
	tcpBroadcastPort int
)

func setTNCConnection(conn TNCConnection) {
	tncConnMutex.Lock()
	defer tncConnMutex.Unlock()
	tncConn = conn
}

func getTNCConnection() TNCConnection {
	tncConnMutex.Lock()
	defer tncConnMutex.Unlock()
	return tncConn
}

// broadcastToClients sends data to every connected client. If a client errors out,
// it is removed from the list.
func broadcastToClients(data []byte) {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	for i := len(clients) - 1; i >= 0; i-- {
		client := clients[i]
		_, err := client.Write(data)
		if err != nil {
			log.Printf("Error writing to client %s: %v. Removing client.", client.RemoteAddr(), err)
			client.Close()
			clients = append(clients[:i], clients[i+1:]...)
		}
	}
}

// broadcastToBroadcastClients sends data to every connected broadcast client.
// If writing fails, the client is removed.
func broadcastToBroadcastClients(data []byte) {
	broadcastClientsLock.Lock()
	defer broadcastClientsLock.Unlock()
	for i := len(broadcastClients) - 1; i >= 0; i-- {
		bc := broadcastClients[i]
		_, err := bc.Write(data)
		if err != nil {
			log.Printf("Error writing to broadcast client %s: %v. Removing client.", bc.RemoteAddr(), err)
			bc.Close()
			broadcastClients = append(broadcastClients[:i], broadcastClients[i+1:]...)
		}
	}
}

// -----------------------------------------------------------------------------
// TCP Broadcast Listener (if --tcp-broadcast-port is set)
// -----------------------------------------------------------------------------

// startTCPBroadcastListener starts a TCP listener on the given port. Any client that
// connects is added to the broadcastClients list. Note: we immediately close the read side
// of the connection so that it only serves as a one‑way (write‑only) broadcast.
func startTCPBroadcastListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting TCP broadcast listener on %s: %v", addr, err)
	}
	log.Printf("TCP broadcast listener started on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting broadcast client: %v", err)
			continue
		}
		// If possible, close the read side so that this connection is write‑only.
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseRead()
		}
		broadcastClientsLock.Lock()
		broadcastClients = append(broadcastClients, conn)
		broadcastClientsLock.Unlock()
		log.Printf("Broadcast client connected: %s", conn.RemoteAddr())
		// We do not spawn a read loop for broadcast clients because we don't expect any data.
	}
}

// -----------------------------------------------------------------------------
// TNC Read Loop with KISS Framing Checks and Application-Level Inactivity Timer
// -----------------------------------------------------------------------------

// handleTNCRead continuously reads from the TNC and broadcasts any received
// complete KISS frames to all connected clients and broadcast clients. It also updates the lastTNCRecv timestamp.
// (The inactivity timeout is now handled by a separate goroutine.)
func handleTNCRead(conn TNCConnection) {
	var buffer []byte

	for {
		// Attempt to read data with a short timeout.
		data, err := conn.Recv(1 * time.Second)
		if err != nil {
			// If the error is not a timeout, log it and exit.
			log.Printf("Error reading from TNC: %v", err)
			return
		}
		if len(data) > 0 {
			// Append received data to our buffer.
			buffer = append(buffer, data...)
			// Extract complete KISS frames from the buffer.
			frames, remaining := extractKISSFrames(buffer)
			buffer = remaining
			for _, frame := range frames {
				// Update the timestamp for TCP connections.
				if _, ok := conn.(*TCPTNCConnection); ok {
					lastTNCRecvMutex.Lock()
					lastTNCRecv = time.Now()
					lastTNCRecvMutex.Unlock()
				}
				// Send the frame to normal clients.
				broadcastToClients(frame)
				// Also send the frame to any broadcast clients.
				broadcastToBroadcastClients(frame)
			}
		}
	}
}

// startInactivityMonitor starts an application-level timer for TCP TNC connections.
// It periodically checks the lastTNCRecv timestamp and, if no complete frame has been
// received for tcpReadDeadline, logs a message (once) and closes the connection.
func startInactivityMonitor(conn TNCConnection) {
	// Only apply for TCP connections.
	if _, ok := conn.(*TCPTNCConnection); !ok {
		return
	}
	var logged bool
	go func() {
		for {
			time.Sleep(1 * time.Second)
			lastTNCRecvMutex.Lock()
			elapsed := time.Since(lastTNCRecv)
			lastTNCRecvMutex.Unlock()
			if elapsed > tcpReadDeadline {
				if !logged {
					log.Printf("No data received from TNC for %v; triggering reconnect", tcpReadDeadline)
					logged = true
				}
				// Close the connection to force the read loop to exit.
				conn.Close()
				return
			}
		}
	}()
}

// -----------------------------------------------------------------------------
// Turnaround Delay Helper
// -----------------------------------------------------------------------------

// waitForTurnaroundDelay pauses until at least sendDelay has passed since the last TNC frame was received.
func waitForTurnaroundDelay() {
	if sendDelay > 0 {
		for {
			lastTNCRecvMutex.Lock()
			lastRecv := lastTNCRecv
			lastTNCRecvMutex.Unlock()
			elapsed := time.Since(lastRecv)
			if elapsed >= sendDelay {
				break
			}
			time.Sleep(sendDelay - elapsed)
		}
	}
}

// -----------------------------------------------------------------------------
// Client Connection Handler with KISS Framing Checks
// -----------------------------------------------------------------------------

// handleClientConnection reads from a TCP client and sends any complete KISS frame
// it receives to the TNC (if connected), applying the turnaround delay if needed.
// It also broadcasts the frame to any broadcast clients.
func handleClientConnection(client net.Conn) {
	defer client.Close()
	var clientBuffer []byte
	buf := make([]byte, 1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from client %s: %v", client.RemoteAddr(), err)
			}
			break
		}
		if n > 0 {
			// Append received data to the client buffer.
			clientBuffer = append(clientBuffer, buf[:n]...)
			// Extract complete KISS frames.
			frames, remaining := extractKISSFrames(clientBuffer)
			clientBuffer = remaining
			for _, frame := range frames {
				conn := getTNCConnection()
				if conn != nil {
					// Wait for the turnaround delay.
					waitForTurnaroundDelay()
					if err := conn.Send(frame); err != nil {
						log.Printf("Error sending data to TNC: %v", err)
					}
				} else {
					log.Printf("No TNC connection available. Dropping data from client %s", client.RemoteAddr())
				}
				// Also broadcast the frame to broadcast clients.
				broadcastToBroadcastClients(frame)
			}
		}
	}
	// Remove the client from our list on disconnect.
	clientsLock.Lock()
	for i, c := range clients {
		if c == client {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	clientsLock.Unlock()
	log.Printf("Client %s disconnected.", client.RemoteAddr())
}

// -----------------------------------------------------------------------------
// Client Listener
// -----------------------------------------------------------------------------

// startClientListener starts a TCP listener on the given port to accept client connections.
func startClientListener(listenPort int) {
	addr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting client listener on %s: %v", addr, err)
	}
	log.Printf("Client listener started on %s", addr)
	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting client: %v", err)
			continue
		}
		clientsLock.Lock()
		clients = append(clients, client)
		clientsLock.Unlock()
		log.Printf("Client connected: %s", client.RemoteAddr())
		go handleClientConnection(client)
	}
}

// -----------------------------------------------------------------------------
// Main: Command‑Line Parsing and Auto‑Reconnection Loop
// -----------------------------------------------------------------------------

func main() {
	// Command‑line arguments
	tncConnType := flag.String("tnc-connection-type", "tcp", "TNC connection type: tcp or serial")
	tncHost := flag.String("tnc-host", "127.0.0.1", "TNC TCP host (if tcp connection)")
	tncPort := flag.Int("tnc-port", 9001, "TNC TCP port (if tcp connection)")
	tncSerialPort := flag.String("tnc-serial-port", "", "TNC serial port (if serial connection)")
	tncBaud := flag.Int("tnc-baud", 115200, "TNC serial baud rate (if serial connection)")
	clientListenPort := flag.Int("client-listen-port", 5010, "TCP port to listen for client connections")
	sendDelayFlag := flag.Int("send-delay", 0, "Delay in milliseconds before sending frames to the TNC if we have just received a frame from it (a.k.a. turnaround). It specifies the minimum time which must have passed before we start sending frames.")
	tcpReadDeadlineFlag := flag.Int("tcp-read-deadline", 600, "TCP read deadline in seconds for the TNC connection (applies only if tnc-connection-type is tcp)")
	// New flag for TCP broadcast port. No default value is provided.
	tcpBroadcastPortFlag := flag.Int("tcp-broadcast-port", 0, "TCP port to broadcast all frames (one-way; clients connecting here will only receive data)")
	flag.Parse()

	// Convert the send delay from milliseconds to a time.Duration.
	sendDelay = time.Duration(*sendDelayFlag) * time.Millisecond

	// Set the TCP read deadline from the flag.
	tcpReadDeadline = time.Duration(*tcpReadDeadlineFlag) * time.Second

	// Set the global tcpBroadcastPort variable.
	tcpBroadcastPort = *tcpBroadcastPortFlag

	// If the tcpBroadcastPort is set (non‑zero), start the broadcast listener.
	if tcpBroadcastPort > 0 {
		go startTCPBroadcastListener(tcpBroadcastPort)
	}

	// Start the client listener (this runs independently)
	go startClientListener(*clientListenPort)

	// Main loop: (re)connect to the TNC and run the bridge
	for {
		var conn TNCConnection
		var err error

		if *tncConnType == "tcp" {
			conn, err = newTCPTNCConnection(*tncHost, *tncPort)
		} else if *tncConnType == "serial" {
			if *tncSerialPort == "" {
				log.Fatalf("For a serial connection, --tnc-serial-port must be specified.")
			}
			conn, err = newSerialTNCConnection(*tncSerialPort, *tncBaud)
		} else {
			log.Fatalf("Invalid TNC connection type: %s", *tncConnType)
		}

		if err != nil {
			log.Printf("Error connecting to TNC: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		setTNCConnection(conn)
		log.Printf("TNC connection established.")

		// For TCP connections, initialize the last received timestamp.
		if *tncConnType == "tcp" {
			lastTNCRecvMutex.Lock()
			lastTNCRecv = time.Now()
			lastTNCRecvMutex.Unlock()
			// Start the inactivity monitor for application-level timeout.
			startInactivityMonitor(conn)
		}

		// Start a goroutine to read from the TNC.
		tncDone := make(chan struct{})
		go func() {
			handleTNCRead(conn)
			close(tncDone)
		}()

		// Block here until the TNC connection is lost.
		<-tncDone

		setTNCConnection(nil)
		log.Printf("TNC connection lost. Reconnecting in 5 seconds...")
		conn.Close()
		time.Sleep(5 * time.Second)
	}
}

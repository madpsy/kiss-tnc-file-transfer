// 1200beacon.go
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// KISS framing constants.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// KISSConnection is a minimal interface for sending data.
type KISSConnection interface {
	Write([]byte) (int, error)
	Close() error
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn net.Conn
}

func NewTCPKISSConnection(host string, port int) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to %s via TCP", addr)
	return &TCPKISSConnection{conn: conn}, nil
}

func (t *TCPKISSConnection) Write(b []byte) (int, error) {
	return t.conn.Write(b)
}

func (t *TCPKISSConnection) Close() error {
	return t.conn.Close()
}

// escapeData applies KISS escaping.
func escapeData(data []byte) []byte {
	var buf bytes.Buffer
	for _, b := range data {
		if b == KISS_FLAG {
			buf.WriteByte(0xDB)
			buf.WriteByte(0xDC)
		} else if b == 0xDB {
			buf.WriteByte(0xDB)
			buf.WriteByte(0xDD)
		} else {
			buf.WriteByte(b)
		}
	}
	return buf.Bytes()
}

// buildKISSFrameCmd wraps the payload in KISS framing using the specified command byte.
func buildKISSFrameCmd(cmd byte, payload []byte) []byte {
	escaped := escapeData(payload)
	frame := []byte{KISS_FLAG, cmd}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	return frame
}

// buildKISSFrame is a helper that wraps the payload using the data command (0x00).
func buildKISSFrame(payload []byte) []byte {
	return buildKISSFrameCmd(KISS_CMD_DATA, payload)
}

// encodeAX25Address encodes a callsign (with optional SSID, e.g. "MYCALL-1")
// into a 7-byte AX.25 address field. When isLast is true, the last bit is set.
func encodeAX25Address(callsign string, isLast bool) []byte {
	parts := strings.Split(callsign, "-")
	base := strings.ToUpper(strings.TrimSpace(parts[0]))
	if len(base) < 6 {
		base = base + strings.Repeat(" ", 6-len(base))
	} else if len(base) > 6 {
		base = base[:6]
	}
	addr := make([]byte, 7)
	for i := 0; i < 6; i++ {
		addr[i] = base[i] << 1
	}
	ssid := 0
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &ssid)
	}
	// SSID byte: bits 1-4 hold the SSID; bit 6 is set to 1.
	addr[6] = byte((ssid & 0x0F) << 1) | 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// createBeaconPacket builds an AX.25 beacon packet.
// The destination is fixed to "BEACON" and the source is taken from myCallsign.
// The packet includes a control byte (0x03) and a PID (0xF0).
// The beacon message is automatically prepended with a '>' if not already present.
func createBeaconPacket(myCallsign, message string) []byte {
	if !strings.HasPrefix(message, ">") {
		message = ">" + message
	}
	dest := encodeAX25Address("BEACON", false)
	src := encodeAX25Address(myCallsign, true)
	header := append(dest, src...)
	header = append(header, 0x03, 0xF0)
	info := []byte(message)
	return append(header, info...)
}

func main() {
	// Define command-line flags.
	host := flag.String("host", "127.0.0.1", "TCP host")
	port := flag.Int("port", 5001, "TCP port (default 5001)")
	myCallsign := flag.String("my-callsign", "", "Your callsign (required)")
	mode := flag.Int("mode", 3, "Mode value (default 3)")
	message := flag.String("message", "", "Beacon message (required)")
	interval := flag.Int("interval", 30, "Interval in minutes between beacons")
	delay := flag.Int("delay", 500, "Delay between each KISS packet in milliseconds (default 500)")
	flag.Parse()

	// Check required flags.
	if *myCallsign == "" {
		log.Fatal("The -my-callsign flag is required.")
	}
	if *message == "" {
		log.Fatal("The -message flag is required.")
	}

	// Outer loop: attempt to (re)connect to the TNC.
	for {
		conn, err := NewTCPKISSConnection(*host, *port)
		if err != nil {
			log.Printf("Error establishing connection: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Create a ticker for the beacon interval.
		ticker := time.NewTicker(time.Duration(*interval) * time.Minute)
		log.Printf("Beacon program started. Sending beacon every %d minutes.", *interval)

		// Inner loop: send beacons until a write error occurs.
		sendBeacons:
		for {
			// 1. Send KISS packet to change mode to 1200.
			// The TNC expects a mode-change command with command byte 0x06 and payload {22} (which is 6+16).
			mode1200 := byte(22)
			frame := buildKISSFrameCmd(0x06, []byte{mode1200})
			if _, err := conn.Write(frame); err != nil {
				log.Printf("Error sending mode change to %d: %v", mode1200, err)
				break sendBeacons
			} else {
				log.Printf("Sent KISS packet to change mode to 1200 baud AFSK (%d = 6+16)", mode1200)
			}

			time.Sleep(time.Duration(*delay) * time.Millisecond)

			// 2. Send AX.25 beacon packet with the provided message.
			beaconPkt := createBeaconPacket(*myCallsign, *message)
			frame = buildKISSFrame(beaconPkt)
			if _, err := conn.Write(frame); err != nil {
				log.Printf("Error sending beacon packet: %v", err)
				break sendBeacons
			} else {
				log.Printf("Sent AX.25 beacon packet with message: %s", *message)
			}

			time.Sleep(time.Duration(*delay) * time.Millisecond)

			// 3. Send KISS packet to change mode to (mode argument + 16).
			finalMode := byte(*mode + 16)
			frame = buildKISSFrameCmd(0x06, []byte{finalMode})
			if _, err := conn.Write(frame); err != nil {
				log.Printf("Error sending mode change packet to mode %d: %v", finalMode, err)
				break sendBeacons
			} else {
				log.Printf("Sent KISS packet to change mode to %d (%d+16)", finalMode, *mode)
			}

			log.Printf("Beacon sent. Waiting %d minutes until next beacon...", *interval)
			<-ticker.C
		}

		// Stop the ticker and close the connection before retrying.
		ticker.Stop()
		conn.Close()
		log.Printf("Connection lost. Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

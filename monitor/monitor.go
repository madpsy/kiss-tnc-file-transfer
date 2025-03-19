// monitor.go
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
)

// KISS constants
const (
	KISS_FLAG    = 0xC0
	KISS_ESC     = 0xDB
	KISS_ESC_END = 0xDC
	KISS_ESC_ESC = 0xDD
)

// removeKISSFrame removes the starting and ending KISS_FLAG bytes and unescapes the payload.
// If the frame is malformed, it returns nil.
func removeKISSFrame(frame []byte) []byte {
	if len(frame) < 2 || frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
		return nil
	}
	payload := frame[1 : len(frame)-1]
	var unescaped bytes.Buffer
	i := 0
	for i < len(payload) {
		b := payload[i]
		if b == KISS_ESC && i+1 < len(payload) {
			next := payload[i+1]
			if next == KISS_ESC_END {
				unescaped.WriteByte(KISS_FLAG)
			} else if next == KISS_ESC_ESC {
				unescaped.WriteByte(KISS_ESC)
			} else {
				unescaped.WriteByte(b)
				unescaped.WriteByte(next)
			}
			i += 2
		} else {
			unescaped.WriteByte(b)
			i++
		}
	}
	return unescaped.Bytes()
}

var asciiOutput bool
var decodeFileTransfer bool
var decodeAx25 bool

// Global Prometheus metrics.
var (
	totalFramesCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "frames_total",
		Help: "Total number of frames processed",
	})
	totalBytesCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bytes_total",
		Help: "Total number of bytes processed",
	})
	// Using linear buckets from 0 to 256 bytes with step 16.
	packetSizeHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "packet_size_bytes",
		Help:    "Distribution of packet sizes (max 255 bytes for AX.25 packets)",
		Buckets: prometheus.LinearBuckets(0, 16, 17),
	})
	packetIntervalHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "packet_interval_seconds",
		Help:    "Distribution of intervals between packets",
		Buckets: prometheus.DefBuckets,
	})
	// Total counter grouping by both src and dest.
	packetCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packets_by_callsign_total",
		Help: "Number of packets grouped by source, destination, and packet type",
	}, []string{"src", "dest", "packet_type"})
	// New metric: packets sent, by source callsign.
	packetsSentCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packets_sent_total",
		Help: "Total number of packets sent by a given source callsign",
	}, []string{"src", "packet_type"})
	// New metric: packets received, by destination callsign.
	packetsReceivedCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packets_received_total",
		Help: "Total number of packets received by a given destination callsign",
	}, []string{"dest", "packet_type"})
)

func init() {
	// Register all Prometheus metrics.
	prometheus.MustRegister(totalFramesCounter)
	prometheus.MustRegister(totalBytesCounter)
	prometheus.MustRegister(packetSizeHistogram)
	prometheus.MustRegister(packetIntervalHistogram)
	prometheus.MustRegister(packetCounter)
	prometheus.MustRegister(packetsSentCounter)
	prometheus.MustRegister(packetsReceivedCounter)
}

// decodeFileTransferPacket attempts to decode a file-transfer packet,
// and now also CMD/RSP packets.
func decodeFileTransferPacket(packet []byte) string {
	// Remove the KISS command byte.
	if len(packet) < 1 {
		return ""
	}
	packet = packet[1:]

	// Require at least 16 bytes for the AX.25 header.
	if len(packet) < 16 {
		return ""
	}
	totalPacketSize := len(packet)

	// Decode the AX.25 header.
	header := packet[:16]
	dest := decodeAX25Address(header[0:7])
	src := decodeAX25Address(header[7:14])
	// For file-transfer packets, we use the decoded addresses.
	sender := src
	receiver := dest

	// If there is any info beyond the header, process it.
	if len(packet) > 16 {
		infoField := packet[16:]
		infoStr := strings.TrimSpace(string(infoField))
		// Split the info field using colon as delimiter.
		parts := strings.Split(infoStr, ":")
		if len(parts) >= 3 {
			// Check for a CMD packet: expected format "cmdID:CMD:<cmd text>"
			if strings.ToUpper(parts[1]) == "CMD" {
				cmdID := parts[0]
				command := strings.Join(parts[2:], ":")
				return fmt.Sprintf("CMD Packet:\n  Total Packet Size: %d bytes\n  Destination: %s\n  Source: %s\n  Command ID: %s\n  Command: %s",
					totalPacketSize, dest, src, cmdID, command)
			}
			// Check for an RSP packet: expected format "cmdID:RSP:<status>:<msg>"
			if strings.ToUpper(parts[1]) == "RSP" && len(parts) >= 4 {
				cmdID := parts[0]
				status := parts[2]
				statusWord := "failed"
				if status == "1" {
					statusWord = "success"
				}
				msg := strings.Join(parts[3:], ":")
				return fmt.Sprintf("RSP Packet:\n  Total Packet Size: %d bytes\n  Destination: %s\n  Source: %s\n  Command ID: %s\n  Status: %s\n  Message: %s",
					totalPacketSize, dest, src, cmdID, statusWord, msg)
			}
		}

		// If the info field doesn’t match CMD/RSP formats, assume it’s a file-transfer packet.
		infoAndPayload := infoField
		if len(infoAndPayload) == 0 {
			return ""
		}

		var fileInfoField, payload []byte
		if strings.Contains(string(infoAndPayload), "ACK:") {
			// ACK packet: treat entire remainder as the info field.
			fileInfoField = infoAndPayload
			payload = []byte{}
		} else if len(infoAndPayload) >= 17 && string(infoAndPayload[3:7]) == "0001" {
			// Header packet (sequence == 1): first 17 bytes are info.
			fileInfoField = infoAndPayload[:17]
			payload = infoAndPayload[17:]
		} else if len(infoAndPayload) >= 12 {
			// Data packet: 12-byte info field.
			fileInfoField = infoAndPayload[:12]
			payload = infoAndPayload[12:]
		} else {
			return ""
		}

		infoStr = string(fileInfoField)
		parts = strings.Split(infoStr, ":")
		if len(parts) < 3 {
			return ""
		}

		// In file-transfer packets the first field is the fileID.
		fileID := strings.TrimSpace(parts[0])

		// ACK packet handling.
		if strings.ToUpper(strings.TrimSpace(parts[1])) == "ACK" {
			ackVal := strings.TrimSpace(parts[2])
			return fmt.Sprintf("ACK Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  ACK Value: %s",
				totalPacketSize, sender, receiver, fileID, ackVal)
		}

		// Header packet: expected second field to start with "0001"
		if strings.HasPrefix(parts[1], "0001") {
			if len(parts[1]) < 9 {
				return ""
			}
			burstHex := parts[1][4:8]
			burstDec, err := strconv.ParseInt(burstHex, 16, 32)
			if err != nil {
				return ""
			}
			totalData := 0
			if slashIdx := strings.Index(parts[1], "/"); slashIdx != -1 && len(parts[1]) > slashIdx+1 {
				totalHex := parts[1][slashIdx+1:]
				totalDec, err := strconv.ParseInt(totalHex, 16, 32)
				if err == nil {
					totalData = int(totalDec)
				}
			}
			headerPayload := strings.TrimSpace(string(payload))
			headerFields := strings.Split(headerPayload, "|")
			if len(headerFields) < 10 {
				return ""
			}
			timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(headerFields[0]))
			if err != nil {
				timeoutSeconds = 0
			}
			timeoutRetries := strings.TrimSpace(headerFields[1])
			fileName := headerFields[2]
			origSize := headerFields[3]
			compSize := headerFields[4]
			md5Hash := headerFields[5]
			encodingMethod := headerFields[7] // "0" = binary, "1" = base64
			compressFlag := headerFields[8]     // "1" if enabled
			totalIncludingHeader := headerFields[9]
			encStr := "Binary"
			if encodingMethod == "1" {
				encStr = "Base64"
			}
			compStr := "No"
			if compressFlag == "1" {
				compStr = "Yes"
			}
			return fmt.Sprintf("HEADER Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  Sequence: 1\n  BurstTo: %d\n  Total Data Packets (excluding header): %d\n\n  Header Payload:\n    Timeout Seconds: %d\n    Timeout Retries: %s\n    File Name: %s\n    Original Size: %s bytes\n    Compressed Size: %s bytes\n    MD5 Hash: %s\n    Encoding: %s\n    Compression Enabled: %s\n    Total Packets (including header): %s",
				totalPacketSize, sender, receiver, fileID, burstDec, totalData,
				timeoutSeconds, timeoutRetries, fileName, origSize, compSize, md5Hash, encStr, compStr, totalIncludingHeader)
		}

		// Otherwise, assume a regular data packet.
		if len(parts[1]) < 8 {
			return ""
		}
		seqHex := parts[1][:4]
		burstHex := parts[1][4:8]
		seqDec, err1 := strconv.ParseInt(seqHex, 16, 32)
		burstDec, err2 := strconv.ParseInt(burstHex, 16, 32)
		if err1 != nil || err2 != nil {
			return ""
		}
		return fmt.Sprintf("DATA Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  Sequence: %d\n  BurstTo: %d\n  Payload Length: %d bytes",
			totalPacketSize, sender, receiver, fileID, seqDec, burstDec, len(payload))
	}

	return ""
}

// decodeAX25Packet attempts to decode the AX.25 header and payload from the packet.
// If the PID is missing, it logs 'null' for the PID.
func decodeAX25Packet(packet []byte) string {
	if len(packet) == 0 {
		return "Empty packet"
	}

	// Assume the first byte is the KISS command.
	kissCmd := packet[0]
	packet = packet[1:]

	// We need at least 14 bytes for destination and source addresses.
	if len(packet) < 14 {
		return fmt.Sprintf("AX.25 header incomplete (KISS cmd 0x%02X), available bytes: % X", kissCmd, packet)
	}

	// Decode destination (first 7 bytes) and source (next 7 bytes).
	dest := decodeAX25Address(packet[0:7])
	src := decodeAX25Address(packet[7:14])

	// Decode control field if available.
	var control byte = 0
	if len(packet) >= 15 {
		control = packet[14]
	}

	// Decode PID if available; otherwise use "null".
	var pid string
	if len(packet) >= 16 {
		pid = fmt.Sprintf("0x%02X", packet[15])
	} else {
		pid = "null"
	}

	// The payload starts after the header. If PID is missing, payload starts at offset 15;
	// otherwise, it starts at offset 16.
	var payloadStart int
	if len(packet) >= 16 {
		payloadStart = 16
	} else {
		payloadStart = 15
	}

	var payloadInfo string
	if len(packet) > payloadStart {
		payloadInfo = "\nPayload (ASCII): " + string(packet[payloadStart:])
	}

	// Swap source and destination in the output.
	return fmt.Sprintf("AX.25 Header (KISS cmd 0x%02X):\n  Source: %s\n  Destination: %s\n  Control: 0x%02X\n  PID: %s",
		kissCmd, src, dest, control, pid) + payloadInfo
}

// decodeAX25Address decodes a 7-byte AX.25 address field into a human-readable callsign.
func decodeAX25Address(addr []byte) string {
	// Each address is 7 bytes. The first 6 bytes contain the callsign (each character shifted right by 1).
	callsign := ""
	for i := 0; i < 6; i++ {
		c := addr[i] >> 1
		// Only add non-space characters.
		if c != ' ' {
			callsign += string(c)
		}
	}
	// The 7th byte contains the SSID in bits 1-4.
	ssid := (addr[6] >> 1) & 0x0F
	if ssid > 0 {
		callsign += fmt.Sprintf("-%d", ssid)
	}
	return callsign
}

func main() {
	// Disable the default logger timestamp.
	log.SetFlags(0)

	// Command-line arguments for connecting to the broadcast server.
	host := flag.String("host", "127.0.0.1", "Broadcast host (default 127.0.0.1)")
	port := flag.Int("port", 0, "Broadcast port (required)")

	// MQTT options.
	mqttHost := flag.String("mqtt-host", "", "MQTT server host")
	mqttPort := flag.Int("mqtt-port", 0, "MQTT server port")
	mqttUser := flag.String("mqtt-user", "", "MQTT username")
	mqttPass := flag.String("mqtt-pass", "", "MQTT password")
	mqttTLS := flag.Bool("mqtt-tls", false, "Use TLS for MQTT")
	mqttTopic := flag.String("mqtt-topic", "", "MQTT topic to publish frames")

	// Optional Prometheus port.
	prometheusPort := flag.Int("prometheus-port", 2112, "Port for Prometheus metrics endpoint (default 2112)")

	// Optional file-dump options for Prometheus metrics.
	prometheusFile := flag.String("prometheus-file", "", "File path to dump Prometheus metrics")
	prometheusPeriod := flag.Int("prometheus-period", 300, "Period (in seconds) to dump metrics to file (default 300 seconds)")

	// Flag for ascii output (for raw frames).
	flag.BoolVar(&asciiOutput, "ascii", false, "Print frames as ASCII text instead of hexadecimal")
	// Flag to attempt to decode file transfer packets.
	flag.BoolVar(&decodeFileTransfer, "decode-file-transfer", false, "Attempt to decode known file transfer packets")
	// Flag to attempt to decode AX.25 packets.
	flag.BoolVar(&decodeAx25, "decode-ax25", false, "Attempt to decode all AX.25 packets")

	flag.Parse()

	// Enforce mutual exclusivity for decoding options.
	if decodeAx25 && (asciiOutput || decodeFileTransfer) {
		fmt.Fprintln(os.Stderr, "Error: -decode-ax25 is mutually exclusive with -ascii and -decode-file-transfer")
		flag.Usage()
		os.Exit(1)
	}

	if *port == 0 {
		fmt.Fprintln(os.Stderr, "Error: -port is required")
		flag.Usage()
		os.Exit(1)
	}

	mqttEnabled := false
	if *mqttHost != "" || *mqttPort != 0 || *mqttUser != "" || *mqttPass != "" || *mqttTopic != "" {
		if *mqttHost == "" || *mqttPort == 0 || *mqttUser == "" || *mqttPass == "" || *mqttTopic == "" {
			fmt.Fprintln(os.Stderr, "Error: When using MQTT, all MQTT parameters are required")
			flag.Usage()
			os.Exit(1)
		}
		mqttEnabled = true
	}

	// Setup MQTT client if enabled.
	var mqttClient mqtt.Client
	if mqttEnabled {
		opts := mqtt.NewClientOptions()
		mqttAddr := fmt.Sprintf("tcp://%s:%d", *mqttHost, *mqttPort)
		if *mqttTLS {
			mqttAddr = fmt.Sprintf("ssl://%s:%d", *mqttHost, *mqttPort)
			tlsConfig := &tls.Config{InsecureSkipVerify: true}
			opts.SetTLSConfig(tlsConfig)
		}
		opts.AddBroker(mqttAddr)
		opts.SetUsername(*mqttUser)
		opts.SetPassword(*mqttPass)
		opts.SetClientID("monitor-client-" + fmt.Sprint(time.Now().UnixNano()))
		// Enable automatic MQTT reconnection.
		opts.SetAutoReconnect(true)
		opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
			log.Printf("MQTT connection lost: %v. Reconnecting...", err)
		})
		mqttClient = mqtt.NewClient(opts)
		if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
			log.Fatalf("Error connecting to MQTT broker: %v", token.Error())
		}
		log.Printf("Connected to MQTT broker at %s", mqttAddr)
	}

	// Start Prometheus metrics HTTP server on the specified port.
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		addr := fmt.Sprintf(":%d", *prometheusPort)
		log.Fatal(http.ListenAndServe(addr, nil))
	}()

	// If either prometheus-file or prometheus-period are set (non-empty or > 0),
	// launch a goroutine that dumps the metrics to file periodically.
	if *prometheusFile != "" {
  	  period := time.Duration(*prometheusPeriod) * time.Second
  	  go func() {
	        ticker := time.NewTicker(period)
	        defer ticker.Stop()
	        for range ticker.C {
	            // Gather metrics.
	            mfs, err := prometheus.DefaultGatherer.Gather()
	            if err != nil {
	                log.Printf("Error gathering metrics: %v", err)
	                continue
	            }
	            var buf bytes.Buffer
	            encoder := expfmt.NewEncoder(&buf, expfmt.FmtText)
	            for _, mf := range mfs {
	                if err := encoder.Encode(mf); err != nil {
	                    log.Printf("Error encoding metric family: %v", err)
	                }
	            }
	            // Write to file.
	            if err := ioutil.WriteFile(*prometheusFile, buf.Bytes(), 0644); err != nil {
	                log.Printf("Error writing metrics to file %s: %v", *prometheusFile, err)
	            } else {
	                log.Printf("Dumped metrics to file %s", *prometheusFile)
	            }
	        }
	    }()
	}

	// --- Local metrics variables for computation ---
	var minDelta int64 = math.MaxInt64
	var maxDelta int64
	var lastPacketTime time.Time

	// Set up signal handling to catch Ctrl-C (SIGINT)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		// When Ctrl-C is caught, print the summary and exit.
		log.Printf("\n--- Summary ---")
		log.Printf("Total frames seen: %v", totalFramesCounter)
		log.Printf("Total bytes seen: %v", totalBytesCounter)
		if totalFramesCounter != nil {
			log.Printf("Minimum time between packets: %d ms", minDelta)
			log.Printf("Maximum time between packets: %d ms", maxDelta)
		} else {
			log.Printf("Not enough packets to compute time differences.")
		}
		os.Exit(0)
	}()

	// Prepare a buffer for incoming data.
	buf := make([]byte, 4096)
	var dataBuffer []byte

	addrStr := fmt.Sprintf("%s:%d", *host, *port)

	// Outer loop: attempt to (re)connect to the broadcast server.
	for {
		conn, err := net.Dial("tcp", addrStr)
		if err != nil {
			log.Printf("Error connecting to broadcast server at %s: %v. Retrying in 5 seconds...", addrStr, err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("Connected to broadcast server at %s", addrStr)
		dataBuffer = nil // reset buffer for new connection

		// Inner loop: read data until an error occurs.
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("Error reading from broadcast connection: %v", err)
				conn.Close()
				break
			}
			if n > 0 {
				dataBuffer = append(dataBuffer, buf[:n]...)
				for {
					start := bytes.IndexByte(dataBuffer, KISS_FLAG)
					if start == -1 {
						dataBuffer = nil
						break
					}
					end := bytes.IndexByte(dataBuffer[start+1:], KISS_FLAG)
					if end == -1 {
						break
					}
					end = start + 1 + end
					frame := dataBuffer[start : end+1]
					dataBuffer = dataBuffer[end+1:]
					payload := removeKISSFrame(frame)
					if payload == nil {
						continue
					}

					// Update global metrics.
					totalFramesCounter.Inc()
					totalBytesCounter.Add(float64(len(payload)))
					packetSizeHistogram.Observe(float64(len(payload)))

					now := time.Now()
					if !lastPacketTime.IsZero() {
						d := now.Sub(lastPacketTime)
						packetIntervalHistogram.Observe(d.Seconds())
					}
					lastPacketTime = now

					var deltaStr string
					if !lastPacketTime.IsZero() {
						d := now.Sub(lastPacketTime)
						deltaMs := d.Milliseconds()
						// If the delta is less than 1ms, use microseconds.
						if deltaMs == 0 {
							deltaStr = fmt.Sprintf("+%dµs", d.Microseconds())
						} else {
							deltaStr = fmt.Sprintf("+%dms", deltaMs)
						}
					} else {
						deltaStr = ""
					}
					timeStamp := fmt.Sprintf("[%s %s]", now.Format(time.RFC3339Nano), deltaStr)

					// Publish raw packet to MQTT if enabled.
					if mqttEnabled {
						token := mqttClient.Publish(*mqttTopic, 0, false, payload)
						token.Wait()
						if token.Error() != nil {
							log.Printf("Error publishing to MQTT: %v", token.Error())
						}
					}

					// Determine packet type and extract callsigns.
					var src, dest, packetType string
					if decodeAx25 {
						// For AX.25 decoding, extract callsigns from payload:
						if len(payload) >= 15 {
							// payload[0] is kiss cmd; addresses follow.
							dest = decodeAX25Address(payload[1:8])
							src = decodeAX25Address(payload[8:15])
						}
						packetType = "ax25"
						decoded := decodeAX25Packet(payload)
						log.Printf("%s\n%s", timeStamp, decoded)
					} else if decodeFileTransfer {
						// For file transfer, the first 16 bytes after the kiss cmd form the header.
						if len(payload) >= 17 {
							header := payload[1:17]
							dest = decodeAX25Address(header[0:7])
							src = decodeAX25Address(header[7:14])
						}
						packetType = "file_transfer"
						decoded := decodeFileTransferPacket(payload)
						if decoded != "" {
							log.Printf("%s\n%s", timeStamp, decoded)
						}
					} else {
						// For raw packets, mark as such.
						packetType = "raw"
						src = "unknown"
						dest = "unknown"
						if asciiOutput {
							log.Printf("%s %s", timeStamp, string(payload))
						} else {
							log.Printf("%s % X", timeStamp, payload)
						}
					}

					// Update the total per-callsign packet counter.
					packetCounter.WithLabelValues(src, dest, packetType).Inc()

					// Update the sent and received metrics.
					packetsSentCounter.WithLabelValues(src, packetType).Inc()
					packetsReceivedCounter.WithLabelValues(dest, packetType).Inc()
				}
			}
		}
		// Wait 5 seconds before attempting to reconnect.
		log.Printf("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

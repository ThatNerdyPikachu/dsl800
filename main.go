/*
22 93
05
12 F1
20
32 02
FF
*/

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
)

const (
	commandGreeting        = 0x01
	commandProtocolError   = 0x02
	commandGenericResponse = 0x03
	commandSecureResponse  = 0x04
	commandTimeout         = 0x05

	commandGetTime       = 0x81
	commandStartSecurity = 0x82
	commandPing          = 0x83
	commandRequestFlag   = 0x84
)

var commandMagic = []byte{0x44, 0x4E, 0x53, 0x4D}

func read(conn net.Conn, len uint8) []byte {
	x := make([]byte, len)

	conn.Read(x)

	return x
}

func main() {
	genericMessageCounter := 0
	connectionKey := []byte{}

	conn, err := net.Dial("tcp", "problems.hackdalton.com:24992")
	if err != nil {
		panic(err)
	}

	for {
		magic := read(conn, 4)

		if !bytes.Equal(magic, commandMagic) {
			return
		}

		fmt.Printf("got magic!\n")

		command := read(conn, 1)

		_ = read(conn, 1) // sequence number

		dataLength := read(conn, 1)

		securityFlag := read(conn, 1) // security flag

		_ = read(conn, 4) // security message key

		_ = read(conn, 4) // security checksum

		data := read(conn, dataLength[0])

		switch command[0] {
		case commandGreeting:
			fmt.Printf("is greeting\n")

			fmt.Printf("%s\n", string(data))

			var command []byte

			command = append(command, commandMagic...)
			command = append(command, commandGetTime)
			command = append(command, 0)          // sequence number
			command = append(command, 0)          // data length
			command = append(command, 0)          // security flag
			command = append(command, 0, 0, 0, 0) // security message key
			command = append(command, 0, 0, 0, 0) // security checksum

			conn.Write(command)
		case commandProtocolError:
			fmt.Printf("error: %s\n", string(data))

			return
		case commandGenericResponse:
			fmt.Printf("generic response\n")

			switch genericMessageCounter {
			case 0:
				var command []byte

				command = append(command, commandMagic...)
				command = append(command, commandStartSecurity)
				command = append(command, 1)          // sequence number
				command = append(command, 0)          // data length
				command = append(command, 0)          // security flag
				command = append(command, 0, 0, 0, 0) // security message key
				command = append(command, 0, 0, 0, 0) // security checksum

				conn.Write(command)
			case 1:
				// security tip
			case 2:
				connectionKey = data

				pingPayload := make([]byte, 255)
				rand.Read(pingPayload)

				sumBE := make([]byte, 4)
				binary.BigEndian.PutUint32(sumBE, crc32.ChecksumIEEE(pingPayload[:80]))

				messageKey := make([]byte, 4)
				rand.Read(messageKey)

				finalKey := make([]byte, 4)

				for i, x := range connectionKey {
					finalKey[i] = x + messageKey[i]
				}

				counter := 0

				ciphertext := []byte{}

				for _, b := range pingPayload {
					ciphertext = append(ciphertext, b^finalKey[counter])

					if counter < 3 {
						counter++
					} else {
						counter = 0
					}
				}

				var command []byte

				command = append(command, commandMagic...)
				command = append(command, commandPing)
				command = append(command, 2)             // sequence number
				command = append(command, 255)           // data length
				command = append(command, 1)             // security flag
				command = append(command, messageKey...) // security message key
				command = append(command, sumBE...)      // security checksum
				command = append(command, ciphertext...)

				conn.Write(command)
			}

			genericMessageCounter++
		case commandSecureResponse:
			if securityFlag[0] != 1 {
				return
			}

			/*finalKey := make([]byte, 4)

			for i, x := range connectionKey {
				finalKey[i] = x + securityMessageKey[i]
			}

			counter := 0

			plaintext := make([]byte, len(data))

			for _, b := range data {
				plaintext = append(plaintext, b^finalKey[counter])

				if counter < 3 {
					counter++
				} else {
					counter = 0
				}
			}*/

			fmt.Printf("%s\n", string(data))

			fmt.Printf("%x\n", data)

			return
		default:
			fmt.Printf("unknown command: 0x%x\n", command)
		}
	}
}

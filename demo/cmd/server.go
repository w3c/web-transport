package main

import (
	"demo"
	"fmt"
	"log"
	"net"
	"net/http"
)

var (
	httpPort    = ":3030"
	iceAddress  = "127.0.0.1"
	icePort     = 3737
	icePassword = "password"

	// If any of these are set, an HTTP server will be run
	iceAddressUrl  = "/ice-address"
	icePortUrl     = "/ice-port"
	icePasswordUrl = "/ice-password"
)

func runIceQuicServer() {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: icePort})
	if err != nil {
		log.Fatalf("Failed to open UDP port %d: '%s'\n", icePort, err)
	}
	log.Printf("Listening for ICE and QUIC on %s for password %s.\n", udp.LocalAddr(), icePassword)

	buffer := make([]byte, 1500)
	for {
		size, addr, err := udp.ReadFromUDP(buffer[:])
		log.Printf("Read packet of size %d from %s.\n", size, addr)
		p := buffer[:size]
		if err != nil {
			log.Fatalf("Failed to read UDP packet: '%s'\n", err)
		}

		stun := demo.VerifyStunPacket(p)
		isIceCheck := (stun != nil && stun.Type() == demo.StunBindingRequest && stun.ValidateFingerprint())
		if isIceCheck {
			if !stun.ValidateMessageIntegrity([]byte(icePassword)) {
				log.Printf("ICE check has bad message integrity.\n")
				continue
			}
			response := demo.NewStunPacket(demo.StunBindingResponse, stun.TransactionId()).AppendMessageIntegrity([]byte(icePassword)).AppendFingerprint()
			_, err = udp.WriteTo(response, addr)
			if err != nil {
				log.Printf("Failed to write ICE check response.\n")
			}
		} else {
			log.Printf("Read unknown packet of size %d from %s.\n", size, addr)
		}
	}
}

func runHttpServer() {
	http.HandleFunc(iceAddressUrl, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, iceAddress)
	})
	http.HandleFunc(icePortUrl, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, icePort)
	})
	http.HandleFunc(icePasswordUrl, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, icePassword)
	})

	http.Handle("/", http.FileServer(http.Dir(".")))

	log.Fatal(http.ListenAndServe(httpPort, nil))
}

func main() {
	if len(iceAddressUrl) > 0 || len(iceAddressUrl) > 0 || len(icePasswordUrl) > 0 {
		go runHttpServer()
	}
	runIceQuicServer()
}

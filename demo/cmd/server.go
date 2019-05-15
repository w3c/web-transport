package main

import (
	"demo"
	"log"
	"net"
	)

var udpPort = 3737

// Do this if you need to provide the files to pass in the client's password to send back pings
// func runHttpServer() {
// 	http.HandleFunc("/ice", func(w http.ResponseWriter, r *http.Request) {
// 		icePassword, err := ioutil.ReadAll(r.Body)
// 		if err != nil {
// 			log.Fatal("Connection to /ice blew up.")
// 		}
// 		go runIceQuicServer(icePassword)
// 	})
// 	http.Handle("/", http.FileServer(http.Dir(".")))

// 	log.Fatal(http.ListenAndServe(":8080", nil))
// }

func runIceQuicServer(icePassword string) {
	// TODO: Can we just do this? net.ListenUDP(???, &net.UDPAddr{})
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: udpPort})
	if err != nil {
		log.Fatalf("Failed to open UDP port %d: '%s'\n", udpPort, err)
	}
	log.Printf("Listening for ICE and QUIC on %s for password %s.\n", udp.LocalAddr(), icePassword)

	buffer := make([]byte, 1500)
	for {
		size, addr, err := udp.ReadFromUDP(buffer[:])
		p := buffer[:size]
		if err != nil {
			log.Fatalf("Failed to read UDP packet: '%s'\n", err)
		}
		// log.Printf("Read packet of size %d from %s.\n", size, addr)
		
		stun := demo.VerifyStunPacket(p)
		isIceCheck := (stun != nil && stun.Type() == demo.StunBindingRequest && stun.ValidateFingerprint())

		if !isIceCheck {
			log.Printf("It's an unknown packet.\n")
			continue
		}
		check := stun
		// log.Printf("It's an ICE check.\n")

		// Do this if you want
		// if !check.ValidateMessageIntegrity(icePassword) {
		//	log.Printf("ICE check has bad message integrity.\n")
		//	continue
		//}

		// log.Printf("Received ICE packet with username %s from %v \n", username, addr)

		response := demo.NewStunPacket(demo.StunBindingResponse, check.TransactionId()).AddMessageIntegrity([]byte(icePassword)).AddFingerprint()
    
		_, err = udp.WriteTo(response, addr)
		if err != nil {
			log.Printf("Failed to write ICE check response.\n")
			continue
		}
		// log.Printf("Wrote ICE check response to %v.\n", addr)
		
		// Do this if you need to send checks back.  But it doesn't look like we need to.
		// TODO: Don't assume local and remote ufrag and pwd are the same.
		// username, found := check.FindUsername()
		// if !found {
		// 	log.Printf("ICE check has no username.\n")
		// 	continue
		// }
	  // checkBack := demo.NewStunPacketWithRandomTid(demo.StunBindingRequest).AddUsername(username).AddMessageIntegrity(icePassword)
    // 	_, err = udp.WriteTo(checkBack, addr)
		// if err != nil {
		// 	log.Printf("Failed to write ICE check back.\n")
		// 	continue
		// }
		// log.Printf("Wrote ICE check back with username %s and password %s to %v.\n", username, icePassword, addr)
	}
}

func main() {
	// runHttpServer()
	runIceQuicServer("password")
}

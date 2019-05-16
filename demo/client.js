const demoConfig = {
  // If the URLs are set, it will use them.
  serverIceAddressUrl: "/ice-address",
  serverIcePorUrl: "/ice-port",
  serverIcePasswordUrl: "/ice-password",

  // If they URLs are not set, these values will be used.
  serverIceAddress: "127.0.0.1",
  serverIcePort: 3737,
  serverIcePassword: "password",
};

async function runClient(config) {
  const ice = new RTCIceTransport();
  const quic = new RTCQuicTransport(ice);
  ice.onstatechange = (e) => {
    log(`ICE state changed to ${ice.state}`); 
    document.querySelector("#ice-state").textContent = ice.state;
  }
  quic.onstatechange = (e => {
    log(`QUIC state changed to ${quic.state}`);
    document.querySelector("#quic-state").textContent = quic.state;
  });

  let serverAddress = config.serverIceAddress;
  let serverPort = config.serverIcePort;
  let serverIcePassword = config.serverIcePassword;
  if (location.protocol == "http" || location.protocol == "https") {
    if(!!config.serverIceAddressUrl) {
      serverAddress = await fetch(config.serverIceAddressUrl);
    }
    if(!!config.serverIcePortal) {
      serverPort = await fetch(config.serverPort)
    }
    if(!!config.serverIcePasswordUrl) {
      serverIcePassword = await fetch(config.serverIcePasswordUrl);
    }
  }


  ice.gather({});
  ice.start({
    // This is a hack to simplify the server code.  It doesn't need to flip the username around.
    usernameFragment: ice.getLocalParameters().usernameFragment,
    password: serverIcePassword
  });
  // TODO: Make this work:
  // ice.addRemoteCandidate(new RTCIceCandidate({type: "host", ip: "127.0.0.1", protocol: "udp", port: 3737}));
  ice.addRemoteCandidate(new RTCIceCandidate({sdpMid: "", candidate: `candidate:0 0 UDP 0 ${config.serverIceAddress} 3737 typ host`}));

  /* TODO
  this.quic.onquicstream = ({stream}) => {
    log(`Got a QUIC stream: ${stream}`); 
  }; */
  
}

function log(msg) {
  console.log(msg);
}

runClient(demoConfig);

function log(msg) {
  console.log(msg);
}

function runIceQuicClient(ice, remotePassword) {
  // log ("Created RTCIceTransport.");
  
  ice.gather({});
  ice.start({
    usernameFragment: ice.getLocalParameters().usernameFragment,
    password: remotePassword
  });
  // Sadly, this does not work
  // ice.addRemoteCandidate(new RTCIceCandidate({type: "host", ip: "127.0.0.1", protocol: "udp", port: 3737}));
  ice.addRemoteCandidate(new RTCIceCandidate({sdpMid: "", candidate: "candidate:0 0 UDP 0 127.0.0.1 3737 typ host"}));

  // log (`Started RTCIceTransport with ufrag ${local.usernameFragment} and pwd ${local.password}.`);
}

async function runHttpClient(ice, url) {
  let response = await fetch(url, {
    method: 'post',
    body: ice.getLocalParameters().password,
  });
  remotePassword = ice.getLocalParameters().password
  runIceQuicClient(ice, remotePassword)
}

async function main() {
  const ice = new RTCIceTransport();
  ice.onstatechange = (e) => {
    log(`ICE state changed to ${ice.state}`); 
  }
  // Do this if you want to upload the client's local ufrag/password
  // await unHttpClient(ice, "/ice");
  runIceQuicClient(ice, "password");
}

main()







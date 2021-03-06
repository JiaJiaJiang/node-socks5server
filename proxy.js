
var net = require('net'),
	{
		createSocksServer,
		UDPRelay,
		TCPRelay,
	} = require('./index.js');
var commander = require('commander');
	
commander
	.usage('[options]')
	.option('-u, --user [value]', 'set a user:pass format user')
	.option('-H, --host [value]', 'host to listen,defaults to 127.0.0.1')
	.option('-P, --port <n>', 'port to listen,defaults to 1080',/^\d+$/i)
	.option('--localAddress [value]', 'local address to establish the connection')
	.option('--localPort [value]', 'local port to establish the connection')
	.parse(process.argv);

const opts=commander.opts();
// Create server
// The server accepts SOCKS connections. This particular server acts as a proxy.
var HOST=opts.host||'127.0.0.1',
	PORT=opts.port||'1080',
	server = createSocksServer();

console.log('server starting at ',HOST,':',PORT);

if(opts.user){
	let u=opts.user.split(":");
	server.setSocks5UserPass(u[0],u[1]);
	console.log('user ',opts.user);
}

/*
tcp request relay
directly connect the target and source
*/
function relayTCP(socket, address, port, CMD_REPLY){
	let relay=new TCPRelay(socket, address, port, CMD_REPLY, opts.localAddress, opts.localPort);
	relay.on('connection',(socket,relaySocket)=>{
		console.log('[TCP]',`${socket.remoteAddress}:${socket.remotePort} ==> ${net.isIP(address)?'':'('+address+')'} ${relaySocket.remoteAddress}:${relaySocket.remotePort}`);
	}).on('proxy_error',(err,socket,relaySocket)=>{
		console.error('	[TCP proxy error]',`${relay.remoteAddress}:${relay.remotePort}`,err.message);
	}).once('close',e=>{
		let msg='';
		if(socket.remoteAddress)
			msg+=`${socket.remoteAddress}:${socket.remotePort} ==> `;
		if(relay.remoteAddress){
			msg+=`${net.isIP(address)?'':'('+address+')'} ${relay.remoteAddress}:${relay.remotePort}`;
		}else{
			msg+=`${address}:${port}`;
		}
		console.log('  [TCP closed]',msg);
	});

	//example for modify data
	relay.outModifier=null;//give a readable stream here to modify outgoing data
	relay.inModifier=null;//give a readable stream here to modify incoming data
}

/*
udp request relay
send udp msgs to each other
*/
function relayUDP(socket, address, port, CMD_REPLY){
	console.log('[UDP]',`${socket.remoteAddress}`);
	let relay=new UDPRelay(socket, address, port, CMD_REPLY);
	relay.on('proxy_error',(relaySocket,direction,err)=>{
		console.error('	[UDP proxy error]',`[${direction}]`,err.message);
	});
	relay.relaySocket.once('close',()=>{
		console.log('  [UDP closed]',socket.remoteAddress);
	});

	//example for modify data sync
	relay.on('message',(fromClient,packet)=>{
		fromClient;//is this packet from the client

		// when fromClient is true
		packet.address;//target address
		packet.port;//target port
		packet.data;//client sent data

		// when fromClient is false
		packet.address;//source address
		packet.port;//source port
		packet.data;//data

		//If the packet was not from the client, modification on addreses and
		//port will not take effect, because the packet must be sent back
		//to the client
	});

	//example for modify data async
	relay.packetHandler=async (fromClient,packet)=>{
		//same with previous
	};
}

//the socks server
server
.on('tcp',relayTCP)
.on('udp',relayUDP)
.on('error', function (e) {
	console.error('SERVER ERROR: %j', e);
	if(e.code == 'EADDRINUSE') {
		console.log('Address in use, retrying in 10 seconds...');
		setTimeout(function () {
			console.log('Reconnecting to %s:%s', HOST, PORT);
			server.close();
			server.listen(PORT, HOST);
		}, 10000);
	}
}).on('client_error',(socket,e)=>{
	console.error('  [client error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
}).on('socks_error',(socket,e)=>{
	console.error('  [socks error]',`${net.isIP(socket.targetAddress)?'':'('+(socket.targetAddress||"unknown")+')'} ${socket.remoteAddress||"unknown"}:${socket.targetPort||"unknown"}`,e);
}).listen(PORT, HOST);

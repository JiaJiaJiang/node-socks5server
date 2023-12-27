'use strict'

const net = require('net'),
	DNS = require('dns'),
	dgram = require('dgram'),
	events = require('events'),
	ipAddress = require('ip-address');
const { pipeline } = require('stream');

const SOCKS_VERSION5 = 5,
	SOCKS_VERSION4 = 4;
/*
 * Authentication methods
 ************************
 * o  X'00' NO AUTHENTICATION REQUIRED
 * o  X'01' GSSAPI
 * o  X'02' USERNAME/PASSWORD
 * o  X'03' to X'7F' IANA ASSIGNED
 * o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 * o  X'FF' NO ACCEPTABLE METHODS
 */
const AUTHENTICATION = {
	NOAUTH: 0x00,
	GSSAPI: 0x01,
	USERPASS: 0x02,
	NONE: 0xFF
};
/*
 * o  CMD
 *    o  CONNECT X'01'
 *    o  BIND X'02'
 *    o  UDP ASSOCIATE X'03'
 */
const REQUEST_CMD = {
	CONNECT: 0x01,
	BIND: 0x02,
	UDP_ASSOCIATE: 0x03
};
/*

 */
const SOCKS_REPLY = {
	SUCCEEDED: 0x00,
	SERVER_FAILURE: 0x01,
	NOT_ALLOWED: 0X02,
	NETWORK_UNREACHABLE: 0X03,
	HOST_UNREACHABLE: 0X04,
	CONNECTION_REFUSED: 0X05,
	TTL_EXPIRED: 0X06,
	COMMAND_NOT_SUPPORTED: 0X07,
	ADDR_NOT_SUPPORTED: 0X08,
};
/*
 * o  ATYP   address type of following address
 *    o  IP V4 address: X'01'
 *    o  DOMAINNAME: X'03'
 *    o  IP V6 address: X'04'
 */
const ATYP = {
	IP_V4: 0x01,
	DNS: 0x03,
	IP_V6: 0x04
};


//CMD reply
const _005B = Buffer.from([0x00, 0x5b]),//?
	_0101 = Buffer.from([0x01, 0x01]),//auth failed
	_0501 = Buffer.from([0x05, 0x01]),//general SOCKS server failure
	_0507 = Buffer.from([0x05, 0x01]),//Command not supported
	_0100 = Buffer.from([0x01, 0x00]);//auth succeeded


const Address = {
	read: function (buffer, offset) {//offset : offset of ATYP in buffer
		if (buffer[offset] == ATYP.IP_V4) {
			return `${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}.${buffer[offset + 4]}`;
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer.toString('utf8', offset + 2, offset + 2 + buffer[offset + 1]);
		} else if (buffer[offset] == ATYP.IP_V6) {
			let h = [...buffer.slice(offset + 1, offset + 1 + 16)].map(num => num.toString(16).padStart(2, '0'));//to hex address
			//divide every 2 bytes into groups
			return `${h[0]}${h[1]}:${h[2]}${h[3]}:${h[4]}${h[5]}:${h[6]}${h[7]}:${h[8]}${h[9]}:${h[10]}${h[11]}:${h[12]}${h[13]}:${h[14]}${h[15]}`;
		}
	},
	//size of byteLength in buffer
	sizeOf: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) {
			return 4;
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer[offset + 1];
		} else if (buffer[offset] == ATYP.IP_V6) {
			return 16;
		}
	}
},
	Port = {
		read: function (buffer, offset) {//offset : offset of ATYP in buffer
			if (buffer[offset] == ATYP.IP_V4) {
				return buffer.readUInt16BE(8);
			} else if (buffer[offset] == ATYP.DNS) {
				return buffer.readUInt16BE(5 + buffer[offset + 1]);
			} else if (buffer[offset] == ATYP.IP_V6) {
				return buffer.readUInt16BE(20);
			}
		},
	};

/*
options:
	the same as net.Server options
*/
class socksServer extends net.Server {
	constructor(options) {
		super(options);
		this.enabledVersion = new Set([SOCKS_VERSION5, SOCKS_VERSION4]);
		this.enabledCmd = new Set([REQUEST_CMD.CONNECT, REQUEST_CMD.UDP_ASSOCIATE]);
		this.socks5 = {
			authMethodsList: new Set([AUTHENTICATION.NOAUTH]),
			authConf: {
				userpass: new Map(),
			},
			authFunc: new Map([
				[AUTHENTICATION.USERPASS, this._socks5UserPassAuth.bind(this)],
				[AUTHENTICATION.NOAUTH, this._socks5NoAuth.bind(this)],
			]),
		};
		this.on('connection', socket => {
			//socket._socksServer=this;
			socket.on('error', e => {
				this.emit('client_error', socket, e);
			}).once('data', chunk => {
				this._handshake(socket, chunk);
			}).on('socks_error', e => {
				this.emit('socks_error', socket, e);
			});
		});
	}
	/**
	 *set authentication function for each method
	 *
	 * @param {number} method method defined in AUTHENTICATION
	 * @param {function} func
	 */
	setSocks5AuthFunc(method, func) {
		if (typeof func !== 'function' || typeof method !== 'number')
			throw (new TypeError('Invalid arguments'));
		this.socks5.authFunc.set(method, func);
	}
	/**
	 *set enabled authentication methods
	 *
	 * @param {Array[number]} list list of method defined in AUTHENTICATION
	 */
	setSocks5AuthMethods(list) {
		if (!Array.isArray(list))
			throw (new TypeError('Not an Array'));
		this.socks5.authMethodsList = new Set(list);
	}
	/**
	 *set an authentication method
	 *
	 * @param {number} method method defined in AUTHENTICATION
	 * @returns {boolean}  
	 */
	deleteSocks5AuthMethod(method) {
		return this.socks5.authMethodsList.delete(method);
	}
	/**
	 *add an user for USERPASS auth method
	 *
	 * @param {string} user
	 * @param {string} pass
	 */
	setSocks5UserPass(user, pass) {
		if (typeof user !== 'string' || typeof pass !== 'string')
			throw (new TypeError('Invalid username or password'));
		this.socks5.authConf.userpass.set(user, pass);
		let methodList = this.socks5.authMethodsList;
		if (!methodList.has(AUTHENTICATION.USERPASS)) {
			methodList.add(AUTHENTICATION.USERPASS);
		}
		if (methodList.has(AUTHENTICATION.NOAUTH)) {
			methodList.delete(AUTHENTICATION.NOAUTH);
		}
	}
	/**
	 *delete an user for USERPASS auth method
	 *
	 * @param {string} user
	 * @returns {boolean}  
	 */
	deleteSocks5UserPass(user) {
		return this.socks5.authConf.userpass.delete(user);
	}
	/**
	 *handle socks handshake
	 *@private
	 * @param {net.Socket} socket
	 * @param {Buffer} chunk
	 */
	_handshake(socket, chunk) {
		if (!this.enabledVersion.has(chunk[0])) {
			socket.end();
			socket.emit('socks_error', `handshake: not enabled version: ${chunk[0]}`);
		}
		if (chunk[0] == SOCKS_VERSION5) {
			this._handshake5(socket, chunk);
		} else if (chunk[0] == SOCKS_VERSION4) {
			this._handshake4(socket, chunk);
		} else {
			socket.end();
			socket.emit('socks_error', `handshake: socks version not supported: ${chunk[0]}`);
		}
	}
	/**
	 *handle socks4 handshake
	 *@private
	 * @param {net.Socket} socket
	 * @param {Buffer} chunk
	 */
	_handshake4(socket, chunk) {// SOCKS4/4a
		let cmd = chunk[1],
			address,
			port,
			uid;

		port = chunk.readUInt16BE(2);

		// SOCKS4a
		if ((chunk[4] === 0 && chunk[5] === chunk[6] === 0) && (chunk[7] !== 0)) {
			var it = 0;

			uid = '';
			for (it = 0; it < 1024; it++) {
				uid += chunk[8 + it];
				if (chunk[8 + it] === 0x00)
					break;
			}
			address = '';
			if (chunk[8 + it] === 0x00) {
				for (it++; it < 2048; it++) {
					address += chunk[8 + it];
					if (chunk[8 + it] === 0x00)
						break;
				}
			}
			if (chunk[8 + it] === 0x00) {
				// DNS lookup
				DNS.lookup(address, (err, ip, family) => {
					if (err) {
						socket.end(_005B);
						socket.emit('socks_error', err);
						return;
					} else {
						socket.socksAddress = ip;
						socket.socksPort = port;
						socket.socksUid = uid;

						if (cmd == REQUEST_CMD.CONNECT) {
							socket.request = chunk;
							this.emit('tcp', socket, ip, port, _CMD_REPLY4.bind(socket));
						} else {
							socket.end(_005B);
							return;
						}
					}
				});
			} else {
				socket.end(_005B);
				return;
			}
		} else {
			// SOCKS4
			address = `${chunk[4]}.${chunk[5]}.${chunk[6]}.${chunk[7]}`;

			uid = '';
			for (it = 0; it < 1024; it++) {
				uid += chunk[8 + it];
				if (chunk[8 + it] == 0x00)
					break;
			}

			socket.socksAddress = address;
			socket.socksPort = port;
			socket.socksUid = uid;

			if (cmd == REQUEST_CMD.CONNECT) {
				socket.request = chunk;
				this.emit('tcp', socket, address, port, _CMD_REPLY4.bind(socket));
			} else {
				socket.end(_005B);
				return;
			}
		}
	}
	/**
	 *handle socks5 handshake
	 *@private
	 * @param {net.Socket} socket
	 * @param {Buffer} chunk
	 */
	_handshake5(socket, chunk) {
		let method_count = 0;

		// Number of authentication methods
		method_count = chunk[1];

		if (chunk.byteLength < method_count + 2) {
			socket.end();
			socket.emit('socks_error', 'socks5 handshake error: too short chunk');
			return;
		}

		let availableAuthMethods = [];
		// i starts on 2, since we've read chunk 0 & 1 already
		for (let i = 2; i < method_count + 2; i++) {
			if (this.socks5.authMethodsList.has(chunk[i])) {
				availableAuthMethods.push(chunk[i]);
			}
		}

		let resp = Buffer.from([
			SOCKS_VERSION5,//response version 5
			availableAuthMethods[0]//select the first auth method
		]);
		let authFunc = this.socks5.authFunc.get(resp[1]);

		if (availableAuthMethods.length === 0 || !authFunc) {//no available auth method
			resp[1] = AUTHENTICATION.NONE;
			socket.end(resp);
			socket.emit('socks_error', 'unsupported authentication method');
			return;
		}

		// auth
		socket.once('data', chunk => {
			authFunc.call(this, socket, chunk);
		});

		socket.write(resp);//socks5 auth response
	}
	/**
	 *handle socks5 user password auth request
	 *@private
	 * @param {net.Socket} socket
	 * @param {Buffer} chunk
	 */
	_socks5UserPassAuth(socket, chunk) {
		let username, password;
		// Wrong version!
		if (chunk[0] !== 1) { // MUST be 1
			socket.end(_0101);
			socket.emit('socks_error', `socks5 handleAuthRequest: wrong socks version: ${chunk[0]}`);
			return;
		}

		try {
			let na = [], pa = [], ni, pi;
			for (ni = 2; ni < (2 + chunk[1]); ni++) na.push(chunk[ni]); username = Buffer.from(na).toString('utf8');
			for (pi = ni + 1; pi < (ni + 1 + chunk[ni]); pi++) pa.push(chunk[pi]); password = Buffer.from(pa).toString('utf8');
		} catch (e) {
			socket.end(_0101);
			socket.emit('socks_error', `socks5 handleAuthRequest: username/password ${e}`);
			return;
		}

		// check user:pass
		let users = this.socks5.authConf.userpass;
		if (users && users.has(username) && users.get(username) === password) {
			socket.once('data', chunk => {
				this._socks5HandleRequest(socket, chunk);
			});
			socket.write(_0100);//success
		} else {
			setTimeout(() => {
				socket.end(_0101);//failed
				socket.emit('socks_error', `socks5 handleConnRequest: auth failed`);
			}, Math.floor(Math.random() * 90 + 3));
			return;
		}
	}
	/**
	 *handle socks5 no auth request
	 *@private
	 * @param {net.Socket} socket
	 * @param {Buffer} chunk
	 */
	_socks5NoAuth(socket, chunk) {
		this._socks5HandleRequest(socket, chunk);
	}
	/**
	 *handle socks5 command request
	 *@private
	 * @param {net.Socket} socket the socks5 request socket
	 * @param {Buffer} chunk
	 */
	_socks5HandleRequest(socket, chunk) {//the chunk is the cmd request head
		let cmd = chunk[1],//command
			address,
			port;
			// offset = 3;
		if (!this.enabledCmd.has(cmd)) {
			_CMD_REPLY5.call(socket, SOCKS_REPLY.COMMAND_NOT_SUPPORTED);//Command not supported
			return;
		}

		try {
			address = Address.read(chunk, 3);
			port = Port.read(chunk, 3);
		} catch (e) {
			socket.end();
			socket.emit('socks_error', e);
			return;
		}
		socket.targetAddress = address;
		socket.targetPort = port;

		if (cmd === REQUEST_CMD.CONNECT) {
			socket.request = chunk;
			this.emit('tcp', socket, address, port, _CMD_REPLY5.bind(socket));
		} else if (cmd === REQUEST_CMD.UDP_ASSOCIATE) {
			socket.request = chunk;
			this.emit('udp', socket, address, port, _CMD_REPLY5.bind(socket));
		} else {
			socket.end(_0507);
			return;
		}
	}
}

/**
 *base class for relaies
 *
 * @class Relay
 * @extends {events}
 */
class Relay extends events {
	socket;
	relaySocket;
	closed = false;
	get localAddress() { return this.relaySocket && this.relaySocket.address().address; }
	get localPort() { return this.relaySocket && this.relaySocket.address().port; }
	constructor(socket) {
		super();
		this.socket = socket;
	}
	close() {
		if (this.closed) return;
		this.socket && destroySocket(this.socket);
		this.relaySocket && destroySocket(this.relaySocket);

		this.closed = true;
		this.emit('close');
		setImmediate(() => {
			if (this.relaySocket) {
				this.relaySocket.removeAllListeners();
			}
			this.relaySocket = null;
			this.socket = null;
		});
	}
}

/**
 *an udp relay tool
 *
 * @class UDPRelay
 * @extends {Relay}
 */
class UDPRelay extends Relay {
	packetHandler;
	/**
	 * Creates an instance of UDPRelay.
	 * @param {net.Socket} socket the socks5 request socket
	 * @param {string} address client's outgoing address, the address must be an IP
	 * @param {number} port client's outgoing port
	 * @param {function} CMD_REPLY CMD_REPLY(reply_code)
	 */
	constructor(socket, address, port, CMD_REPLY) {
		super(socket);

		this.relaySocket;//the UDP socket used for relay udp request

		//the client want to send UDP datagrams from this address to this relay
		//if not clarified, the first incoming address will be the client's address
		this.expectClientAddress = address;
		this.expectClientPort = port;

		//the client's address and port which finally determined
		this.finalClientAddress;
		this.finalClientPort;


		let ipFamily;
		if (net.isIPv4(socket.localAddress)) { ipFamily = 4; }
		else if (net.isIPv6(socket.localAddress)) { ipFamily = 6; }
		else {
			CMD_REPLY(SOCKS_REPLY.ADDR_NOT_SUPPORTED);//Address type not supported
			return;
		}


		const relaySocket = this.relaySocket = dgram.createSocket('udp' + ipFamily);//create a relay socket to targets
		relaySocket.bind(() => {
			CMD_REPLY(SOCKS_REPLY.SUCCEEDED, ipFamily === 4 ? '0.0.0.0' : "::", this.localPort);//success
		});

		relaySocket.on('message', async (msg, info) => {//message from remote or client
			/*
				only handle datagrams from socket source and specified address
			*/
			if (this.isFromClient(info)) {//from client to remote
				let headLength;
				if (!(headLength = UDPRelay.validateSocks5UDPHead(msg))) {
					return;
				}
				//unpack the socks5 udp request
				let packet = {
					address: Address.read(msg, 3),
					port: Port.read(msg, 3),
					data: msg.slice(headLength)
				};
				this.emit('message', true, packet);
				if (this.packetHandler) await this.packetHandler(true, packet);
				this.relaySocket.send(packet.data, packet.port, packet.address, err => {
					if (err) this.emit('proxy_error', relaySocket, 'to remote', err);
				});
			} else {//from other hosts
				let packet = {
					address: info.address,
					port: info.port,
					data: msg,
				};
				if (!this.finalClientAddress) return;//ignore if client address unknown
				this.emit('message', false, packet);
				if (this.packetHandler) await this.packetHandler(false, packet);
				this.reply(info.address, info.port, packet.data, err => {
					if (err) this.emit('proxy_error', relaySocket, 'to client', err);
				});
			}
		}).once('error', e => {
			if (!CMD_REPLY(SOCKS_REPLY.HOST_UNREACHABLE))
				socket.destroy('relay error');
		});
		//when the tcp socket ends, the relay must stop
		socket.once('close', () => {
			this.close();
		});
	}
	/**
	 *reply message from remote to client
	 *
	 * @param {string} address message source
	 * @param {number} port
	 * @param {Buffer} msg	message
	 * @param {function} callback
	 */
	reply(address, port, msg, callback) {
		let head = replyHead5(address, port);
		head[0] = 0x00;
		this.relaySocket.send(Buffer.concat([head, msg]), this.finalClientPort, this.finalClientAddress, callback);
	}
	/**
	 *check if the message is from socks client
	 *
	 * @param {dgram.RemoteInfo} info 
	 * @returns {boolean}
	 */
	isFromClient(info) {
		if (!this.finalClientPort) {//update client's out going address and port by the first client message 
			if (this.expectClientPort && info.port !== this.expectClientPort) {//if client port defined but not from expectClientPort
				return false;
			}
			if (info.address !== this.socket.remoteAddress) {//not from client, ignore it
				return false;
			}
			//the first request from client
			this.finalClientAddress = info.address;
			this.finalClientPort = info.port;
			return true;
		}
		if (this.finalClientAddress !== info.address || this.finalClientPort !== info.port) return false;
		return true;
	}
	close() {
		super.close();
		this.packetHandler = null;
	}
	/**
	 *check socks5 UDP head
	 *
	 * @static
	 * @param {Buffer} buf
	 * @returns {boolean|number} return false if it's not a valid head,otherwise return the head size
	 */
	static validateSocks5UDPHead(buf) {
		if (buf[0] !== 0 || buf[1] !== 0) return false;
		let minLength = 6;//data length without addr
		if (buf[3] === 0x01) { minLength += 4; }
		else if (buf[3] === 0x03) { minLength += buf[4]; }
		else if (buf[3] === 0x04) { minLength += 16; }
		else return false;
		if (buf.byteLength < minLength) return false;
		return minLength;
	}
}



/**
 *an tcp relay tool
 *
 * @class TCPRelay
 * @extends {Relay}
 */
class TCPRelay extends Relay {
	remoteAddress;
	remotePort;
	outModifier;//a readable stream for modifying outgoing stream
	inModifier;//a readable stream for modifying incoming stream
	/**
	 * Creates an instance of TCPRelay.
	 * @param {net.Socket} socket the socks5 request socket
	 * @param {string} remoteAddress target server's address
	 * @param {number} remotePort target server's port
	 * @param {function} CMD_REPLY CMD_REPLY(reply_code)
	 * @param {string} [localAddress] bind on this address for relay socket
	 * @param {number} [localPort] bind on this port for relay socket
	 */
	constructor(socket, remoteAddress, remotePort, CMD_REPLY, localAddress, localPort) {
		super(socket);
		this.remoteAddress = remoteAddress;
		this.remotePort = remotePort;
		this.socket = socket;
		const relaySocket = this.relaySocket = net.createConnection({//the tcp socket used for relay tcp request
			port: remotePort,
			host: remoteAddress,
			localAddress: localAddress || undefined,
			localPort: localPort || undefined
		});

		relaySocket.on('connect', () => {
			CMD_REPLY(SOCKS_REPLY.SUCCEEDED, this.localAddress, this.localPort);
			let outChain = [socket, relaySocket];
			if (this.outModifier) outChain.splice(1, 0, this.outModifier);
			pipeline(outChain, (err) => {
				if (err) {
					this.emit('socks_error', err);
				}
			});
			let inChain = [relaySocket, socket];
			if (this.inModifier) inChain.splice(1, 0, this.inModifier);
			pipeline(inChain, (err) => {
				if (err) {
					this.emit('socks_error', err);
				}
			});
			this.emit('connection', socket, relaySocket);
		}).once('error', err => {
			let rep = SOCKS_REPLY.SERVER_FAILURE;
			if (err.message.indexOf('ECONNREFUSED') > -1) {
				rep = SOCKS_REPLY.CONNECTION_REFUSED;
			} else if (err.message.indexOf('EHOSTUNREACH') > -1) {
				rep = SOCKS_REPLY.HOST_UNREACHABLE;
			} else if (err.message.indexOf('ENETUNREACH') > -1) {
				rep = SOCKS_REPLY.NETWORK_UNREACHABLE;
			}
			CMD_REPLY(rep);
			this.emit('proxy_error', err, socket, relaySocket);
			this.close();
		});

		socket.once('close', () => {
			this.close();
		});
	}
	close() {
		super.close();
		this.inModifier = null;
		this.outModifier = null;
		this.packetHandler = null;
	}
}

const _0000 = Buffer.from([0, 0, 0, 0]),
	_00 = Buffer.from([0, 0]);
function replyHead5(addr, port) {
	let resp = [0x05, 0x00, 0x00];
	if (!addr || net.isIPv4(addr)) {
		resp.push(0x01, ...(addr ? (new ipAddress.Address4(addr)).toArray() : _0000));
	} else if (net.isIPv6(addr)) {
		resp.push(0x04, ...((new ipAddress.Address6(addr)).toUnsignedByteArray()));
	} else {
		addr = Buffer.from(addr);
		if (addr.byteLength > 255)
			throw (new Error('too long domain name'));
		resp.push(0x03, addr.byteLength, ...addr);
	}
	if (!port) resp.push(0, 0);//default:0
	else {
		resp.push(port >>> 8, port & 0xFF);
	}
	return Buffer.from(resp);
}

function _CMD_REPLY5(REP, addr, port) {//'this' is the socket
	if (this.CMD_REPLIED || !this.writable) return false;//prevent it from replying twice
	// creating response
	if (REP) {//something wrong
		this.end(Buffer.from([0x05, REP, 0x00]));
	} else {
		this.write(replyHead5(addr, port));
	}
	this.CMD_REPLIED = true;
	return true;
}
function _CMD_REPLY4() {//'this' is the socket
	if (this.CMD_REPLIED) return;
	// creating response
	let resp = Buffer.allocUnsafe(8);

	// write response header
	resp[0] = 0x00;
	resp[1] = 0x5a;

	// port
	resp.writeUInt16BE(this.socksPort, 2);

	// ip
	let ips = this.socksAddress.split('.');
	resp.writeUInt8(parseInt(ips[0]), 4);
	resp.writeUInt8(parseInt(ips[1]), 5);
	resp.writeUInt8(parseInt(ips[2]), 6);
	resp.writeUInt8(parseInt(ips[3]), 7);

	this.write(resp);
	this.CMD_REPLIED = true;
}

function destroySocket(socket) {
	if (socket.destroyed === false) {
		socket.destroy();
	}
}

function createSocksServer(options) {
	return new socksServer(options);
}


module.exports = {
	createSocksServer,
	socksServer,
	replyHead5,
	UDPRelay,
	TCPRelay,
	Address,
	Port,
	AUTHENTICATION,
	REQUEST_CMD,
	SOCKS_REPLY,
};

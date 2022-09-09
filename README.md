SOCKS v4/v4a/v5 server implementation with user/pass authentication node.js
=============================================================================

A simple SOCKS v5/v4/v4a server implementation and a demo proxy.

You can launch a demo proxy server easily :

```
node proxy.js [options]
```

This will create a proxy server default at `127.0.0.1:1080`.

`options`: see `node proxy.js --help`


### Install

```
npm install socks5server
```

### Embed the server in your project

You may need socks protocol knowledge to use this one in your project, or refer to the `proxy.js` demo.

```javascript
const socks5server = require('socks5server');

var server = socks5server.createServer();
//or
//var server = new socks5server.socksServer();

server
.on('tcp',(socket, address, port, CMD_REPLY)=>{
	//do something with the tcp proxy request
}).on('udp',(socket, expectClientAddress, expectClientPort, CMD_REPLY)=>{
	//do something with the udp proxy request
}).on('error', function (e) {
	console.error('SERVER ERROR: %j', e);
}).on('client_error',(socket,e)=>{
	console.error('  [client error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
}).on('socks_error',(socket,e)=>{
	console.error('  [socks error]',`${net.isIP(socket.targetAddress)?'':'('+(socket.targetAddress||"unknown")+')'} ${socket.remoteAddress||"unknown"}}:${socket.targetPort||"unknown"}`,e);
}).listen(1080, "127.0.0.1");

/*
What is 'CMD_REPLY'?
	CMD_REPLY(replyCode,addr,port)
	see https://www.ietf.org/rfc/rfc1928.txt @page5:"6 Replies" for details
*/
```
The `proxy.js` is a simple demo of the server.

### Implementations

✅ : OK
❌ : not implemented
❓ : I'm not sure is it completely finished

#### Socks4
* ❓ 					

#### Socks4a
* ❓

#### Socks5
* address
	* ipv4				✅
	* ipv6				✅
	* domain name		✅

* auth methods
	* no auth 			✅
	* userpass 			✅
	* GSSAPI 			❌
	* iana assigned		❌
	* private methods	✅ (use as a module)

* CMD
	* connect			✅
	* udp				✅ (maybe usable)
		* fragment		❌ (no plan on it)
	* bind 				❌
	
	

RFC:
* [socks5](https://www.ietf.org/rfc/rfc1928.txt)

### License

(The MIT License)

This repo was forked from https://github.com/gvangool/node-socks/
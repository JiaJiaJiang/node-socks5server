

# Socks5

RFC: https://www.ietf.org/rfc/rfc1928.txt

### 1. Procedure for TCP-based clients

client → socks server

```
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
```
* VER : X'05'
* NMETHODS : METHODS' count
* METHODS : bytes of methods

client ← socks server

```
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
```
* VER : X'05'
* METHOD : selected method

The values currently defined for METHOD are:

* X'00' NO AUTHENTICATION REQUIRED
* X'01' GSSAPI
* X'02' USERNAME/PASSWORD
* X'03' to X'7F' IANA ASSIGNED
* X'80' to X'FE' RESERVED FOR PRIVATE METHODS
* X'FF' NO ACCEPTABLE METHODS

### 2.  Requests

client → socks server

```
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```
* VER : protocol version: X'05'
* CMD
	* CONNECT : X'01'
	* BIND : X'02'
	* UDP : ASSOCIATE X'03'
* RSV : RESERVED
* ATYP : address type of following address
	* IPV4 address: X'01'
	* DOMAINNAME: X'03'
	* IPV6 address: X'04'
* DST.ADDR : desired destination address
  * ATYP = IPV4 : 4 bytes ipv4 address
  * ATYP = DOMAINNAME : The first byte of ADDR is the byte length of the domain, following the domain string
  * ATYP = IPV6 : 16 bytes ipv6 address
  * CMD = CONNECT : address for destination server
  * CMD = BIND : the client want the relay server to listen on this address
  * CMD = UDP ASSOCIATE: the client want to send UDP datagrams from this address to the relay server, if not clarified, must fill 0
* DST.PORT : desired destination port in network octet order, refer to DST.ADDR for its' meaning

### 3.  Replies

client ← socks server

```
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```

* VER : protocol version: X'05'
* REP : Reply field:
	* X'00' : succeeded
	* X'01' : general SOCKS server failure
	* X'02' : connection not allowed by ruleset
	* X'03' : Network unreachable
	* X'04' : Host unreachable
	* X'05' : Connection refused
	* X'06' : TTL expired
	* X'07' : Command not supported
	* X'08' : Address type not supported
	* X'09' : to X'FF' unassigned
* RSV : RESERVED
* ATYP : address type of following address
	* IPV4 address : X'01'
	* DOMAINNAME : X'03'
	* IPV6 address : X'04'
* BND.ADDR : server bound address
  * CMD = CONNECT : address bound on relay server for connecting to destination server
  * CMD = BIND : there are two replies for a bind request
    * 1st : address bound on relay server for incoming connections
    * 2nd : address of connected remote host

  * CMD = UDP ASSOCIATE: the relay server has bound on this address, the client must send datagrams here

* BND.PORT : server bound port in network octet order, refer to BND.ADDR for its' meaning

### 4.  Procedure for UDP-based clients

client → socks server

```
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
```
* RSV : Reserved X'0000'
* FRAG : Current fragment number
* ATYP : address type of following addresses:
	* IPV4 address : X'01'
	* DOMAINNAME : X'03'
	* IPV6 address : X'04'
* DST.ADDR : desired destination address
* DST.PORT : desired destination port
* DATA : user data
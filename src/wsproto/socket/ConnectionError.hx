package wsproto.socket;

/**
	Why a `Connection` reports an error. A close follows each.
**/
enum abstract ConnectionError(Int) from Int to Int {
	/**
		The name did not resolve, the TCP connect failed, or the TLS handshake
		did for a reason other than the server's certificate.
	**/
	var CONNECT_FAILED = 1;

	/** The connect or an opening handshake took too long, or the peer went silent for `idleTimeout`. **/
	var TIMEOUT = 2;

	/** The opening handshake failed: the server refused the upgrade, or answered it wrongly. **/
	var REFUSED = 3;

	/** More than `maxQueuedBytes` waited to be sent: the peer is not reading. **/
	var OVERFLOW = 4;

	/**
		A `wss://` server's certificate did not verify: no trusted authority
		issued it, it names another host, or it is out of date. A client
		reports it where it would otherwise report `CONNECT_FAILED`.
	**/
	var CERTIFICATE_REJECTED = 5;
}

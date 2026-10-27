package wsproto.socket;

/**
	Why a `Connection` reports an error. A close follows each.
**/
enum abstract ConnectionError(Int) from Int to Int {
	/** The name did not resolve, the TCP connect failed, or the TLS handshake did. **/
	var CONNECT_FAILED = 1;

	/** The connect or an opening handshake took too long, or the peer went silent for `idleTimeout`. **/
	var TIMEOUT = 2;

	/** The opening handshake failed: the server refused the upgrade, or answered it wrongly. **/
	var REFUSED = 3;

	/** More than `maxQueuedBytes` waited to be sent: the peer is not reading. **/
	var OVERFLOW = 4;
}

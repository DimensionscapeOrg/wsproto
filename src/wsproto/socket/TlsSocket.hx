package wsproto.socket;

#if (cpp || hl || neko)
#if hl
import sys.ssl.Context;
#end

/**
	The standard library's TLS socket, with what it gets wrong put right:
	CrossByte's `HlTlsSocket` and `NekoTlsSocket`, and the same for hxcpp.

	**Every connection a listener accepts gets a TLS configuration of its
	own** (hxcpp, HashLink, Neko). The standard library's `accept()` sets
	each one up on the listener's configuration, and the listener's `close()`
	frees it (`mbedtls_ssl_config_free`) under connections still using it:
	mbedTLS needs a configuration to outlive every connection set up on it.
	So a connection still open when its server closed failed at its next
	read, and one still in its handshake read freed memory (on Neko on
	Windows, an access violation). Here each is set up on a configuration
	built as the listener's was, which only that connection holds and its
	own `close()` frees, after its context. A configuration of a connection's
	own costs a few microseconds against its handshake's milliseconds.

	**A client's waits are ones HashLink's collector can see past.** HashLink
	stops every thread to collect, and waits for each to reach a safe point
	or to have said it is blocked. Its plain socket reads say so. Its TLS
	layer reads the network with a bare `recv` that does not (mbedTLS's
	socket callbacks in `ssl.hdll`), so a thread waiting for a slow server's
	answer would hold every other thread for as long as the server took, and
	the collector would spin a core waiting. mbedTLS takes its reads and
	writes through callbacks, and `ssl.hdll` lets those be Haxe functions
	(`ssl_set_bio`): these hand them to the plain socket natives, whose reads
	are marked blocking. The handshake reads through them too. Nothing else
	changes: blocking and non-blocking use, timeouts, the handshake's
	failures and the end of the stream behave as the standard library's do.
	Not a wait in `select` before each read, which is the obvious fix and a
	wrong one: mbedTLS holds decrypted bytes the socket no longer has. The
	callbacks are a client's; a server's accepted connections are driven
	without blocking, where a read that finds nothing returns at once and
	there is no wait to mark.
**/
@:access(sys.net.Socket)
@:access(sys.ssl.Socket)
class TlsSocket extends sys.ssl.Socket {
	#if hl
	/**
		What mbedTLS is handed for its callbacks: this socket and the two
		functions. mbedTLS keeps it as a raw pointer, in memory the collector
		does not scan, so this field is what keeps it alive.
	**/
	@:noCompletion private var __bio:hl.NativeArray<Dynamic>;

	/** The standard library's `connect`, with the callbacks installed before the handshake. **/
	public override function connect(host:sys.net.Host, port:Int):Void {
		conf = buildConfig(false);
		ssl = new Context(conf);
		var bio = new hl.NativeArray<Dynamic>(3);
		bio[0] = this;
		bio[1] = __bioRead;
		bio[2] = __bioWrite;
		__bio = bio;
		__setBio(ssl, bio);
		handshakeDone = false;
		if (hostname == null)
			hostname = host.host;
		if (hostname != null)
			ssl.setHostname(@:privateAccess hostname.toUtf8());
		if (!sys.net.Socket.socket_connect(__s, host.ip, port))
			throw new Sys.SysError("Failed to connect on " + host.toString() + ":" + port);
		if (isBlocking)
			handshake();
	}

	public override function accept():sys.ssl.Socket {
		var accepted:sys.ssl.Socket = super.accept();
		try {
			// buildConfig puts the server-name callback it makes in a field,
			// and the listener's own configuration still calls the one there
			// now.
			var listenersCallback = sniCallback;
			var own:sys.ssl.Context.Config = buildConfig(true);
			accepted.sniCallback = sniCallback;
			sniCallback = listenersCallback;

			// accept() set the connection up on the listener's configuration;
			// nothing has been sent on it yet.
			accepted.ssl.close();
			accepted.ssl = null;
			accepted.ssl = new Context(own);
			accepted.ssl.setSocket(accepted.__s);
			accepted.conf = own;

			// What the configuration points at, kept as long as it is.
			accepted.ownCert = ownCert;
			accepted.ownKey = ownKey;
			accepted.altSNIContexts = altSNIContexts;
		} catch (e:Dynamic) {
			try {
				accepted.close();
			} catch (_:Dynamic) {}
			throw e;
		}
		return accepted;
	}

	/**
		mbedTLS's read, by way of `socket_recv`, which is marked blocking. A
		would-block (a timeout run out included) answers -2, which `ssl.hdll`
		turns into MBEDTLS_ERR_SSL_WANT_READ as its own callback does; a
		failure answers -1, which mbedTLS passes up as one.
	**/
	@:noCompletion private static function __bioRead(owner:Dynamic, buffer:hl.Bytes, length:Int):Int {
		var socket:sys.net.Socket = cast owner;
		var read = __recv(socket.__s, buffer, 0, length);
		return read == -1 ? -2 : (read < 0 ? -1 : read);
	}

	/** mbedTLS's write, by way of `socket_send`, mapped the same way. **/
	@:noCompletion private static function __bioWrite(owner:Dynamic, buffer:hl.Bytes, length:Int):Int {
		var socket:sys.net.Socket = cast owner;
		var sent = __send(socket.__s, buffer, 0, length);
		return sent == -1 ? -2 : (sent < 0 ? -1 : sent);
	}

	@:hlNative("ssl", "ssl_set_bio") @:noCompletion private static function __setBio(ssl:Context, bio:Dynamic):Void {}

	// The standard library's own plain socket natives, which its socket
	// keeps to its input and output.
	@:hlNative("std", "socket_recv") @:noCompletion private static function __recv(s:hl.Abstract<"hl_socket">, bytes:hl.Bytes, pos:Int, len:Int):Int {
		return 0;
	}

	@:hlNative("std", "socket_send") @:noCompletion private static function __send(s:hl.Abstract<"hl_socket">, bytes:hl.Bytes, pos:Int, len:Int):Int {
		return 0;
	}
	#elseif neko
	public override function accept():sys.ssl.Socket {
		var accepted:sys.ssl.Socket = super.accept();
		try {
			var listenersCallback:Dynamic = sniCallback;
			var conf = buildSSLContext(true);
			accepted.sniCallback = sniCallback;
			sniCallback = listenersCallback;

			sys.ssl.Socket.ssl_close(accepted.ssl);
			accepted.ssl = null;
			accepted.ssl = sys.ssl.Socket.ssl_new(conf);
			sys.ssl.Socket.ssl_set_socket(accepted.ssl, accepted.__s);
			accepted.ctx = conf;

			accepted.ownCert = ownCert;
			accepted.ownKey = ownKey;
			accepted.altSNIContexts = altSNIContexts;
		} catch (e:Dynamic) {
			try {
				accepted.close();
			} catch (_:Dynamic) {}
			neko.Lib.rethrow(e);
		}
		return accepted;
	}
	#elseif cpp
	public override function accept():sys.ssl.Socket {
		var accepted:sys.ssl.Socket = cast super.accept();
		try {
			var listenersCallback:Dynamic = sniCallback;
			var own = buildSSLConfig(true);
			accepted.sniCallback = sniCallback;
			sniCallback = listenersCallback;

			cpp.NativeSsl.ssl_close(accepted.ssl);
			accepted.ssl = null;
			accepted.ssl = cpp.NativeSsl.ssl_new(own);
			cpp.NativeSsl.ssl_set_socket(accepted.ssl, accepted.__s);
			accepted.conf = own;

			accepted.ownCert = ownCert;
			accepted.ownKey = ownKey;
			accepted.altSNIContexts = altSNIContexts;
		} catch (e:Dynamic) {
			try {
				accepted.close();
			} catch (_:Dynamic) {}
			cpp.Lib.rethrow(e);
		}
		return accepted;
	}
	#end
}
#end

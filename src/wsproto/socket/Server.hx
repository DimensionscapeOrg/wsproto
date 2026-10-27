package wsproto.socket;

#if (cpp || hl || neko)
import wsproto.Session;

/**
	Listens for WebSocket connections on a TCP port, plain or, with a
	certificate set, TLS: each client whose opening handshake it accepts is
	handed to `onConnection`, open. Its listening socket is non-blocking, and
	what has arrived is taken as its `Loop` is polled.

	Closing a server leaves the connections it accepted open, TLS ones
	included (see `TlsSocket`).
**/
@:access(wsproto.socket.Connection)
@:access(wsproto.socket.Loop)
class Server {
	/** Called for each connection the server accepts, once its opening handshake is done. **/
	public var onConnection:Null<Connection->Void> = null;

	/**
		The subprotocols this server speaks, in its order of preference: a
		client asking for any of them is given the first of them it asked for,
		and one asking for none of them is accepted without a subprotocol.
		Null, the default, accepts the first a client asks for.
	**/
	public var protocols:Null<Array<String>> = null;

	/**
		How long a connection has, in seconds, from being accepted to its
		opening handshake being done (its TLS handshake included); past it the
		connection is closed. 10 by default.
	**/
	public var handshakeTimeout:Float = 10;

	/** The `maxMessageSize` each accepted connection starts with. **/
	public var maxMessageSize:Int = Session.DEFAULT_MAX_MESSAGE_SIZE;

	/** The `maxQueuedBytes` each accepted connection starts with; `0` for no limit. **/
	public var maxQueuedBytes:Int = 0;

	/** Why the last `listen` failed, or null. **/
	public var error(default, null):Null<String> = null;

	/** Whether the server is listening. **/
	public var listening(get, never):Bool;

	/** The port the server listens on, which `listen(0)` leaves to the system; 0 when not listening. **/
	public var localPort(get, never):Int;

	/** The loop this server is polled on. **/
	public var loop(default, null):Loop;

	private var __socket:Null<FlexSocket> = null;
	#if (cpp || hl || neko)
	private var __certificate:Null<sys.ssl.Certificate> = null;
	private var __key:Null<sys.ssl.Key> = null;
	private var __sni:Array<{match:String->Bool, certificate:sys.ssl.Certificate, key:sys.ssl.Key}> = [];
	#end

	public function new(?loop:Loop) {
		this.loop = loop != null ? loop : Loop.shared;
	}

	#if (cpp || hl || neko)
	/**
		Serves `wss://` with `certificate` and its `key`, for the listens that
		follow.
	**/
	public function setCertificate(certificate:sys.ssl.Certificate, key:sys.ssl.Key):Void {
		__certificate = certificate;
		__key = key;
	}

	/**
		Serves `certificate` and `key` to a client whose SNI name `match`
		accepts, in place of the one `setCertificate` set: several names on
		one port.
	**/
	public function addSNICertificate(match:String->Bool, certificate:sys.ssl.Certificate, key:sys.ssl.Key):Void {
		__sni.push({match: match, certificate: certificate, key: key});
	}
	#end

	/**
		Listens on `port` of `host` (every interface by default), closing what
		this server listened on before. A `port` of `0` takes any free one,
		which `localPort` then says. Answers false, with `error` saying why, if
		it cannot listen there.
	**/
	public function listen(port:Int, host:String = "0.0.0.0", backlog:Int = 64):Bool {
		close();
		error = null;

		try {
			var secure:Bool = #if (cpp || hl || neko) __certificate != null #else false #end;
			var socket:FlexSocket = new FlexSocket(secure);
			#if (cpp || hl || neko)
			if (secure) {
				// A server asks nothing of its clients' certificates
				socket.verifyCert = false;
				socket.setCertificate(__certificate, __key);
				for (entry in __sni) {
					socket.addSNICertificate(entry.match, entry.certificate, entry.key);
				}
			}
			#end
			__socket = socket;
			socket.bind(host, port);
			socket.listen(backlog);
			socket.setBlocking(false);
		} catch (e:Dynamic) {
			error = Std.string(e);
			close();
			return false;
		}

		loop.__servers.push(this);
		return true;
	}

	/** Stops listening. Connections already accepted stay open until they are closed. **/
	public function close():Void {
		if (__socket != null) {
			try {
				__socket.close();
			} catch (_:Dynamic) {}
			__socket = null;
		}
		loop.__servers.remove(this);
	}

	private inline function get_listening():Bool {
		return __socket != null;
	}

	private function get_localPort():Int {
		if (__socket != null) {
			try {
				return __socket.host().port;
			} catch (_:Dynamic) {}
		}
		return 0;
	}

	// What has arrived, taken: each a connection of its own, waiting for its
	// client's upgrade.
	private function __accept():Void {
		while (__socket != null) {
			var accepted:Null<FlexSocket> = null;
			try {
				accepted = __socket.accept();
			} catch (e:Dynamic) {
				// Nothing more waiting, or a connection that went before it
				// was taken
				break;
			}
			if (accepted == null) {
				break;
			}

			try {
				accepted.setBlocking(false);
				accepted.setFastSend(true);
			} catch (_:Dynamic) {}

			var connection:Connection = new Connection(loop);
			connection.__adopt(accepted, this);
		}
	}
}
#end

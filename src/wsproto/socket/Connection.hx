package wsproto.socket;

#if (cpp || hl || neko)
import haxe.Timer;
import haxe.ds.StringMap;
import haxe.io.Bytes;
import haxe.io.Eof;
import sys.net.Host;
import wsproto.Frame;
import wsproto.Opcode;
import wsproto.Session;

/**
	A WebSocket over a socket of Haxe's own (`FlexSocket`): a client's,
	connected to a `ws://` or `wss://` URL, or one a `Server` accepted.

	A client's connect (the name's lookup, the TCP connect and, for `wss://`,
	the TLS handshake) runs on a thread of its own where the target has
	threads, so the thread polling its `Loop` never waits on the network.
	Once connected the socket is non-blocking: each `poll` reads what has
	arrived, hands it to the session, and writes what waits to go. What is
	sent is written at once, as far as the socket takes it.

	Its callbacks run on the loop's thread, inside `poll` or inside the call
	that caused them. A connection is used once: to connect again, make
	another.
**/
@:access(wsproto.socket.Loop)
@:access(wsproto.socket.Server)
class Connection extends Session {
	/**
		Fills `length` bytes of `bytes` from `offset` from a cryptographically
		secure source, answering whether it could: what a client's masks and
		key are drawn from. Haxe's standard library has none, so a host
		supplies its platform's. Unset, `/dev/urandom` is read where there is
		one; on Windows a client cannot connect until a host sets this.
	**/
	public static var random:Null<(bytes:Bytes, offset:Int, length:Int) -> Bool> = null;

	// What one read takes at most, into a buffer every connection on the
	// thread shares: nothing is delivered between a read and the copy that
	// follows it.
	private static inline var READ_SIZE:Int = 64 * 1024;

	// What an emptied buffer keeps for the next burst.
	private static inline var KEEP:Int = 64 * 1024;

	// How many random bytes a client's masks are drawn from at a time: 8 KB,
	// two thousand frames' worth, as Node's `ws` keeps its pool.
	private static inline var MASK_POOL:Int = 8 * 1024;

	#if target.threaded
	private static var __readBuffers:sys.thread.Tls<Bytes> = new sys.thread.Tls();
	private static var __maskPools:sys.thread.Tls<MaskPool> = new sys.thread.Tls();
	#else
	private static var __readBuffer:Bytes = null;
	private static var __maskPool:MaskPool = null;
	#end

	#if (cpp || hl || neko)
	private static var __defaultCA:Null<sys.ssl.Certificate> = null;
	#end

	/** Called once the opening handshake is done, and messages can be sent and received. **/
	public var onOpen:Null<Void->Void> = null;

	/** Called for each text message. **/
	public var onText:Null<String->Void> = null;

	/** Called for each binary message, with bytes of its own. **/
	public var onBinary:Null<Bytes->Void> = null;

	/**
		Called once the connection has ended, with the code and reason of the
		closing handshake: the peer's, whichever end began it. 1006 when it
		ended without one, as a connection that dropped, failed or never
		opened does, after `onError` says why.
	**/
	public var onClose:Null<(code:Int, reason:String) -> Void> = null;

	/** Called when something went wrong, saying what. `onClose` follows. **/
	public var onError:Null<(error:ConnectionError, message:String) -> Void> = null;

	/**
		Whether a `wss://` server's certificate is checked against the
		trusted authorities (`certificateAuthority`, or the system's) and the
		URL's host name. On by default. Set before `connect`.

		Neko's TLS checks a certificate whatever this says: there, trust a
		server's own certificate through `certificateAuthority` instead.
	**/
	public var verifyCertificates:Bool = true;

	#if (cpp || hl || neko)
	/** The authority a `wss://` server's certificate is checked against, or null for the system's. **/
	public var certificateAuthority:Null<sys.ssl.Certificate> = null;
	#end

	/**
		The most that may wait to be sent, in bytes; `0`, the default, for no
		limit. A write that leaves more waiting reports `ConnectionError.OVERFLOW` and closes
		with 1011, throwing away what was waiting: a peer that stops reading
		cannot be waited on forever.
	**/
	public var maxQueuedBytes:Int = 0;

	/** The address of the other end, once connected, or null. **/
	public var remoteAddress(default, null):Null<String> = null;

	/** The port of the other end, once connected, or 0. **/
	public var remotePort(default, null):Int = 0;

	/** Whether the opening handshake is done, and no close begun. **/
	public var connected(get, never):Bool;

	/** What has been sent that the socket has not taken yet, framing included. **/
	public var bytesPending(get, never):Int;

	/** The loop this connection is polled on. **/
	public var loop(default, null):Loop;

	private var __socket:Null<FlexSocket> = null;
	private var __server:Null<Server> = null;
	private var __handshaking:Bool = false;
	#if target.threaded
	// A client's connect in flight: the socket, connected, or why not.
	private var __dial:Null<sys.thread.Deque<Dynamic>> = null;
	#end

	private var __input:Null<Bytes> = null;
	private var __inputStart:Int = 0;
	private var __inputEnd:Int = 0;
	private var __output:Null<Bytes> = null;
	private var __outputStart:Int = 0;
	private var __outputEnd:Int = 0;
	private var __messageBytes:Null<Bytes> = null;

	private var __openDeadline:Float = 0;
	private var __closeDeadline:Float = 0;
	private var __beatPeriod:Float = 0;
	private var __nextBeat:Float = 0;

	// A close waiting for what is queued to go: what it will report.
	private var __closeWhenDrained:Bool = false;
	private var __drainedCode:Int = 1000;
	private var __drainedReason:Null<String> = null;

	// The owner is told of a close once, and of a failed connect's reason
	// once.
	private var __closeReported:Bool = false;
	private var __errorReported:Bool = false;

	public function new(?loop:Loop) {
		super();
		this.loop = loop != null ? loop : Loop.shared;
	}

	/**
		Connects to `url`, a `ws://` or `wss://` URL, asking for one of
		`protocols` as the subprotocol where there are any. `onOpen` is called
		once the server has accepted, or `onError` and then `onClose` if it does
		not within `timeout` seconds (`0` waits as long as it takes).
	**/
	public function connect(url:String, ?protocols:Array<String>, timeout:Float = 10):Void {
		if (readyState != Session.CONNECTING || __isClient != null) {
			throw "A Connection connects once";
		}

		try {
			__client(url, protocols, null);
		} catch (e:Dynamic) {
			__isClient = true;
			__onError("Could not connect to " + url + ": " + e, ConnectionError.CONNECT_FAILED);
			__close(1006);
			return;
		}

		if (__secure && !FlexSocket.tlsSupported) {
			__onError("Could not connect to " + url + ": TLS is not available on this target", ConnectionError.CONNECT_FAILED);
			__close(1006);
			return;
		}

		__openDeadline = timeout > 0 ? Timer.stamp() + timeout : 0;
		loop.__connections.push(this);

		var host:String = __host;
		var port:Int = __port;
		var secure:Bool = __secure;
		var verify:Bool = verifyCertificates;
		var authority:Dynamic = #if (cpp || hl || neko) certificateAuthority #else null #end;

		#if target.threaded
		var result = new sys.thread.Deque<Dynamic>();
		__dial = result;
		sys.thread.Thread.create(function() {
			result.add(__open(host, port, secure, verify, authority));
		});
		#else
		__dialed(__open(host, port, secure, verify, authority));
		#end
	}

	/**
		Sends `length` bytes of `data` from `offset` as one binary message,
		without waiting. Answers false if the connection is not open.
	**/
	public function send(data:Bytes, offset:Int, length:Int):Bool {
		if (readyState != Session.OPEN) {
			return false;
		}
		sendRange(data, offset, length);
		return true;
	}

	/** Sends `text` as one text message, without waiting. Answers false if the connection is not open. **/
	public function sendText(text:String):Bool {
		if (readyState != Session.OPEN) {
			return false;
		}
		sendString(text);
		return true;
	}

	private inline function get_connected():Bool {
		return readyState == Session.OPEN;
	}

	private inline function get_bytesPending():Int {
		return __outputEnd - __outputStart;
	}

	// A connection its server accepted, waiting for its client's upgrade:
	// and for a secure server, first its TLS handshake.
	private function __adopt(socket:FlexSocket, server:Server):Void {
		__isClient = false;
		__server = server;
		__socket = socket;
		__handshaking = socket.isSecure;
		maxMessageSize = server.maxMessageSize;
		maxQueuedBytes = server.maxQueuedBytes;
		__noteEndpoints();
		__openDeadline = Timer.stamp() + (server.handshakeTimeout > 0 ? server.handshakeTimeout : Session.DEFAULT_CLOSE_TIMEOUT);
		loop.__connections.push(this);
	}

	// A client's connect, on its own thread: the socket, connected (and for
	// wss://, its TLS handshake done), or why it is not.
	private static function __open(host:String, port:Int, secure:Bool, verify:Bool, authority:Dynamic):Dynamic {
		try {
			var address:Host = new Host(host);
			var socket:FlexSocket = new FlexSocket(secure);

			#if (cpp || hl || neko)
			if (secure) {
				socket.verifyCert = verify;
				// The name the certificate is matched against, and the SNI name
				socket.setHostname(host);
				if (verify) {
					var ca:Null<sys.ssl.Certificate> = authority;
					if (ca == null) {
						if (__defaultCA == null) {
							__defaultCA = sys.ssl.Certificate.loadDefaults();
						}
						ca = __defaultCA;
					}
					if (ca != null) {
						socket.setCA(ca);
					}
				}
			}
			#end

			socket.connectHost(address, port);
			return socket;
		} catch (e:Dynamic) {
			return Std.string(e);
		}
	}

	// The connect is over: the upgrade request goes, or the client fails.
	private function __dialed(result:Dynamic):Void {
		#if target.threaded
		__dial = null;
		#end

		if (Std.isOfType(result, String)) {
			__onError("Failed to connect to server: " + result, ConnectionError.CONNECT_FAILED);
			__close(1006);
			return;
		}

		var connected:FlexSocket = cast result;
		if (readyState == Session.CLOSED) {
			// Closed while it connected
			try {
				connected.close();
			} catch (_:Dynamic) {}
			return;
		}

		__socket = connected;
		try {
			connected.setBlocking(false);
			connected.setFastSend(true);
		} catch (_:Dynamic) {}
		__noteEndpoints();
		__doHandshake();
	}

	private function __noteEndpoints():Void {
		try {
			var peer = __socket.peer();
			remoteAddress = peer.host.toString();
			remotePort = peer.port;
		} catch (_:Dynamic) {}
	}

	private function __poll(now:Float):Void {
		#if target.threaded
		if (__dial != null) {
			var result:Dynamic = __dial.pop(false);
			if (result != null) {
				__dialed(result);
			}
		}
		#end

		if (readyState == Session.CLOSED) {
			return;
		}

		if (__socket != null) {
			if (__handshaking && !__stepTLS()) {
				// Still in it, or failed and closed
				if (readyState == Session.CLOSED) {
					return;
				}
			} else {
				__read();
				if (readyState == Session.CLOSED) {
					return;
				}
				__flush();
				if (readyState == Session.CLOSED) {
					return;
				}
			}
		}

		if (__openDeadline > 0 && readyState == Session.CONNECTING && now >= __openDeadline) {
			__openDeadline = 0;
			__onError(__isClient == false ? "The client did not finish its WebSocket upgrade in time" : "Failed to connect to server: " + url
				+ " did not open in time",
				ConnectionError.TIMEOUT);
			__close(1006);
			return;
		}

		if (__closeDeadline > 0 && now >= __closeDeadline) {
			__closeDeadline = 0;
			// Either the peer never answered this side's close (1006), or it
			// did, and what was queued could not drain in time
			if (__closeWhenDrained) {
				__close(__drainedCode, __drainedReason);
			} else {
				__close(1006, "the peer did not answer the close");
			}
			return;
		}

		if (__beatPeriod > 0 && now >= __nextBeat) {
			__nextBeat = now + __beatPeriod;
			__onHeartbeat();
		}
	}

	// A secure server's accepted connection's TLS handshake, stepped without
	// waiting: true once it is done.
	private function __stepTLS():Bool {
		#if (cpp || hl || neko)
		try {
			__socket.handshake();
		} catch (e:Dynamic) {
			if (FlexSocket.isBlocked(e)) {
				return false;
			}
			__handshaking = false;
			__onError("TLS handshake failed: " + e, ConnectionError.CONNECT_FAILED);
			__close(1015);
			return false;
		}
		#end
		__handshaking = false;
		return true;
	}

	// Reads everything the socket has, then hands it to the session.
	private function __read():Void {
		var buffer:Bytes = __sharedReadBuffer();
		var total:Int = 0;
		var ended:Bool = false;
		var secure:Bool = __socket.isSecure;

		while (true) {
			var count:Int = 0;
			try {
				count = __socket.input.readBytes(buffer, 0, READ_SIZE);
			} catch (e:Eof) {
				ended = true;
				break;
			} catch (e:Dynamic) {
				if (!FlexSocket.isBlocked(e)) {
					ended = true;
				}
				break;
			}

			if (count <= 0) {
				ended = true;
				break;
			}

			__append(buffer, count);
			total += count;

			// A read shorter than the buffer drained the socket, so nothing
			// asks it again only to hear it would block. A TLS read takes one
			// record at most, so it reads on until the socket says so.
			if (count < READ_SIZE && !secure) {
				break;
			}
		}

		// What came before a disconnect is delivered before it
		if (total > 0) {
			__heard = true;
			__process();
		}

		if (ended && readyState != Session.CLOSED) {
			__close(1006);
		}
	}

	// Writes what waits, as far as the socket takes it.
	private function __flush():Void {
		if (__socket == null) {
			return;
		}

		while (__outputStart < __outputEnd) {
			var count:Int = 0;
			try {
				count = __socket.output.writeBytes(__output, __outputStart, __outputEnd - __outputStart);
			} catch (e:Dynamic) {
				if (FlexSocket.isBlocked(e)) {
					break;
				}
				__close(1006);
				return;
			}

			if (count <= 0) {
				break;
			}
			__outputStart += count;
			bytesSent += count;
		}

		if (__outputStart >= __outputEnd) {
			__outputStart = __outputEnd = 0;
			if (__output != null && __output.length > KEEP) {
				__output = null;
			}

			// A close that was waiting for this to go, and an answer to a
			// ping that was waiting for the last
			if (__closeWhenDrained) {
				__close(__drainedCode, __drainedReason);
				return;
			}
			if (__pongOwed) {
				__settlePong();
			}
		}
	}

	private function __append(bytes:Bytes, length:Int):Void {
		if (__input == null) {
			__input = Bytes.alloc(length > KEEP ? length : KEEP);
		}

		if (__inputEnd + length > __input.length) {
			var held:Int = __inputEnd - __inputStart;
			if (__inputStart > 0 && held + length <= __input.length) {
				__input.blit(0, __input, __inputStart, held);
			} else {
				var grown:Bytes = Bytes.alloc((held + length) + ((held + length) >> 1));
				grown.blit(0, __input, __inputStart, held);
				__input = grown;
			}
			__inputStart = 0;
			__inputEnd = held;
		}

		__input.blit(__inputEnd, bytes, 0, length);
		__inputEnd += length;
	}

	// What has arrived, handed to the session: the opening handshake's head,
	// then frame after frame.
	private function __process():Void {
		if (__refusing) {
			// An upgrade refused: what the peer sends after it is not read
			__inputStart = __inputEnd = 0;
			return;
		}

		if (readyState == Session.OPEN || readyState == Session.CLOSING) {
			while (__inputEnd > __inputStart) {
				var at:Int = __frameHeader(__input, __inputStart, __inputEnd);
				if (at <= 0) {
					break;
				}

				// Past the frame before it is taken: a callback may send, or
				// close
				__inputStart = at + __frameLength;

				if (__frameOpcode >= Opcode.CLOSE) {
					var opcode:Int = __frameOpcode;
					__controlFrame(__input, at);
					if (opcode == Opcode.CLOSE || readyState == Session.CLOSED) {
						return;
					}
					continue;
				}

				if (!__dataFrame(__input, at)) {
					return;
				}
			}

			if (__input != null && __inputStart >= __inputEnd) {
				__inputStart = __inputEnd = 0;
				if (__input.length > KEEP) {
					__input = null;
				}
			}
		} else if (readyState == Session.CONNECTING) {
			var headerLength:Int = __findHead(__input, __inputStart, __inputEnd);
			if (headerLength <= 0) {
				return;
			}

			var start:Int = __inputStart;
			__inputStart += headerLength;
			__takeHead(__input, start, headerLength);

			if (readyState == Session.OPEN && __inputEnd > __inputStart) {
				__process();
			}
		}
	}

	private function __queue(length:Int):Int {
		if (__output == null) {
			__output = Bytes.alloc(length > KEEP ? length : KEEP);
		}

		if (__outputEnd + length > __output.length) {
			var held:Int = __outputEnd - __outputStart;
			if (__outputStart > 0 && held + length <= __output.length) {
				__output.blit(0, __output, __outputStart, held);
			} else {
				var grown:Bytes = Bytes.alloc((held + length) + ((held + length) >> 1));
				grown.blit(0, __output, __outputStart, held);
				__output = grown;
			}
			__outputStart = 0;
			__outputEnd = held;
		}

		var at:Int = __outputEnd;
		__outputEnd += length;
		return at;
	}

	// The output limit, after a write: true when it closed the connection.
	private function __overflowed():Bool {
		var waiting:Int = __outputEnd - __outputStart;
		if (maxQueuedBytes <= 0 || waiting <= maxQueuedBytes) {
			return false;
		}
		// Thrown away rather than sent: the limit exists to reclaim it
		__outputStart = __outputEnd = 0;
		__onError('$waiting bytes waited to be sent, past maxQueuedBytes ($maxQueuedBytes); the peer is not reading', ConnectionError.OVERFLOW);
		__close(1011, "output buffer limit exceeded");
		return true;
	}

	private static function __sharedReadBuffer():Bytes {
		#if target.threaded
		var buffer:Null<Bytes> = __readBuffers.value;
		if (buffer == null) {
			buffer = Bytes.alloc(READ_SIZE);
			__readBuffers.value = buffer;
		}
		return buffer;
		#else
		if (__readBuffer == null) {
			__readBuffer = Bytes.alloc(READ_SIZE);
		}
		return __readBuffer;
		#end
	}

	private static function __masks():MaskPool {
		#if target.threaded
		var pool:Null<MaskPool> = __maskPools.value;
		if (pool == null) {
			pool = new MaskPool();
			__maskPools.value = pool;
		}
		return pool;
		#else
		if (__maskPool == null) {
			__maskPool = new MaskPool();
		}
		return __maskPool;
		#end
	}

	private static function __fill(bytes:Bytes, offset:Int, length:Int):Void {
		var source = random;
		if (source != null) {
			if (!source(bytes, offset, length)) {
				throw "The secure random source failed";
			}
			return;
		}
		#if sys
		if (Sys.systemName() != "Windows" && sys.FileSystem.exists("/dev/urandom")) {
			var file = sys.io.File.read("/dev/urandom", true);
			try {
				file.readFullBytes(bytes, offset, length);
			} catch (e:Dynamic) {
				file.close();
				throw e;
			}
			file.close();
			return;
		}
		#end
		throw "No secure random source for a WebSocket client: set Connection.random";
	}

	// Session's hooks

	override private function get_ownPending():Int {
		return __outputEnd - __outputStart;
	}

	override private function __randomBytes(count:Int):Bytes {
		var bytes:Bytes = Bytes.alloc(count);
		__fill(bytes, 0, count);
		return bytes;
	}

	override private function __writeBytes(bytes:Bytes):Void {
		var at:Int = __queue(bytes.length);
		__output.blit(at, bytes, 0, bytes.length);
		if (!__overflowed()) {
			__flush();
		}
	}

	override private function __sendFrameOf(payload:Bytes, offset:Int, length:Int, opcode:Int, isFinal:Bool, compressed:Bool):Void {
		if (readyState == Session.CLOSED) {
			return;
		}

		// The frame made in place in what waits to go: its header, and its
		// payload, which on a client goes under four bytes of the mask pool,
		// used for this frame alone, masked once it is copied in
		var masked:Bool = __isClient != false;
		var at:Int = __queue(Frame.headerLength(length, masked) + length);
		at = Frame.writeHeader(__output, at, (isFinal ? Frame.FIN : 0) | (compressed ? Frame.RSV1 : 0) | opcode, length, masked);

		if (masked) {
			var pool:MaskPool = __masks();
			var keyAt:Int = pool.take();
			__output.blit(at, pool.bytes, keyAt, 4);
			Frame.maskInto(__output, at + 4, payload, offset, length, pool.bytes, keyAt);
		} else if (length > 0) {
			__output.blit(at, payload, offset, length);
		}

		if (!__overflowed()) {
			__flush();
		}
	}

	override private function __hasTransport():Bool {
		#if target.threaded
		if (__dial != null) {
			return true;
		}
		#end
		return __socket != null;
	}

	override private function __close(code:Int, ?reason:String):Void {
		var connecting:Bool = readyState == Session.CONNECTING;
		readyState = Session.CLOSED;

		if (__closeReported) {
			return;
		}

		// A client that never opened has failed to connect, whatever ended
		// it, and says so as a browser's WebSocket does: why, then 1006. Its
		// owner's own close is no failure
		if (connecting && __isClient == true && !__ownerClosing) {
			if (!__errorReported) {
				__onError("The connection ended before it opened" + (reason != null ? ": " + reason : ""), ConnectionError.CONNECT_FAILED);
			}
			code = 1006;
			reason = null;
		}

		__closeWhenDrained = false;
		__openDeadline = 0;
		__closeDeadline = 0;
		__beatPeriod = 0;
		__handshaking = false;

		#if target.threaded
		if (__dial != null) {
			loop.__abandoned.push(__dial);
			__dial = null;
		}
		#end

		if (__socket != null) {
			// What was waiting goes first, as far as the socket takes it now:
			// the close frame a failure or an abort sends just before this
			var pending:Int = __outputEnd - __outputStart;
			if (pending > 0) {
				try {
					__socket.output.writeBytes(__output, __outputStart, pending);
				} catch (_:Dynamic) {}
			}

			try {
				__socket.close();
			} catch (_:Dynamic) {}
			__socket = null;
		}

		loop.__connections.remove(this);
		__input = null;
		__output = null;
		__messageBytes = null;
		__inputStart = __inputEnd = __outputStart = __outputEnd = 0;
		__closeReported = true;

		var listener = onClose;
		if (listener != null) {
			listener(code, reason != null ? reason : "");
		}
	}

	override private function __finishClose(code:Int, ?reason:String):Void {
		if (__outputEnd <= __outputStart) {
			__close(code, reason);
			return;
		}

		__closeWhenDrained = true;
		__drainedCode = code;
		__drainedReason = reason;
		__armCloseDeadline();
	}

	override private function __armCloseDeadline():Void {
		if (__closeDeadline > 0) {
			return;
		}
		__closeDeadline = Timer.stamp() + (closeTimeout > 0 ? closeTimeout : Session.DEFAULT_CLOSE_TIMEOUT);
	}

	override private function __onError(errorMessage:String, errorId:Int = 0):Void {
		__errorReported = true;
		var listener = onError;
		if (listener != null) {
			// What the session reports itself is its opening handshake's
			listener(errorId == 0 ? ConnectionError.REFUSED : errorId, errorMessage);
		}
	}

	override private function __silenced():Void {
		__onError('Nothing was heard from the peer for ${Math.round(__silentFor)} s; the connection was closed as idle', ConnectionError.TIMEOUT);
		__close(1006, "idle timeout");
	}

	override private function __opened():Void {
		__openDeadline = 0;

		var server:Null<Server> = __server;
		if (server != null) {
			var listener = server.onConnection;
			if (listener != null) {
				listener(this);
			}
		} else {
			var listener = onOpen;
			if (listener != null) {
				listener();
			}
		}
	}

	override private function __disarmOpenDeadline():Void {
		__openDeadline = 0;
	}

	override private function __admit(requestLine:String, headers:StringMap<String>, ?head:String):Bool {
		var server:Null<Server> = __server;
		var supported:Null<Array<String>> = server != null ? server.protocols : null;
		if (supported == null) {
			return super.__admit(requestLine, headers, head);
		}

		// The first the client asked for that the server speaks, or none
		var offered:Null<String> = headers.get("sec-websocket-protocol");
		protocol = null;
		if (offered != null) {
			for (name in offered.split(",")) {
				name = StringTools.trim(name);
				if (supported.indexOf(name) >= 0) {
					protocol = name;
					break;
				}
			}
		}
		return true;
	}

	override private function __dropInput():Void {
		__inputStart = __inputEnd = 0;
	}

	override private function __messageBegin():Void {
		if (__messageBytes == null) {
			__messageBytes = Bytes.alloc(256);
		}
	}

	override private function __roomForMessage(held:Int, length:Int, last:Bool):Bytes {
		if (length > __messageBytes.length) {
			var grown:Bytes = Bytes.alloc(last ? length : length + (length >> 1));
			grown.blit(0, __messageBytes, 0, held);
			__messageBytes = grown;
		}
		return __messageBytes;
	}

	override private function __message():Bytes {
		return __messageBytes;
	}

	override private function __dispatchMessage():Void {
		var opcode:Int = __incomingOpcode;
		var size:Int = __incomingMessageSize;
		var open:Bool = readyState == Session.OPEN;

		// The next message's first frame starts afresh, whatever a callback
		// does with this one
		super.__dispatchMessage();

		// Nothing new is delivered once closing: a peer's data after its
		// close frame, or after ours, belongs to no one
		if (!open) {
			return;
		}

		var message:Bytes = __messageBytes;
		if (message.length > KEEP) {
			__messageBytes = null;
		}

		if (opcode == Opcode.TEXT) {
			var listener = onText;
			if (listener != null) {
				listener(message.getString(0, size));
			}
		} else {
			var listener = onBinary;
			if (listener != null) {
				listener(message.sub(0, size));
			}
		}
	}

	override private function __scheduleHeartbeat(period:Float):Void {
		__beatPeriod = period;
		__nextBeat = Timer.stamp() + period;
	}

	override private function __stopHeartbeat():Void {
		__beatPeriod = 0;
	}

	override private function __trimWhenQuiet(heard:Bool, sent:Bool):Void {
		// What a quiet connection holds goes, until it is busy again
		if (!heard) {
			if (__inputEnd <= __inputStart) {
				__input = null;
				__inputStart = __inputEnd = 0;
			}
			if (__incomingOpcode == -1) {
				__messageBytes = null;
			}
		}
		if (!sent && __outputEnd <= __outputStart) {
			__output = null;
			__outputStart = __outputEnd = 0;
		}

		super.__trimWhenQuiet(heard, sent);
	}
}

/**
	Random bytes for a client's frame masks, four taken for each frame and
	none taken twice, refilled from the secure source when used up: CrossByte's
	`MaskPool`. One a thread.
**/
@:access(wsproto.socket.Connection)
private class MaskPool {
	public var bytes(default, null):Null<Bytes> = null;

	private var __at:Int = 0;

	public function new() {}

	/** Where the next four bytes start, in `bytes`. **/
	public inline function take():Int {
		if (bytes == null || __at + 4 > bytes.length) {
			__refill();
		}
		var at:Int = __at;
		__at = at + 4;
		return at;
	}

	private function __refill():Void {
		if (bytes == null) {
			bytes = Bytes.alloc(Connection.MASK_POOL);
		}
		Connection.__fill(bytes, 0, bytes.length);
		__at = 0;
	}
}
#end

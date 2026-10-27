package wsproto;

import haxe.crypto.Base64;
import haxe.ds.StringMap;
import haxe.io.Bytes;

/**
	One WebSocket session, either end, without its connection: the opening
	handshake, framing and closing handshake of RFC 6455, and RFC 7692's
	compression agreed in the handshake, over bytes a host moves.

	A host extends this with its transport. It hands over what arrives, a
	frame or a head at a time, from wherever it read it to (`__findHead`
	and `__takeHead` while connecting, `__frameHeader`, `__controlFrame`
	and `__dataFrame` once open), and the session calls back for what only
	the host can do, through the methods documented as hooks below: send
	bytes, keep a message's bytes, deliver it, close the connection, arm a
	timer. A hook left alone does nothing, or what is said at it.

	Nothing here allocates per frame or per message: a frame is read where
	it lies and a message assembled in storage the host gives, and what is
	sent is framed into the host's own output.

	A session is used from one thread at a time, its host's.
**/
class Session {
	public static inline var CLOSED:Int = 3;
	public static inline var CLOSING:Int = 2;
	public static inline var CONNECTING:Int = 0;
	public static inline var OPEN:Int = 1;

	/** The default `maxMessageSize`: 1 MiB. **/
	public static inline var DEFAULT_MAX_MESSAGE_SIZE:Int = 1024 * 1024;

	/**
		The largest frame this side sends: a message longer is sent in frames
		of this many bytes. What this side takes in one is bounded by
		`maxMessageSize` alone.
	**/
	public static inline var FRAGMENT_SIZE:Int = 64 * 1024;

	/** The ping interval a session starts with, in seconds; see `pingInterval`. **/
	public static inline var DEFAULT_PING_INTERVAL:Float = 30.0;

	/** The idle timeout a session starts with, in seconds; see `idleTimeout`. **/
	public static inline var DEFAULT_IDLE_TIMEOUT:Float = 60.0;

	/** The closing handshake's deadline a session starts with, in seconds; see `closeTimeout`. **/
	public static inline var DEFAULT_CLOSE_TIMEOUT:Float = 5.0;

	/** The default `maxHeaderSize`: 16 KiB, as Node's. **/
	public static inline var DEFAULT_MAX_HEADER_SIZE:Int = 16 * 1024;

	/** The extension named in the handshake, as RFC 7692 names it. **/
	public static inline var PERMESSAGE_DEFLATE:String = PerMessageDeflate.NAME;

	/**
		The smallest message sent compressed when `compressionThreshold` is
		not set: below about a kilobyte the DEFLATE framing costs about as much
		as it saves, and the time is spent for nothing.
	**/
	public static inline var DEFAULT_COMPRESSION_THRESHOLD:Int = 1024;

	private static inline var WS:String = "ws";
	private static inline var WSS:String = "wss";
	private static inline var CRLF:String = "\r\n";
	private static inline var GET:String = "GET";
	private static inline var HTTP:String = "HTTP";

	/**
		The largest message this session takes, in bytes: a frame whose
		length would take the message it belongs to past this is refused on
		its header, before anything waits for its payload, and the session
		fails with 1009 (Message Too Big); so is a compressed message that
		would inflate past it. `0` or less takes messages of any size.

		1 MiB by default. A frame may be as long as the message: a browser
		sends one of 100 KB as a single frame, and Node's `ws` sends every
		message as one, so a frame is held only to what is left of the
		message, on its header.
	**/
	public var maxMessageSize:Int = DEFAULT_MAX_MESSAGE_SIZE;

	/**
		How long a closing handshake is given, in seconds: for the peer to
		answer a close frame, and for what was queued before it to drain.
		Past it the connection is closed regardless, as 1006 when the peer
		never answered. Five by default. The host keeps the time; see
		`__armCloseDeadline`.
	**/
	public var closeTimeout:Float = DEFAULT_CLOSE_TIMEOUT;

	/**
		The largest opening handshake this session reads, in bytes: a server
		session's upgrade request, or a client's answer to its own, from the
		request or status line to the blank line that ends the head. Past it
		a server answers `431 Request Header Fields Too Large` and closes; a
		client gives up, with an error saying so, and closes with 1006. `0`
		or less reads one of any size.

		16 KiB by default, as Node's HTTP parser (and so the `ws` library
		on it) has it: a browser's upgrade request is a few hundred bytes
		with its cookies, a few kilobytes at most, and a server holds what
		has arrived of each one still upgrading.
	**/
	public var maxHeaderSize:Int = DEFAULT_MAX_HEADER_SIZE;

	/**
		Whether to ask for, or agree to, permessage-deflate (RFC 7692): each
		message compressed on its own. Off unless set, before the handshake.
		Whether a session uses it is its peer's say too; see `compressed`.
	**/
	public var perMessageDeflate:Bool = false;

	/**
		Messages shorter than this many bytes are sent as they are, even where
		compression was agreed.
	**/
	public var compressionThreshold:Int = DEFAULT_COMPRESSION_THRESHOLD;

	/**
		The extensions this session agreed to in its handshake, as the
		`Sec-WebSocket-Extensions` it answered or was answered with; empty for
		none.
	**/
	public var extensions(default, null):String = "";

	/** Whether this session agreed to permessage-deflate. **/
	public var compressed(get, never):Bool;

	/**
		The subprotocol the session speaks: on a server, the one accepted; on a
		client, the one the server chose from those asked for. `null` for none.
	**/
	public var protocol(default, null):String;

	public var readyState(default, null):Int = CONNECTING;

	/** A client's URL, as it was given; `null` on a server. **/
	public var url(default, null):String;

	/**
		What the network has taken from this session since it opened, as the
		host counts it.
	**/
	public var bytesSent(default, null):Float = 0;

	/**
		What this session's host holds that is not yet handed to the system:
		with `bytesSent`, every byte sent, each once. The host's; 0 unless it
		says.
	**/
	public var ownPending(get, never):Int;

	/**
		How often, in seconds, a session that has heard nothing from its peer
		pings it; zero for never. A peer answers a ping with a pong, so a quiet
		connection whose peer is still there stays in use, which also keeps a
		proxy between the two from closing it as idle.
	**/
	public var pingInterval(get, set):Float;

	/**
		How long, in seconds, a session hears nothing (no message, no pong, no
		frame at all) before it takes the peer for gone and closes with 1006;
		zero for never. Checked every `pingInterval`, or every quarter of this
		with pings off.
	**/
	public var idleTimeout(get, set):Float;

	// Agreed in the handshake; and whether the message arriving is compressed.
	private var __deflate:Bool = false;
	private var __incomingCompressed:Bool = false;

	// Whether what this side sends may go compressed: only where its peer
	// agreed to inflate each message on its own; see __takeDeflateAnswer.
	private var __deflateSend:Bool = false;

	// The message arriving: its opcode (-1 between messages) and what it has
	// come to.
	private var __incomingOpcode:Int = -1;
	private var __incomingMessageSize:Int = 0;

	// Which end: true for a client, false for a server; set by __client, or
	// by a host before anything reads it.
	private var __isClient:Null<Bool>;

	// A client's: the key its upgrade carries, what its URL names, and what
	// it asks for.
	private var __key:String;
	private var __scheme:String;
	private var __host:String;
	private var __port:Int;
	private var __path:String;
	private var __secure:Bool;
	private var __origin:String;
	// A client's, as asked for; null for none, and on every server session.
	private var __protocols:Null<Array<String>> = null;

	// Whether the owner is the one closing the session: what a client's
	// connect that ends before it opens reports turns on it.
	private var __ownerClosing:Bool = false;

	// How far the search for the end of the opening handshake's head has
	// got, so each arrival is searched once rather than the whole head again
	// with every byte that arrives.
	private var __headScanned:Int = 0;

	// Whether this server session refused its upgrade: what still arrives
	// from the peer is dropped until the answer has gone.
	private var __refusing:Bool = false;

	// The frame __frameHeader read last: its opcode, FIN, reserved bits,
	// payload length, and where its mask key lies (-1 for none).
	private var __frameOpcode:Int = 0;
	private var __frameFinal:Bool = false;
	private var __frameReserved:Int = 0;
	private var __frameLength:Int = 0;
	private var __frameKeyAt:Int = -1;

	// A control frame's payload, read in; see __controlFrame. Made with the
	// first, and let go of when the session goes quiet.
	private var __control:Null<Bytes> = null;

	// Cleared by a pong; kept for tests that set it.
	private var __hasTimeoutPotential:Bool = false;

	// What the network will have taken, counted as `bytesSent` counts, once
	// the last answer to a ping has gone; 0 before the first. And the
	// payload of the newest ping since, still owed an answer, with whether
	// one is.
	private var __pongUntil:Float = 0;
	private var __pongOwed:Bool = false;
	private var __pongNext:Null<Bytes> = null;
	private var __pongNextLength:Int = 0;

	// The heartbeat: whether anything has arrived since the last beat (the
	// host sets it as bytes arrive), for how long in a row nothing has, and
	// what had been sent or queued at the last beat.
	private var __pingInterval:Float = -1;
	private var __idleTimeout:Float = DEFAULT_IDLE_TIMEOUT;
	private var __heard:Bool = false;
	private var __silentFor:Float = 0;
	private var __sentAtBeat:Float = 0;

	public function new() {}

	private inline function get_compressed():Bool {
		return __deflate;
	}

	private function get_ownPending():Int {
		return 0;
	}

	// A client's start.

	/**
		Makes this a client session for `url` (`ws://` or `wss://`), asking for
		`protocols`, from `origin`: the key its upgrade carries is drawn from
		`__randomBytes`. Throws a `String` for a URL that is not one.
	**/
	private function __client(url:String, ?protocols:Array<String>, ?origin:String):Void {
		__isClient = true;
		// A client's alone: a server answers the key it is sent, and needs
		// no randomness of its own.
		__key = Base64.encode(__randomBytes(16));
		this.url = url;

		// The host is a bracketed IPv6 literal or a run without colons: a
		// URL writes an IPv6 address in brackets, and without the first
		// alternative its colons read as the start of a port.
		var regex:EReg = ~/^(\w+):\/\/(\[[^\]\/]*\]|[^:\/]+)(?::(\d+))?\/?(.*)$/;

		if (regex.match(url)) {
			// the URI is well-formed
			__scheme = regex.matched(1).toLowerCase();
			__host = regex.matched(2);
			if (StringTools.startsWith(__host, "[")) {
				// Dialled, looked up and named to TLS without the brackets.
				__host = __host.substring(1, __host.length - 1);
			}
			if (__scheme == WSS) {
				__secure = true;
			} else if (__scheme == WS) {
				__secure = false;
			} else {
				throw "Uri does not include a valid Web Socket Scheme";
			}

			// Bounded as it is read; see Decimal.
			var portText:Null<String> = regex.matched(3);
			if (portText == null || portText.length == 0) {
				__port = __secure ? 443 : 80;
			} else {
				var port:Int = Decimal.parse(portText, 65535);
				if (port < 0) {
					throw "Uri port is out of range: " + portText;
				}
				__port = port;
			}
			var path:Null<String> = regex.matched(4);
			__path = path == "" ? "/" : "/" + path;
		} else {
			throw "Uri is not a well-formed";
		}

		if (protocols != null) {
			__protocols = protocols.copy();
		}

		if (origin == null) {
			origin = "http://127.0.0.1/";
		}
		__origin = origin;
	}

	/** A client's upgrade request, sent once its transport is up. **/
	private function __doHandshake():Void {
		// Without context takeover either way, which a server must agree to
		// or refuse: this side inflates each message on its own.
		__writeBytes(Handshake.clientRequest(__path, __host, __port, __key, __origin, __protocols, perMessageDeflate ? PerMessageDeflate.OFFER : null));
	}

	// The opening handshake, arriving.

	/**
		Looks for the end of the opening handshake's head in `input`, which
		has arrived from `start` to `end`. Answers the head's length, its
		blank line included, once it has all arrived; 0 while it has not; and
		-1 when it ran past `maxHeaderSize`, which the session has answered
		(see `__headTooLarge`).

		Held where it arrived, as bytes, until the head is whole, rather than
		moved into a string copied whole with every arrival. Searched from
		where the last arrival's search stopped, less the three bytes a CRLFCRLF
		split between arrivals can start in; the host keeps what it has read
		where it lies until the head is taken.
	**/
	private function __findHead(input:Bytes, start:Int, end:Int):Int {
		var from:Int = __headScanned - 3;
		if (from < start) {
			from = start;
		}
		var endIndex:Int = Handshake.findHeaderEnd(input, from, end);
		var limit:Int = maxHeaderSize;
		if (endIndex < 0) {
			__headScanned = end;
			if (limit > 0 && end - start > limit) {
				__headTooLarge(limit);
				return -1;
			}
			return 0;
		}
		__headScanned = 0;

		// The whole head has arrived. A head that did end is held to the same
		// limit as one still arriving, as an HTTP server holds its requests.
		var headerLength:Int = endIndex - start + 4;
		if (limit > 0 && headerLength > limit) {
			__headTooLarge(limit);
			return -1;
		}
		return headerLength;
	}

	/**
		Takes the head `__findHead` found at `start` of `input`, as what this
		session's role expects: a request on a server, an answer on a client.
		The session is OPEN after it if the handshake succeeded; what follows
		the head in `input` is then the peer's first frames, which the host
		hands over next.
	**/
	private function __takeHead(input:Bytes, start:Int, headerLength:Int):Void {
		var headerData:String = input.getString(start, headerLength);
		var lines:Array<String> = headerData.split(CRLF);
		var headers:StringMap<String>;

		if (__isClient == false) {
			if (lines[0].indexOf(GET) != 0) {
				__refuseUpgrade(400, null);
				return;
			}
			headers = Handshake.parseHeaderLines(lines);
			__acceptUpgrade(lines[0], headers, headerData);
			return;
		}

		if (lines[0].indexOf(HTTP) != 0) {
			__onError("The server's answer to the WebSocket upgrade was not HTTP: " + lines[0]);
			__close(1006);
			return;
		}
		headers = Handshake.parseHeaderLines(lines);
		if (lines[0].indexOf("101") > -1) {
			headers.set("status", "101");
		} else {
			// A failed connect, as a browser reports one: the answer said,
			// then 1006 (see __close), not 1002 with no error, as if an open
			// session had broken the protocol.
			__onError("The server refused the WebSocket upgrade: " + lines[0]);
			__close(1006);
			return;
		}

		if (__validateResponseHandshake(headers)) {
			// handshake complete, is ready
			__disarmOpenDeadline();
			readyState = OPEN;
			__startHeartbeat();
			__opened();
		} else {
			__onError("The server's answer to the WebSocket upgrade was not valid: " + lines[0]);
			__close(1006);
		}
	}

	/**
		The opening handshake's head has run past `maxHeaderSize`: a server
		session answers 431, as an HTTP server answers a request whose head
		is too large, and a client gives up on a server that will not stop.
	**/
	private function __headTooLarge(limit:Int):Void {
		__headScanned = 0;
		if (__isClient == false) {
			__refuseUpgrade(431, null);
			return;
		}
		__dropInput();
		__onError('The server\'s answer to the WebSocket upgrade ran past $limit bytes without ending (maxHeaderSize).');
		__close(1006);
	}

	/**
		A server session's answer to the upgrade request it has just received:
		the `101`, or a refusal. Says whether the session opened.

		The host's `__admit` decides on a request that is a valid upgrade,
		and the subprotocol it accepts is echoed: a browser offering a
		subprotocol that hears none back fails the connection.
	**/
	private function __acceptUpgrade(requestLine:String, headers:StringMap<String>, ?head:String):Bool {
		if (!Handshake.isValidRequest(headers)) {
			// Answered rather than dropped, so a client learns why. A version
			// this side does not speak is answered with the one it does, as
			// RFC 6455 4.4 asks.
			var version:Null<String> = headers.get("sec-websocket-version");
			__refuseUpgrade(400, version != null && version != Handshake.VERSION ? ["Sec-WebSocket-Version: 13"] : null);
			return false;
		}

		if (!__admit(requestLine, headers, head)) {
			return false;
		}

		// Compression, where this server allows it and the client offered it
		// on terms this side can keep. Refused, the session goes on without.
		if (perMessageDeflate) {
			var offered:Null<String> = headers.get("sec-websocket-extensions");
			if (offered != null) {
				__acceptDeflateOffer(offered);
			}
		}

		__writeBytes(Handshake.serverResponse(headers.get("sec-websocket-key"), protocol, __deflate ? extensions : null));

		readyState = OPEN;
		__startHeartbeat();
		__opened();
		__upgraded();
		return readyState == OPEN;
	}

	/**
		Answers an upgrade with a refusal, and closes once the answer has gone.
	**/
	private function __refuseUpgrade(status:Int, extraHeaders:Null<Array<String>>):Void {
		// What the request left, and whatever follows it, is not read on.
		__refusing = true;
		__dropInput();
		__writeBytes(Handshake.refusal(status, extraHeaders));
		readyState = CLOSING;
		__finishClose(1002, "upgrade refused with " + status);
	}

	private function __validateResponseHandshake(headers:StringMap<String>):Bool {
		// Check if the response status code is 101
		if (headers.get("status") != "101") {
			return false;
		}

		// Check if the "Upgrade" header is set to "websocket"
		var upgrade:String = headers.get("upgrade");
		if (upgrade == null || upgrade.toLowerCase() != "websocket") {
			return false;
		}

		// Check if the "Connection" header is set to "Upgrade"
		var connection:String = headers.get("connection");
		if (connection == null || connection.toLowerCase().indexOf("upgrade") == -1) {
			return false;
		}

		// Check if the "Sec-WebSocket-Accept" header matches the expected value
		if (headers.get("sec-websocket-accept") != Handshake.accept(__key)) {
			return false;
		}

		// A subprotocol the server chose must be one this side asked for (RFC
		// 6455 4.1); choosing none is allowed.
		var chosen:Null<String> = headers.get("sec-websocket-protocol");
		if (chosen != null && chosen != "") {
			if (__protocols == null || __protocols.indexOf(chosen) < 0) {
				return false;
			}
			protocol = chosen;
		}

		// Compression, where this side asked for it and the server agreed,
		// on terms this side can keep, or the connection fails (RFC 7692 5).
		var agreed:Null<String> = headers.get("sec-websocket-extensions");
		if (perMessageDeflate && agreed != null && StringTools.trim(agreed) != "") {
			if (!__takeDeflateAnswer(agreed)) {
				return false;
			}
		}

		return true;
	}

	/** A server's answer to this client's offer; see `PerMessageDeflate.answerTaken`. **/
	private function __takeDeflateAnswer(value:String):Bool {
		var taken:Int = PerMessageDeflate.answerTaken(value);
		if (taken == PerMessageDeflate.REFUSED) {
			return false;
		}

		__deflate = true;
		__deflateSend = taken == PerMessageDeflate.BOTH;
		extensions = StringTools.trim(value);
		return true;
	}

	/** A client's offers, answered; see `PerMessageDeflate.answer`. **/
	private function __acceptDeflateOffer(value:String):Bool {
		var answer:Null<String> = PerMessageDeflate.answer(value);
		if (answer == null) {
			return false;
		}

		extensions = answer;
		__deflate = true;
		// The answer says server_no_context_takeover: the client inflates
		// each message on its own.
		__deflateSend = true;
		return true;
	}

	// Frames, arriving.

	/**
		Reads the header of the frame at `start` of `input`, which has arrived
		up to `end`, and checks it. Answers where its payload starts once the
		whole frame has arrived (the frame is then in `__frameOpcode`,
		`__frameFinal`, `__frameReserved`, `__frameLength` and
		`__frameKeyAt`), 0 while it has not, and -1 when it broke the
		protocol, and the session failed.

		A frame is refused on its header alone, before any wait for a payload
		that may never arrive, so ten bytes claiming a two-gigabyte length
		cannot put the session into a wait for a frame it would refuse once it
		completed. A data frame is held to what is left of its message under
		`maxMessageSize`, so nothing waits for more than a message.
	**/
	private function __frameHeader(input:Bytes, start:Int, end:Int):Int {
		if (end - start < 2) {
			return 0;
		}

		var firstByte:Int = input.get(start);
		var isFinal:Bool = (firstByte & Frame.FIN) != 0;
		var opCode:Int = firstByte & 0x0F;

		var secondByte:Int = input.get(start + 1);
		var isMasked:Bool = (secondByte & Frame.MASK) != 0;
		var payloadLength:Int = secondByte & 0x7F;
		var at:Int = start + 2;

		// RSV1 marks a compressed message: only where permessage-deflate
		// was agreed, and only on the first frame of a data message,
		// never a continuation, never a control frame (RFC 7692 6).
		var reserved:Int = firstByte & (Frame.RSV1 | Frame.RSV2 | Frame.RSV3);
		if (reserved != 0
			&& (reserved != Frame.RSV1 || !__deflate || opCode == Opcode.CONTINUATION || opCode >= Opcode.CLOSE)) {
			__fail(1002);
			return -1;
		}

		// A server MUST reject unmasked frames from a client (RFC 6455 5.1).
		if (__isClient == false && !isMasked) {
			__fail(1002);
			return -1;
		}

		if (payloadLength == 126) {
			if (end - at < 2) {
				return 0;
			}
			payloadLength = (input.get(at) << 8) | input.get(at + 1);
			at += 2;
		} else if (payloadLength == 127) {
			if (end - at < 8) {
				return 0;
			}
			// A length past 2^31 - 1 is past any message this side takes.
			if ((input.get(at) | input.get(at + 1) | input.get(at + 2) | input.get(at + 3)) != 0 || input.get(at + 4) >= 0x80) {
				__fail(1009);
				return -1;
			}
			payloadLength = (input.get(at + 4) << 24) | (input.get(at + 5) << 16) | (input.get(at + 6) << 8) | input.get(at + 7);
			at += 8;
		}

		var isControl:Bool = opCode >= Opcode.CLOSE;
		if (isControl && (!isFinal || payloadLength > 125)) {
			__fail(1002);
			return -1;
		}
		if (!isControl) {
			var limit:Int = maxMessageSize;
			// A continuation adds to the message under way; with none under
			// way it is refused in __dataFrame, as a protocol error.
			var before:Int = opCode == Opcode.CONTINUATION && __incomingOpcode != -1 ? __incomingMessageSize : 0;
			if (limit > 0 && payloadLength > limit - before) {
				__fail(1009);
				return -1;
			}
		}

		if (opCode != Opcode.CONTINUATION
			&& opCode != Opcode.TEXT
			&& opCode != Opcode.BINARY
			&& opCode != Opcode.CLOSE
			&& opCode != Opcode.PING
			&& opCode != Opcode.PONG) {
			__fail(1002);
			return -1;
		}

		// In Int, and against what is left after the mask: a sum would wrap
		// for a length within four bytes of 2^31.
		var maskBytes:Int = isMasked ? 4 : 0;
		if (payloadLength > end - at - maskBytes) {
			return 0;
		}

		__frameOpcode = opCode;
		__frameFinal = isFinal;
		__frameReserved = reserved;
		__frameLength = payloadLength;
		// The key is used where it lies in the input rather than copied into
		// a buffer made for it, one per frame.
		__frameKeyAt = isMasked ? at : -1;
		return at + maskBytes;
	}

	/**
		Takes the control frame `__frameHeader` read, its payload at `at` in
		`input`: a ping answered, a pong heard, a close answered or taken as
		the answer to this side's own.

		At most 125 bytes, into one buffer the session keeps for them:
		nothing hands a control frame's payload out (a ping's is copied into
		its answer, a close's read in the call), so a peer sending a stream
		of pings makes no buffer for each.
	**/
	private function __controlFrame(input:Bytes, at:Int):Void {
		var control:Null<Bytes> = __control;
		if (control == null) {
			control = __control = Bytes.alloc(125);
		}
		var length:Int = __frameLength;
		if (length > 0) {
			control.blit(0, input, at, length);
			if (__frameKeyAt >= 0) {
				Frame.mask(control, length, input, __frameKeyAt, 0);
			}
		}
		__handleControlFrame(__frameOpcode, control, length);
	}

	private function __handleControlFrame(opcode:Int, payload:Bytes, length:Int):Void {
		switch (opcode) {
			case Opcode.PING:
				// A ping is answered in any state but closed: a peer waiting on
				// the close handshake may still be checking this side is there.
				__answerPing(payload, length);
			case Opcode.PONG:
				__hasTimeoutPotential = false;
			case Opcode.CLOSE:
				var code:Int = 1000;
				var reason:String = null;
				if (length == 1) {
					// A close frame carrying a body must contain at least a 2-byte code.
					__fail(1002);
					return;
				}
				if (length >= 2) {
					code = (payload.get(0) << 8) | payload.get(1);
					if (!CloseCode.isValid(code)) {
						__fail(1002);
						return;
					}
					if (length > 2) {
						if (!Utf8.isValid(payload, 2, length - 2)) {
							__fail(1007);
							return;
						}
						reason = payload.getString(2, length - 2);
					}
				}

				if (readyState == OPEN) {
					// The peer began it. Its code goes back, as RFC 6455 5.5.1
					// asks, and the connection closes once that has gone.
					__sendFrameOf(payload, 0, length, Opcode.CLOSE, true, false);
					readyState = CLOSING;
				}

				// Either the peer began it or this is its answer to ours. What
				// is reported is the peer's code and reason either way (what
				// it said about why), which is what a browser reports too.
				__finishClose(code, reason);
		}
	}

	/**
		Takes the data frame `__frameHeader` read, its payload at `at` in
		`input`, into the message it belongs to: read straight into the
		message's storage (see `__messageBegin` and `__roomForMessage`),
		unmasked where it lands, with no buffer made for each frame. A
		message's last frame has it inflated where it was compressed, checked
		as UTF-8 where it is text, and delivered (`__dispatchMessage`).

		Answers false when the session failed or closed, and nothing more is
		to be read.
	**/
	private function __dataFrame(input:Bytes, at:Int):Bool {
		var opCode:Int = __frameOpcode;
		if (opCode == Opcode.CONTINUATION) {
			if (__incomingOpcode == -1) {
				__fail(1002);
				return false;
			}
		} else {
			if (__incomingOpcode != -1) {
				__fail(1002);
				return false;
			}
			__incomingOpcode = opCode;
			// Start of a new message: reset the cumulative size counter.
			__incomingMessageSize = 0;
			__incomingCompressed = __frameReserved != 0;
			__messageBegin();
		}

		// What the message has come to, held to maxMessageSize on each
		// frame's header.
		var payloadLength:Int = __frameLength;
		var into:Int = __incomingMessageSize;
		__incomingMessageSize = into + payloadLength;

		if (payloadLength > 0) {
			var message:Bytes = __roomForMessage(into, into + payloadLength, __frameFinal);
			message.blit(into, input, at, payloadLength);
			if (__frameKeyAt >= 0) {
				Frame.mask(message, payloadLength, input, __frameKeyAt, into);
			}
		}

		if (__frameFinal) {
			// Inflated whole, once the last frame is in: the size cap on the
			// header is on what arrived, and the inflation has a cap of its own
			// on what it may become.
			if (__incomingCompressed && !__inflateIncoming()) {
				return false;
			}

			// Validate completed TEXT messages as UTF-8.
			if (__incomingOpcode == Opcode.TEXT && !Utf8.isValid(__message(), 0, __incomingMessageSize)) {
				__fail(1007);
				return false;
			}
			__dispatchMessage();
			if (readyState == CLOSED) {
				return false;
			}
		}
		return true;
	}

	// Answering pings.

	/**
		Answers a ping, or, while the answer to an earlier one has not yet
		gone, keeps this one's payload to answer once it has, in place of
		any kept before it.

		RFC 6455 5.5.3 allows exactly this: a pong for only the most recent
		ping, where pings arrive faster than they can be answered. So the
		answers a session owes are never more than two (one going, one
		kept, at most 125 bytes) however many pings arrive; and the last
		ping is always the one last answered. libwebsockets answers so.

		A pong for every ping would let a peer sending pings and reading
		nothing pile them up without end, each written as a frame and offered
		to a full socket. WebSocket need not answer every ping, so nothing
		here has to be closed or tuned.
	**/
	private function __answerPing(payload:Bytes, length:Int):Void {
		if (__pongUnsent()) {
			var next:Null<Bytes> = __pongNext;
			if (next == null) {
				next = __pongNext = Bytes.alloc(125);
			}
			if (length > 0) {
				next.blit(0, payload, 0, length);
			}
			__pongNextLength = length;
			__pongOwed = true;
			return;
		}
		__pongOwed = false;
		__sendPong(payload, length);
	}

	/** Sends a pong answering a ping, and notes where it ends. **/
	private function __sendPong(payload:Bytes, length:Int):Void {
		__sendFrameOf(payload, 0, length, Opcode.PONG, true, false);
		__pongUntil = bytesSent + ownPending;
	}

	/**
		Whether the last answer to a ping is still waiting to go: what the
		network has taken has not reached its end. A host whose network
		queues beyond `ownPending` says so here.
	**/
	private function __pongUnsent():Bool {
		if (__pongUntil <= 0 || !__hasTransport()) {
			return false;
		}
		return bytesSent < __pongUntil;
	}

	/**
		The answer kept for the newest ping goes, once the one before it has:
		for the host to call when the network takes more.
	**/
	private function __settlePong():Void {
		if (__pongOwed && readyState == OPEN && !__pongUnsent()) {
			__pongOwed = false;
			__sendPong(__pongNext, __pongNextLength);
		}
	}

	// Closing.

	/**
		Closes the session the way RFC 6455 has it closed: a close frame with
		`code` and `reason`, then the peer's answer, then the connection.

		The code and reason are in the frame, and the connection stays up for
		the peer's answer: it closes once that arrives and everything queued
		has gone, or after `closeTimeout` regardless. What is reported is the
		code and reason the peer answered with, or 1006 when it never did.

		A session not yet open has nobody to say anything to, and closes at
		once.
	**/
	public function close(?code:Int, ?reason:String):Void {
		if (!__hasTransport() || readyState == CLOSED || readyState == CLOSING) {
			return;
		}

		__ownerClosing = true;
		var closing:Int = code == null ? 1000 : code;

		if (readyState != OPEN) {
			__close(closing, reason);
			return;
		}

		__sendCloseFrame(closing, reason);
		readyState = CLOSING;
		__armCloseDeadline();
	}

	/**
		Closes the connection now, telling the peer with a close frame if the
		host's transport will take it straight away: for a close that cannot
		wait on the peer. What is reported is `code`.
	**/
	public function abort(code:Int = 1000, ?reason:String):Void {
		if (!__hasTransport() || readyState == CLOSED) {
			return;
		}

		__ownerClosing = true;
		if (readyState == OPEN) {
			__sendCloseFrame(code, reason);
		}

		__close(code, reason);
	}

	/**
		Fails the connection, as RFC 6455 7.1.7 has it done: a close frame
		saying why, where the session is open, and then the connection closed
		at once. For a peer breaking the protocol, which is owed no handshake.
	**/
	private function __fail(code:Int):Void {
		if (readyState == OPEN) {
			__sendCloseFrame(code, null);
		}
		__close(code);
	}

	/**
		A close frame carrying `code` and, after it, as much of `reason` as
		fits: a control frame holds 125 bytes, two of them the code, and a
		reason cut there is cut between characters rather than through one.
	**/
	private function __sendCloseFrame(code:Int, ?reason:String):Void {
		var text:Null<Bytes> = reason != null && reason.length > 0 ? Bytes.ofString(reason) : null;
		var length:Int = 0;
		if (text != null) {
			length = text.length;
			if (length > 123) {
				length = 123;
				// Back off any continuation bytes to the start of a character.
				while (length > 0 && (text.get(length) & 0xC0) == 0x80) {
					length--;
				}
			}
		}

		var payload:Bytes = Bytes.alloc(2 + length);
		payload.set(0, (code >> 8) & 0xFF);
		payload.set(1, code & 0xFF);
		if (length > 0) {
			payload.blit(2, text, 0, length);
		}
		__sendFrameOf(payload, 0, payload.length, Opcode.CLOSE, true, false);
	}

	// Sending.

	/** Sends `data` as one binary message. **/
	public function sendBytes(data:Bytes):Void {
		sendRange(data, 0, data.length);
	}

	/**
		Sends `length` bytes of `data` from `offset` as one binary message,
		framed from where they lie, with no copy of their own.
	**/
	public function sendRange(data:Bytes, offset:Int, length:Int):Void {
		__prepareMessage(data, offset, length, Opcode.BINARY);
	}

	/** Sends `data` as one text message, as well-formed UTF-8. **/
	public function sendString(data:String):Void {
		var bytes:Bytes = Utf8.bytesOf(data);
		__prepareMessage(bytes, 0, bytes.length, Opcode.TEXT);
	}

	/**
		`length` bytes of `data` from `offset` sent as one message: compressed
		where that was agreed and the message is worth it, and sent as it is
		when compressing did not make it smaller, which RFC 7692 leaves to
		each message. `data` is not changed.
	**/
	private function __prepareMessage(data:Bytes, offset:Int, length:Int, opcode:Int):Void {
		if (readyState != OPEN) {
			throw "WebSocket is not open";
		}

		if (__deflateSend && length >= compressionThreshold) {
			var deflated:Null<Bytes> = __compress(data, offset, length);
			if (deflated != null && deflated.length < length) {
				__sendPayload(deflated, 0, deflated.length, opcode, true);
				return;
			}
		}

		__sendPayload(data, offset, length, opcode, false);
	}

	/**
		Sends `total` bytes of `data` from `offset` as one message, framed as
		this side frames: in frames of at most `FRAGMENT_SIZE`, RSV1 on the
		first where it is `compressed`. Each frame is made from where its
		bytes lie, so a message longer than a frame is not copied a fragment
		at a time into a buffer of its own first.
	**/
	private function __sendPayload(data:Bytes, offset:Int, total:Int, opcode:Int, compressed:Bool):Void {
		if (total <= FRAGMENT_SIZE) {
			__sendFrameOf(data, offset, total, opcode, true, compressed);
			return;
		}

		// A message longer than a frame, in frames: the first carries the
		// opcode, and RSV1 when compressed; the rest are continuations.
		var at:Int = 0;
		while (at < total) {
			var length:Int = total - at > FRAGMENT_SIZE ? FRAGMENT_SIZE : total - at;
			var first:Bool = at == 0;
			__sendFrameOf(data, offset + at, length, first ? opcode : Opcode.CONTINUATION, at + length >= total, compressed && first);
			at += length;
		}
	}

	private inline function __sendFrame(payload:Bytes, opcode:Int, isFinal:Bool, compressed:Bool = false):Void {
		__sendFrameOf(payload, 0, payload.length, opcode, isFinal, compressed);
	}

	/**
		Pings the peer, which answers with a pong carrying the same payload
		(at most 125 bytes, and none by default). A pong counts as hearing from
		the peer, as anything it sends does.
	**/
	public function ping(?payload:Bytes):Void {
		if (readyState != OPEN) {
			return;
		}
		__sendFrame(__controlPayload(payload), Opcode.PING, true);
	}

	/**
		Sends a pong nobody asked for: a heartbeat in one direction, which RFC
		6455 5.5.3 allows and the peer does not answer.
	**/
	public function pong(?payload:Bytes):Void {
		if (readyState != OPEN) {
			return;
		}
		__pong(__controlPayload(payload));
	}

	private function __pong(?payload:Bytes):Void {
		if (payload == null) {
			payload = __noPayload();
		}
		__sendFrame(payload, Opcode.PONG, true);
	}

	// A control frame with nothing in it, as every heartbeat's ping is: one
	// empty buffer, never written to, shared by every ping. Only read
	// (framed from, by offset), so any thread may share it.
	private static var __empty:Null<Bytes> = null;

	private static inline function __noPayload():Bytes {
		var empty:Null<Bytes> = __empty;
		if (empty == null) {
			empty = __empty = Bytes.alloc(0);
		}
		return empty;
	}

	private function __controlPayload(payload:Null<Bytes>):Bytes {
		if (payload == null) {
			return __noPayload();
		}
		if (payload.length > 125) {
			__controlPayloadTooLong(payload.length);
		}
		return payload;
	}

	// Heartbeat.

	private function get_pingInterval():Float {
		return __pingInterval < 0 ? DEFAULT_PING_INTERVAL : __pingInterval;
	}

	private function set_pingInterval(value:Float):Float {
		__pingInterval = value < 0 ? 0 : value;
		if (readyState == OPEN) {
			__startHeartbeat();
		}
		return __pingInterval;
	}

	private function get_idleTimeout():Float {
		return __idleTimeout;
	}

	private function set_idleTimeout(value:Float):Float {
		__idleTimeout = value < 0 ? 0 : value;
		if (readyState == OPEN) {
			__startHeartbeat();
		}
		return __idleTimeout;
	}

	private function __heartbeatPeriod():Float {
		var interval:Float = pingInterval;
		if (interval > 0) {
			return interval;
		}
		return __idleTimeout > 0 ? __idleTimeout / 4 : 0;
	}

	/**
		Starts the heartbeat, for an open session: both ends run one.

		Without it a peer that vanished without a FIN would be held forever,
		with everything sent to it piling up.
	**/
	private function __startHeartbeat():Void {
		__stopHeartbeat();

		var period:Float = __heartbeatPeriod();
		if (period <= 0 || readyState != OPEN) {
			return;
		}

		__heard = false;
		__silentFor = 0;
		__sentAtBeat = bytesSent + ownPending;
		__scheduleHeartbeat(period);
	}

	/**
		Once a period, for the host's timer to call: a peer heard from since
		the last is there; one silent for `idleTimeout` is gone; one silent for
		less is pinged, and a peer still there answers.
	**/
	private function __onHeartbeat():Void {
		if (readyState != OPEN) {
			__stopHeartbeat();
			return;
		}

		var period:Float = __heartbeatPeriod();
		// Quiet since the last beat, either way: what it held for messages
		// goes, before the ping below asks the peer whether it is there.
		var sent:Bool = bytesSent + ownPending != __sentAtBeat;
		__trimWhenQuiet(__heard, sent);
		if (__heard) {
			__silentFor = 0;
		} else {
			__silentFor += period;
		}
		__heard = false;

		if (__idleTimeout > 0 && __silentFor >= __idleTimeout) {
			__silenced();
			return;
		}

		if (pingInterval > 0 && __silentFor > 0) {
			ping();
		}
		__sentAtBeat = bytesSent + ownPending;
	}

	// Hooks: what only the host can do.

	/** `count` bytes from a cryptographically secure source, for a client's key. **/
	private function __randomBytes(count:Int):Bytes {
		throw "This host gives no random bytes for a client's key";
	}

	/** Sends `bytes` as they are: a head of the opening handshake. **/
	private function __writeBytes(bytes:Bytes):Void {}

	/**
		Sends `length` bytes of `payload` from `offset` as one frame: framed
		(`Frame.writeHeader`) and, on a client, masked with a fresh key
		(`Frame.maskInto`), into the host's output. The host copies what it
		needs before it returns.
	**/
	private function __sendFrameOf(payload:Bytes, offset:Int, length:Int, opcode:Int, isFinal:Bool, compressed:Bool):Void {}

	/**
		Closes the connection, the session over: `readyState` set to CLOSED,
		timers stopped, and the owner told `code` and `reason` (a client that
		never opened and that its owner did not close reports 1006 after an
		error saying why). Called again, it reports nothing.
	**/
	private function __close(code:Int, ?reason:String):Void {
		readyState = CLOSED;
	}

	/**
		The last step of a closing handshake: close once everything the host
		holds to send has gone, reporting `code` and `reason`, or when the
		closing deadline passes with something still stuck.
	**/
	private function __finishClose(code:Int, ?reason:String):Void {
		__close(code, reason);
	}

	/**
		Arms the closing handshake's deadline, `closeTimeout`: past it the
		connection is closed, reporting 1006 if the peer never answered.
	**/
	private function __armCloseDeadline():Void {}

	/** Whether the session still has a connection to send on. **/
	private function __hasTransport():Bool {
		return true;
	}

	/** Something went wrong, said in `errorMessage`; a close follows. **/
	private function __onError(errorMessage:String, errorId:Int = 0):Void {}

	/** The session has opened. **/
	private function __opened():Void {}

	/** A client's connect has opened: its deadline is done with. **/
	private function __disarmOpenDeadline():Void {}

	/**
		A server's say over an upgrade request that is valid: answers true to
		accept it, with `protocol` set to the subprotocol accepted, or refuses
		it with `__refuseUpgrade` and answers false. Accepted with the first
		subprotocol the client offered unless the host says otherwise.
	**/
	private function __admit(requestLine:String, headers:StringMap<String>, ?head:String):Bool {
		var offered:Null<String> = headers.get("sec-websocket-protocol");
		if (offered != null) {
			var first:String = StringTools.trim(offered.split(",")[0]);
			protocol = first == "" ? null : first;
		}
		return true;
	}

	/** A server session has sent its `101` and opened. **/
	private function __upgraded():Void {}

	/** What has arrived and not been handed over is dropped: a refused upgrade's. **/
	private function __dropInput():Void {}

	/** A message's first frame has arrived: its storage, empty, for `__roomForMessage`. **/
	private function __messageBegin():Void {}

	/**
		Storage for the message arriving, `length` bytes in all, `last` when
		its last frame is in: the `held` bytes the message has so far kept
		where they are, from 0, and the rest of the `length` written by the
		session next.
	**/
	private function __roomForMessage(held:Int, length:Int, last:Bool):Bytes {
		throw "This host keeps no messages";
	}

	/** The message arriving, as `__roomForMessage` keeps it, `__incomingMessageSize` bytes from 0. **/
	private function __message():Bytes {
		throw "This host keeps no messages";
	}

	/**
		The whole message arrived compressed: inflated in place of what
		arrived, `__message()` and `__incomingMessageSize` then the inflated
		message's. What arrived is a raw DEFLATE stream the sender ended with
		a flush, less the four octets it took off (RFC 7692 7.2.2), which are
		put back before inflating. Past `maxMessageSize` once inflated, the
		session fails with 1009; data that is not DEFLATE fails it with 1007.
		Answers false when it failed.
	**/
	private function __inflateIncoming():Bool {
		__fail(1007);
		return false;
	}

	/**
		`length` bytes of `data` from `offset`, compressed as a message of its
		own (RFC 7692 7.2.1): raw DEFLATE ended by a flush, less the four
		octets of the empty block that end it, exactly as long as it is; or
		null to send it as it is.
	**/
	private function __compress(data:Bytes, offset:Int, length:Int):Null<Bytes> {
		return null;
	}

	/**
		The message arriving is whole and checked: delivered from `__message()`,
		`__incomingMessageSize` bytes of opcode `__incomingOpcode`, unless the
		session is no longer OPEN, and the next message readied for, with
		`__incomingOpcode` back to -1 and `__incomingMessageSize` to 0.
	**/
	private function __dispatchMessage():Void {
		__incomingOpcode = -1;
		__incomingMessageSize = 0;
	}

	/** A ping or pong of `length` bytes was asked for, past the 125 a control frame carries. **/
	private function __controlPayloadTooLong(length:Int):Void {
		throw "A ping or pong carries at most 125 bytes, and this one is " + length + ".";
	}

	/** Runs `__onHeartbeat` every `period` seconds, until `__stopHeartbeat`. **/
	private function __scheduleHeartbeat(period:Float):Void {}

	private function __stopHeartbeat():Void {}

	/**
		A beat of the heartbeat has passed with nothing `heard`, or nothing
		`sent`: storage kept for what arrives or goes can be let go of. The
		session's own goes here; a host's override says what else.
	**/
	private function __trimWhenQuiet(heard:Bool, sent:Bool):Void {
		if (!heard) {
			__control = null;
		}
		if (!sent && ownPending == 0 && !__pongOwed) {
			__pongNext = null;
		}
	}

	/** Nothing has been heard for `idleTimeout`: the peer is taken for gone. **/
	private function __silenced():Void {
		__onError('Nothing was heard from the peer for ${Math.round(__silentFor)} s; the session was closed as idle.');
		__close(1006, "idle timeout");
	}
}

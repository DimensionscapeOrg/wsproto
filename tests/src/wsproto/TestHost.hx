package wsproto;

import haxe.ds.StringMap;
import haxe.io.Bytes;

/**
	A session whose transport is memory: what it sends collects in `sent`,
	and `receive` hands it bytes as a socket's reads would, frames and heads
	split wherever they fall. `Pair` wires two of them together.

	What a host must do, done as plainly as it can be: a test of the session,
	not of a transport.
**/
@:access(wsproto.Session)
class TestHost extends Session {
	public var sent:Array<Bytes> = [];
	public var messages:Array<{opcode:Int, data:Bytes}> = [];
	public var errors:Array<String> = [];
	public var opened:Int = 0;
	public var closes:Int = 0;
	public var closeCode:Int = -1;
	public var closeReason:Null<String> = null;

	/** The most `__roomForMessage` was ever asked for. **/
	public var largestRoom:Int = 0;

	/** What a host holding unsent bytes would say; see `__pongUnsent`. **/
	public var holding:Int = 0;

	/** The server's say over an upgrade; null accepts with the first subprotocol offered. **/
	public var admit:Null<StringMap<String>->Bool> = null;

	/** What the heartbeat was scheduled with, or -1 while it is stopped. **/
	public var beat:Float = -1;

	private var __in:Bytes = Bytes.alloc(64);
	private var __inStart:Int = 0;
	private var __inEnd:Int = 0;
	private var __messageBytes:Bytes = null;
	private var __random:Int;

	public function new(?url:String, ?protocols:Array<String>, seed:Int = 0x5EED) {
		super();
		__random = seed;
		if (url != null) {
			__client(url, protocols);
		} else {
			__isClient = false;
		}
	}

	/** Bytes arriving, as a read hands them over. **/
	public function receive(bytes:Bytes, offset:Int = 0, ?length:Int):Void {
		if (length == null) {
			length = bytes.length - offset;
		}
		if (readyState == Session.CLOSED || length == 0) {
			return;
		}
		__heard = true;
		if (__inEnd + length > __in.length) {
			var grown:Bytes = Bytes.alloc((__inEnd - __inStart + length) * 2);
			grown.blit(0, __in, __inStart, __inEnd - __inStart);
			__inEnd -= __inStart;
			__inStart = 0;
			__in = grown;
		}
		__in.blit(__inEnd, bytes, offset, length);
		__inEnd += length;
		__process();
	}

	/** Everything sent since the last call, in one piece. **/
	public function takeSent():Bytes {
		var total:Int = 0;
		for (b in sent) {
			total += b.length;
		}
		var all:Bytes = Bytes.alloc(total);
		var at:Int = 0;
		for (b in sent) {
			all.blit(at, b, 0, b.length);
			at += b.length;
		}
		sent = [];
		return all;
	}

	/** A client's upgrade request, sent. **/
	public function start():Void {
		__doHandshake();
	}

	public function heartbeat():Void {
		__onHeartbeat();
	}

	private function __process():Void {
		if (__refusing) {
			__inStart = __inEnd = 0;
			return;
		}
		if (readyState == Session.OPEN || readyState == Session.CLOSING) {
			while (__inEnd > __inStart) {
				var at:Int = __frameHeader(__in, __inStart, __inEnd);
				if (at <= 0) {
					if (at < 0) {
						return;
					}
					break;
				}
				__inStart = at + __frameLength;
				if (__frameOpcode >= Opcode.CLOSE) {
					var opcode:Int = __frameOpcode;
					__controlFrame(__in, at);
					if (opcode == Opcode.CLOSE || readyState == Session.CLOSED) {
						return;
					}
					continue;
				}
				if (!__dataFrame(__in, at)) {
					return;
				}
			}
		} else if (readyState == Session.CONNECTING) {
			var headerLength:Int = __findHead(__in, __inStart, __inEnd);
			if (headerLength <= 0) {
				return;
			}
			var start:Int = __inStart;
			__inStart += headerLength;
			__takeHead(__in, start, headerLength);
			if (readyState == Session.OPEN && __inEnd > __inStart) {
				__process();
			}
		}
	}

	override private function __randomBytes(count:Int):Bytes {
		// Not secure: a test's, so a run repeats.
		var bytes:Bytes = Bytes.alloc(count);
		for (i in 0...count) {
			__random = Seeded.step(__random);
			bytes.set(i, __random >> 16);
		}
		return bytes;
	}

	override private function __writeBytes(bytes:Bytes):Void {
		sent.push(bytes);
	}

	override private function __sendFrameOf(payload:Bytes, offset:Int, length:Int, opcode:Int, isFinal:Bool, compressed:Bool):Void {
		var masked:Bool = __isClient != false;
		var frame:Bytes = Bytes.alloc(Frame.headerLength(length, masked) + length);
		var at:Int = Frame.writeHeader(frame, 0, (isFinal ? Frame.FIN : 0) | (compressed ? Frame.RSV1 : 0) | opcode, length, masked);
		if (masked) {
			var key:Bytes = __randomBytes(4);
			frame.blit(at, key, 0, 4);
			Frame.maskInto(frame, at + 4, payload, offset, length, key, 0);
		} else if (length > 0) {
			frame.blit(at, payload, offset, length);
		}
		sent.push(frame);
	}

	override private function __close(code:Int, ?reason:String):Void {
		var connecting:Bool = readyState == Session.CONNECTING;
		readyState = Session.CLOSED;
		if (closes++ > 0) {
			return;
		}
		if (connecting && __isClient == true && !__ownerClosing) {
			code = 1006;
			reason = null;
		}
		closeCode = code;
		closeReason = reason;
		__stopHeartbeat();
	}

	override private function __onError(errorMessage:String, errorId:Int = 0):Void {
		errors.push(errorMessage);
	}

	override private function __opened():Void {
		opened++;
	}

	override private function __admit(requestLine:String, headers:StringMap<String>, ?head:String):Bool {
		if (admit != null && !admit(headers)) {
			__refuseUpgrade(403, null);
			return false;
		}
		return super.__admit(requestLine, headers, head);
	}

	override private function __messageBegin():Void {
		if (__messageBytes == null) {
			__messageBytes = Bytes.alloc(16);
		}
	}

	override private function __roomForMessage(held:Int, length:Int, last:Bool):Bytes {
		if (length > largestRoom) {
			largestRoom = length;
		}
		if (length > __messageBytes.length) {
			var grown:Bytes = Bytes.alloc(length + (length >> 1));
			grown.blit(0, __messageBytes, 0, held);
			__messageBytes = grown;
		}
		return __messageBytes;
	}

	override private function __message():Bytes {
		return __messageBytes;
	}

	override private function __dispatchMessage():Void {
		if (readyState == Session.OPEN) {
			messages.push({opcode: __incomingOpcode, data: __messageBytes.sub(0, __incomingMessageSize)});
		}
		super.__dispatchMessage();
	}

	override private function get_ownPending():Int {
		return holding;
	}

	override private function __scheduleHeartbeat(period:Float):Void {
		beat = period;
	}

	override private function __stopHeartbeat():Void {
		beat = -1;
	}
}

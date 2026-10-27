package wsproto;

import haxe.io.Bytes;
import utest.Assert;

/**
	A server session fed frames nobody meant it to see, after a real
	handshake: a length mutated deep in a header, a continuation with nothing
	to continue, a frame that promises two gigabytes and sends none of it.
	CrossByte's wire fuzz, at the session.

	**The assertion is the session after them, not the malformed ones.** Each
	round may end open or failed; what is not allowed is a throw, a code a
	peer breaking the protocol is not owed, or storage asked for past
	`maxMessageSize` on the strength of a header. And a fresh session is well
	once the noise stops.
**/
class FuzzTest extends utest.Test {
	private static inline var ROUNDS:Int = 400;

	private var __state:Int;

	public function testASessionSurvivesMalformedFrames():Void {
		// Seeded, so a red run reproduces.
		__state = 0x7EA51234;
		var codes:Map<Int, Int> = new Map();
		for (round in 0...ROUNDS) {
			var pair:Pair = Pair.opened();
			pair.server.maxMessageSize = 4096;
			var wire:Bytes = __frames();
			try {
				// Cut where the network might.
				var at:Int = 0;
				while (at < wire.length) {
					var length:Int = 1 + __next(64);
					if (at + length > wire.length) {
						length = wire.length - at;
					}
					pair.server.receive(wire, at, length);
					at += length;
				}
			} catch (e:Dynamic) {
				Assert.fail('round $round threw $e');
				return;
			}
			if (pair.server.readyState == Session.CLOSED) {
				codes.set(pair.server.closeCode, (codes.exists(pair.server.closeCode) ? codes.get(pair.server.closeCode) : 0) + 1);
				var code:Int = pair.server.closeCode;
				Assert.isTrue(code == 1000 || code == 1002 || code == 1007 || code == 1009 || CloseCode.isValid(code), 'round $round closed $code');
			}
			Assert.isTrue(pair.server.largestRoom <= 4096, 'round $round asked for ${pair.server.largestRoom}');
		}
		// Most rounds break the protocol somewhere.
		Assert.isTrue(codes.exists(1002));

		var pair:Pair = Pair.opened();
		pair.client.sendString("still well");
		pair.pump();
		Assert.equals("still well", pair.server.messages[0].data.toString());
	}

	private function __frames():Bytes {
		var out:haxe.io.BytesBuffer = new haxe.io.BytesBuffer();
		for (i in 0...1 + __next(6)) {
			var opcodes:Array<Int> = [0, 1, 2, 8, 9, 10, 3, 0xB];
			var first:Int = (__next(2) == 0 ? Frame.FIN : 0) | opcodes[__next(opcodes.length)];
			if (__next(8) == 0) {
				first |= Frame.RSV1;
			}
			var payload:Bytes = Bytes.alloc(__next(4) == 0 ? __next(300) : __next(20));
			for (j in 0...payload.length) {
				payload.set(j, __next(256));
			}
			var frame:Bytes = SessionTest.clientFrame(first, payload);
			switch (__next(6)) {
				case 0:
					// A byte of the header, mutated.
					var at:Int = __next(frame.length < 10 ? frame.length : 10);
					frame.set(at, __next(256));
				case 1:
					// A length that promises far more than follows.
					frame = Bytes.ofHex("82ff00000000" + StringTools.hex(__next(0x7FFFFFFF), 8) + "11223344");
				case 2:
					frame = frame.sub(0, __next(frame.length));
				default:
			}
			out.add(frame);
		}
		return out.getBytes();
	}

	private function __next(bound:Int):Int {
		__state = Seeded.step(__state);
		return bound <= 0 ? 0 : (__state >> 4) % bound;
	}
}

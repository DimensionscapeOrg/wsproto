package wsproto;

import haxe.io.Bytes;
import utest.Assert;

/**
	The frame layout against RFC 6455 5.7's examples, and the masking in both
	its forms.
**/
class FrameTest extends utest.Test {
	public function testHeaderLengths():Void {
		Assert.equals(2, Frame.headerLength(0, false));
		Assert.equals(2, Frame.headerLength(125, false));
		Assert.equals(4, Frame.headerLength(126, false));
		Assert.equals(4, Frame.headerLength(65535, false));
		Assert.equals(10, Frame.headerLength(65536, false));
		Assert.equals(6, Frame.headerLength(0, true));
		Assert.equals(8, Frame.headerLength(126, true));
		Assert.equals(14, Frame.headerLength(65536, true));
	}

	public function testAnUnmaskedTextFrameIsRfc6455s():Void {
		// RFC 6455 5.7: a single-frame unmasked text message, "Hello".
		Assert.equals("810548656c6c6f", frame(Opcode.TEXT, Bytes.ofString("Hello"), null).toHex());
	}

	public function testAMaskedTextFrameIsRfc6455s():Void {
		// RFC 6455 5.7: the same, masked with 37 fa 21 3d.
		Assert.equals("818537fa213d7f9f4d5158", frame(Opcode.TEXT, Bytes.ofString("Hello"), Bytes.ofHex("37fa213d")).toHex());
	}

	public function testAMaskedPongIsRfc6455s():Void {
		Assert.equals("8a8537fa213d7f9f4d5158", frame(Opcode.PONG, Bytes.ofString("Hello"), Bytes.ofHex("37fa213d")).toHex());
	}

	public function testLengthsOfTwoAndEightBytesAreBigEndian():Void {
		// RFC 6455 5.7: 256 bytes, and 64 KiB, of binary data.
		Assert.equals("827e0100", frame(Opcode.BINARY, Bytes.alloc(256), null).sub(0, 4).toHex());
		Assert.equals("827f0000000000010000", frame(Opcode.BINARY, Bytes.alloc(65536), null).sub(0, 10).toHex());
	}

	public function testMaskingTwiceGivesTheDataBack():Void {
		var key:Bytes = Bytes.ofHex("a1b2c3d4");
		for (length in [0, 1, 3, 4, 5, 7, 8, 9, 31, 1000]) {
			for (offset in [0, 1, 2, 3]) {
				var data:Bytes = Bytes.alloc(length + offset);
				for (i in 0...data.length) {
					data.set(i, (i * 7 + 3) & 0xFF);
				}
				var original:Bytes = data.sub(0, data.length);
				Frame.mask(data, length, key, 0, offset);
				if (length > 0) {
					Assert.equals(original.get(offset) ^ 0xa1, data.get(offset));
				}
				Frame.mask(data, length, key, 0, offset);
				Assert.equals(original.toHex(), data.toHex());
			}
		}
	}

	public function testMaskIntoIsACopyThenAMask():Void {
		var key:Bytes = Bytes.ofHex("00ffa55a0102");
		for (length in [0, 1, 4, 6, 13, 64, 257]) {
			var data:Bytes = Bytes.alloc(length + 3);
			for (i in 0...data.length) {
				data.set(i, (i * 13 + 5) & 0xFF);
			}
			var expected:Bytes = data.sub(3, length);
			Frame.mask(expected, length, key, 2, 0);
			var out:Bytes = Bytes.alloc(length + 5);
			Frame.maskInto(out, 5, data, 3, length, key, 2);
			Assert.equals(expected.toHex(), out.sub(5, length).toHex());
		}
	}

	private static function frame(opcode:Int, payload:Bytes, key:Null<Bytes>):Bytes {
		var masked:Bool = key != null;
		var out:Bytes = Bytes.alloc(Frame.headerLength(payload.length, masked) + payload.length);
		var at:Int = Frame.writeHeader(out, 0, Frame.FIN | opcode, payload.length, masked);
		if (masked) {
			out.blit(at, key, 0, 4);
			Frame.maskInto(out, at + 4, payload, 0, payload.length, key, 0);
		} else {
			out.blit(at, payload, 0, payload.length);
		}
		return out;
	}
}

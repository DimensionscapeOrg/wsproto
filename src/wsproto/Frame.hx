package wsproto;

import haxe.io.Bytes;

/**
	How a frame is laid out (RFC 6455 5.2): the header in front of its
	payload, and the mask a client's payload goes under.
**/
class Frame {
	public static inline var FIN:Int = 0x80;
	public static inline var RSV1:Int = 0x40;
	public static inline var RSV2:Int = 0x20;
	public static inline var RSV3:Int = 0x10;
	public static inline var MASK:Int = 0x80;

	/** The longest header: two bytes, eight of length and four of mask key. **/
	public static inline var MAX_HEADER:Int = 14;

	/**
		How many bytes go in front of a payload of `length` bytes: 2, 4 or
		10, and the four of the mask key where `masked`.
	**/
	public static inline function headerLength(length:Int, masked:Bool):Int {
		return (length > 65535 ? 10 : length > 125 ? 4 : 2) + (masked ? 4 : 0);
	}

	/**
		Writes a frame's header into `out` at `at`, up to where its mask key
		goes: `first` is the frame's first byte (`FIN`, `RSV1` and the
		opcode), and `length` the payload's. `out` must have room. Answers
		where the header ends.
	**/
	public static inline function writeHeader(out:Bytes, at:Int, first:Int, length:Int, masked:Bool):Int {
		var maskFlag:Int = masked ? MASK : 0;
		out.set(at++, first);
		if (length > 65535) {
			out.set(at++, maskFlag | 127);
			out.set(at++, 0);
			out.set(at++, 0);
			out.set(at++, 0);
			out.set(at++, 0);
			out.set(at++, (length >>> 24) & 0xFF);
			out.set(at++, (length >>> 16) & 0xFF);
			out.set(at++, (length >>> 8) & 0xFF);
			out.set(at++, length & 0xFF);
		} else if (length > 125) {
			out.set(at++, maskFlag | 126);
			out.set(at++, (length >>> 8) & 0xFF);
			out.set(at++, length & 0xFF);
		} else {
			out.set(at++, maskFlag | length);
		}
		return at;
	}

	/**
		XORs `length` bytes of `data` from `dataAt` in place with the four-byte
		mask at `maskAt` in `mask`: a frame read straight into the message it
		belongs to is unmasked where it landed.

		Masking and unmasking are the same operation, so both directions use
		this. It runs on `Bytes` directly rather than through a buffer class
		that bounds-checks every element write an index this loop already
		knows is in range; on a server this is touched once per inbound byte.

		Whole 32-bit words are XORed at a time. The key is read with the same
		accessor as the data, so both agree on byte order and word `i` lines
		up with `mask[(i + j) & 3]` for every offset that is a multiple of
		four, which is why only the trailing bytes need the scalar loop.
		(Word `i` is counted from `dataAt`, so this holds wherever the frame
		starts.)
	**/
	public static function mask(data:Bytes, length:Int, mask:Bytes, maskAt:Int, dataAt:Int):Void {
		if (length <= 0) {
			return;
		}

		var key:Int = mask.getInt32(maskAt);
		var wordEnd:Int = length & ~3;
		var i:Int = 0;

		while (i < wordEnd) {
			data.setInt32(dataAt + i, data.getInt32(dataAt + i) ^ key);
			i += 4;
		}

		while (i < length) {
			data.set(dataAt + i, data.get(dataAt + i) ^ mask.get(maskAt + (i & 0x03)));
			i++;
		}
	}

	/**
		Copies `length` bytes of `data` from `dataAt` into `out` at `outAt`,
		masked with the four-byte key at `maskAt` in `mask`: a client's
		payload framed straight into its frame.

		Copied whole and then masked where it landed, rather than masked on
		the way in one loop: natively the copy is a `memcpy`, and a loop
		over one buffer is vectorized where one reading a buffer and writing
		another is not. A client sending 16 KB messages spent a sixth more
		processor time on each with the single loop.
	**/
	public static inline function maskInto(out:Bytes, outAt:Int, data:Bytes, dataAt:Int, length:Int, mask:Bytes, maskAt:Int):Void {
		if (length > 0) {
			out.blit(outAt, data, dataAt, length);
			Frame.mask(out, length, mask, maskAt, outAt);
		}
	}
}

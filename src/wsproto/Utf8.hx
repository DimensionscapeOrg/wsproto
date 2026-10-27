package wsproto;

import haxe.io.Bytes;

/**
	UTF-8 as a text message and a close frame's reason carry it: checked
	strictly where it arrives (RFC 6455 8.1 fails the connection on any
	byte that is not), and written well formed where it is sent.
**/
class Utf8 {
	/**
		Whether `length` bytes of `bytes` from `offset` are well-formed UTF-8:
		no overlong form, no surrogate, nothing past U+10FFFF, and no
		character cut off at the end.
	**/
	public static function isValid(bytes:Bytes, offset:Int, length:Int):Bool {
		var i:Int = offset;
		var end:Int = offset + length;
		while (i < end) {
			var b0:Int = bytes.get(i);
			if (b0 < 0x80) {
				// 0xxxxxxx
				i++;
			} else if (b0 >= 0xC2 && b0 <= 0xDF) {
				// 110xxxxx 10xxxxxx
				if (i + 1 >= end || (bytes.get(i + 1) & 0xC0) != 0x80) {
					return false;
				}
				i += 2;
			} else if (b0 == 0xE0) {
				// 11100000 101xxxxx 10xxxxxx (reject overlong)
				if (i + 2 >= end) {
					return false;
				}
				var b1:Int = bytes.get(i + 1);
				if (b1 < 0xA0 || b1 > 0xBF || (bytes.get(i + 2) & 0xC0) != 0x80) {
					return false;
				}
				i += 3;
			} else if (b0 >= 0xE1 && b0 <= 0xEC) {
				// 1110xxxx 10xxxxxx 10xxxxxx
				if (i + 2 >= end || (bytes.get(i + 1) & 0xC0) != 0x80 || (bytes.get(i + 2) & 0xC0) != 0x80) {
					return false;
				}
				i += 3;
			} else if (b0 == 0xED) {
				// 11101101 100xxxxx 10xxxxxx (reject surrogates)
				if (i + 2 >= end) {
					return false;
				}
				var b1:Int = bytes.get(i + 1);
				if (b1 < 0x80 || b1 > 0x9F || (bytes.get(i + 2) & 0xC0) != 0x80) {
					return false;
				}
				i += 3;
			} else if (b0 >= 0xEE && b0 <= 0xEF) {
				// 1110xxxx 10xxxxxx 10xxxxxx
				if (i + 2 >= end || (bytes.get(i + 1) & 0xC0) != 0x80 || (bytes.get(i + 2) & 0xC0) != 0x80) {
					return false;
				}
				i += 3;
			} else if (b0 == 0xF0) {
				// 11110000 1001xxxx 10xxxxxx 10xxxxxx (reject overlong)
				if (i + 3 >= end) {
					return false;
				}
				var b1:Int = bytes.get(i + 1);
				if (b1 < 0x90 || b1 > 0xBF || (bytes.get(i + 2) & 0xC0) != 0x80 || (bytes.get(i + 3) & 0xC0) != 0x80) {
					return false;
				}
				i += 4;
			} else if (b0 >= 0xF1 && b0 <= 0xF3) {
				// 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
				if (i + 3 >= end
					|| (bytes.get(i + 1) & 0xC0) != 0x80
					|| (bytes.get(i + 2) & 0xC0) != 0x80
					|| (bytes.get(i + 3) & 0xC0) != 0x80) {
					return false;
				}
				i += 4;
			} else if (b0 == 0xF4) {
				// 11110100 1000xxxx 10xxxxxx 10xxxxxx (cap at U+10FFFF)
				if (i + 3 >= end) {
					return false;
				}
				var b1:Int = bytes.get(i + 1);
				if (b1 < 0x80 || b1 > 0x8F || (bytes.get(i + 2) & 0xC0) != 0x80 || (bytes.get(i + 3) & 0xC0) != 0x80) {
					return false;
				}
				i += 4;
			} else {
				// 0x80-0xBF (stray continuation), 0xC0-0xC1 (overlong), 0xF5-0xFF (out of range)
				return false;
			}
		}
		return true;
	}

	/**
		`text` as UTF-8 into `out` at `at`, which must have room for three
		bytes a code unit of `text`. A surrogate pair is one character of
		four bytes; a surrogate without its other half, which no valid UTF-8
		can carry, is U+FFFD. Answers how many bytes were written.

		For targets whose strings are UTF-16 or whole code points; on Neko a
		string is its UTF-8 already (see `bytesOf`).
	**/
	public static function encode(text:String, out:Bytes, at:Int):Int {
		var count:Int = text.length;
		var start:Int = at;
		var i:Int = 0;
		while (i < count) {
			var c:Int = StringTools.fastCodeAt(text, i++);
			if (c < 0x80) {
				out.set(at++, c);
				continue;
			}
			if (c < 0x800) {
				out.set(at++, 0xC0 | (c >> 6));
				out.set(at++, 0x80 | (c & 0x3F));
				continue;
			}
			if (c >= 0xD800 && c <= 0xDFFF) {
				var low:Int = i < count ? StringTools.fastCodeAt(text, i) : 0;
				if (c <= 0xDBFF && low >= 0xDC00 && low <= 0xDFFF) {
					i++;
					var code:Int = 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
					out.set(at++, 0xF0 | (code >> 18));
					out.set(at++, 0x80 | ((code >> 12) & 0x3F));
					out.set(at++, 0x80 | ((code >> 6) & 0x3F));
					out.set(at++, 0x80 | (code & 0x3F));
					continue;
				}
				c = 0xFFFD;
			} else if (c > 0xFFFF) {
				// A target whose strings hold whole code points.
				out.set(at++, 0xF0 | (c >> 18));
				out.set(at++, 0x80 | ((c >> 12) & 0x3F));
				out.set(at++, 0x80 | ((c >> 6) & 0x3F));
				out.set(at++, 0x80 | (c & 0x3F));
				continue;
			}
			out.set(at++, 0xE0 | (c >> 12));
			out.set(at++, 0x80 | ((c >> 6) & 0x3F));
			out.set(at++, 0x80 | (c & 0x3F));
		}
		return at - start;
	}

	/**
		`text` as well-formed UTF-8, in `Bytes` of exactly its length: as
		`Bytes.ofString`, but with an unpaired surrogate as U+FFFD rather than
		as bytes no peer would take.
	**/
	public static function bytesOf(text:String):Bytes {
		#if neko
		return Bytes.ofString(text);
		#else
		var count:Int = text.length;
		var ascii:Bool = true;
		for (i in 0...count) {
			if (StringTools.fastCodeAt(text, i) >= 0x80) {
				ascii = false;
				break;
			}
		}
		if (ascii) {
			return Bytes.ofString(text);
		}
		var scratch:Bytes = Bytes.alloc(count * 3);
		var length:Int = encode(text, scratch, 0);
		return scratch.sub(0, length);
		#end
	}
}

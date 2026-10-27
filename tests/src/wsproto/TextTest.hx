package wsproto;

import haxe.io.Bytes;
import utest.Assert;

/** UTF-8, close codes and permessage-deflate's negotiation. **/
class TextTest extends utest.Test {
	public function testWellFormedUtf8IsTaken():Void {
		for (hex in ["", "41", "c2a2", "e282ac", "f09f9880", "f48fbfbf", "efbbbf", "ed9fbf", "ee8080"]) {
			Assert.isTrue(valid(hex), hex);
		}
	}

	public function testMalformedUtf8IsRefused():Void {
		for (hex in [
			"80", // a stray continuation
			"c0af", // overlong
			"c1bf", // overlong
			"e080af", // overlong
			"f08080af", // overlong
			"eda080", // a surrogate
			"edbfbf", // a surrogate
			"f4908080", // past U+10FFFF
			"f5808080", // past U+10FFFF
			"ff",
			"c2", // cut off
			"e282", // cut off
			"f09f98", // cut off
			"c241" // a continuation that is not one
		]) {
			Assert.isFalse(valid(hex), hex);
		}
	}

	public function testEncodingIsWellFormed():Void {
		Assert.equals("41c2a2e282acf09f9880", Utf8.bytesOf("A¢€\u{1F600}").toHex());
		Assert.equals("hello", Utf8.bytesOf("hello").toString());
		#if (cpp || jvm || js)
		// A surrogate without its other half is U+FFFD. (HashLink will not
		// make such a string, and Neko's strings are bytes.)
		var lone:String = String.fromCharCode(0xD800) + "x";
		Assert.equals("efbfbd78", Utf8.bytesOf(lone).toHex());
		#end
	}

	public function testCloseCodesAreTheRfcsRanges():Void {
		for (code in [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999]) {
			Assert.isTrue(CloseCode.isValid(code), Std.string(code));
		}
		for (code in [0, 999, 1004, 1005, 1006, 1015, 1016, 2000, 2999, 5000, 65535]) {
			Assert.isFalse(CloseCode.isValid(code), Std.string(code));
		}
	}

	public function testAServerAnswersTheFirstOfferItCanKeep():Void {
		Assert.equals("permessage-deflate; server_no_context_takeover; client_no_context_takeover",
			PerMessageDeflate.answer("permessage-deflate; client_max_window_bits"));
		Assert.equals("permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=15",
			PerMessageDeflate.answer("permessage-deflate; server_max_window_bits=10, permessage-deflate; server_max_window_bits=15"));
		Assert.isNull(PerMessageDeflate.answer("x-webkit-deflate-frame"));
		Assert.isNull(PerMessageDeflate.answer("permessage-deflate; unknown"));
		Assert.isNull(PerMessageDeflate.answer("permessage-deflate; client_max_window_bits=7"));
		Assert.isNull(PerMessageDeflate.answer("permessage-deflate;; x"));
	}

	public function testAClientTakesOnlyAnAnswerItCanKeep():Void {
		Assert.equals(PerMessageDeflate.BOTH, PerMessageDeflate.answerTaken(PerMessageDeflate.OFFER));
		Assert.equals(PerMessageDeflate.RECEIVE, PerMessageDeflate.answerTaken("permessage-deflate; server_no_context_takeover; server_max_window_bits=9"));
		Assert.equals(PerMessageDeflate.REFUSED, PerMessageDeflate.answerTaken("permessage-deflate"));
		Assert.equals(PerMessageDeflate.REFUSED, PerMessageDeflate.answerTaken("permessage-deflate; server_no_context_takeover; client_max_window_bits=10"));
		Assert.equals(PerMessageDeflate.REFUSED, PerMessageDeflate.answerTaken("permessage-deflate; server_no_context_takeover=1"));
		Assert.equals(PerMessageDeflate.REFUSED, PerMessageDeflate.answerTaken(PerMessageDeflate.OFFER + ", permessage-deflate"));
	}

	public function testDecimalsAreBoundedAsTheyAreRead():Void {
		Assert.equals(65535, Decimal.parse("65535", 65535));
		Assert.equals(-1, Decimal.parse("65536", 65535));
		Assert.equals(-1, Decimal.parse("99999999999999999999"));
		Assert.equals(-1, Decimal.parse("1a"));
		Assert.equals(-1, Decimal.parse(""));
	}

	private static function valid(hex:String):Bool {
		var bytes:Bytes = Bytes.ofHex(hex);
		return Utf8.isValid(bytes, 0, bytes.length);
	}
}

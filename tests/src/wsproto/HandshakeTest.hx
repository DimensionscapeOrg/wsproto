package wsproto;

import haxe.io.Bytes;
import utest.Assert;

class HandshakeTest extends utest.Test {
	public function testTheAcceptKeyIsRfc6455s():Void {
		// RFC 6455 1.3.
		Assert.equals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", Handshake.accept("dGhlIHNhbXBsZSBub25jZQ=="));
	}

	public function testHeadersAreByLowerCasedNameAndFolded():Void {
		var headers = Handshake.parseHeaderLines([
			"GET /chat HTTP/1.1",
			"Host: example.com",
			"Sec-WebSocket-Protocol: a, b",
			"sec-websocket-protocol: c",
			"Cookie: one=1",
			"Cookie: two=2",
			"",
			"Ignored: after the blank line"
		]);
		Assert.equals("example.com", headers.get("host"));
		Assert.equals("a, b, c", headers.get("sec-websocket-protocol"));
		Assert.equals("one=1; two=2", headers.get("cookie"));
		Assert.isFalse(headers.exists("ignored"));
	}

	public function testARequestIsValidOnlyWithItsFourHeaders():Void {
		Assert.isTrue(Handshake.isValidRequest(request(["uPgRaDe: WebSocket", "Connection: keep-alive, Upgrade", "Sec-WebSocket-Key: k", "Sec-WebSocket-Version: 13"])));
		Assert.isFalse(Handshake.isValidRequest(request(["Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13"])));
		Assert.isFalse(Handshake.isValidRequest(request(["Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Key: k", "Sec-WebSocket-Version: 12"])));
		Assert.isFalse(Handshake.isValidRequest(request(["Upgrade: websocket", "Connection: keep-alive", "Sec-WebSocket-Key: k", "Sec-WebSocket-Version: 13"])));
		Assert.isFalse(Handshake.isValidRequest(request(["Upgrade: h2c", "Connection: Upgrade", "Sec-WebSocket-Key: k", "Sec-WebSocket-Version: 13"])));
	}

	public function testAClientRequestNamesWhatItAsksFor():Void {
		var head:String = Handshake.clientRequest("/chat", "::1", 8080, "key==", "http://o/", ["a", "b"], PerMessageDeflate.OFFER).toString();
		var lines:Array<String> = head.split("\r\n");
		Assert.equals("GET /chat HTTP/1.1", lines[0]);
		Assert.equals("Host: [::1]:8080", lines[1]);
		Assert.isTrue(lines.indexOf("Sec-WebSocket-Key: key==") > 0);
		Assert.isTrue(lines.indexOf("Sec-WebSocket-Protocol: a, b") > 0);
		Assert.isTrue(lines.indexOf("Sec-WebSocket-Extensions: " + PerMessageDeflate.OFFER) > 0);
		Assert.isTrue(StringTools.endsWith(head, "\r\n\r\n"));
	}

	public function testAResponseEchoesWhatWasAccepted():Void {
		var head:String = Handshake.serverResponse("dGhlIHNhbXBsZSBub25jZQ==", "chat", "permessage-deflate").toString();
		Assert.isTrue(StringTools.startsWith(head, "HTTP/1.1 101 Switching Protocols\r\n"));
		Assert.isTrue(head.indexOf("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") > 0);
		Assert.isTrue(head.indexOf("Sec-WebSocket-Protocol: chat\r\n") > 0);
		Assert.isTrue(head.indexOf("Sec-WebSocket-Extensions: permessage-deflate\r\n") > 0);
		Assert.equals(-1, Handshake.serverResponse("k").toString().indexOf("Sec-WebSocket-Protocol"));
	}

	public function testARefusalSaysWhyAndCloses():Void {
		var head:String = Handshake.refusal(400, ["Sec-WebSocket-Version: 13"]).toString();
		Assert.equals("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nSec-WebSocket-Version: 13\r\n\r\n", head);
		Assert.isTrue(StringTools.startsWith(Handshake.refusal(431).toString(), "HTTP/1.1 431 Request Header Fields Too Large\r\n"));
		Assert.isTrue(StringTools.startsWith(Handshake.refusal(499).toString(), "HTTP/1.1 499 Refused\r\n"));
	}

	public function testTheEndOfAHeadIsFoundWhereverItFalls():Void {
		var bytes:Bytes = Bytes.ofString("GET / HTTP/1.1\r\nA: b\r\n\r\nrest");
		Assert.equals(20, Handshake.findHeaderEnd(bytes, 0, bytes.length));
		Assert.equals(-1, Handshake.findHeaderEnd(bytes, 0, 23));
		Assert.equals(20, Handshake.findHeaderEnd(bytes, 17, 24));
	}

	private static function request(lines:Array<String>) {
		return Handshake.parseHeaderLines(["GET /chat HTTP/1.1"].concat(lines).concat([""]));
	}
}

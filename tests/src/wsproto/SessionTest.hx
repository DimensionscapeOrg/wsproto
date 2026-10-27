package wsproto;

import haxe.io.Bytes;
import utest.Assert;

/**
	Two sessions back to back, and a session fed frames its peer would never
	send: the handshake, messages, the closing handshake, and every way a
	peer can break the protocol.
**/
@:access(wsproto.Session)
class SessionTest extends utest.Test {
	public function testTheHandshakeOpensBothEnds():Void {
		var pair:Pair = Pair.opened(["chat.v2", "chat.v1"]);
		Assert.equals(Session.OPEN, pair.client.readyState);
		Assert.equals(Session.OPEN, pair.server.readyState);
		Assert.equals(1, pair.client.opened);
		Assert.equals(1, pair.server.opened);
		// The first offered, unless the server says otherwise.
		Assert.equals("chat.v2", pair.server.protocol);
		Assert.equals("chat.v2", pair.client.protocol);
		Assert.equals("", pair.client.extensions);
		Assert.isFalse(pair.client.compressed);
	}

	public function testTheHandshakeSurvivesBeingCutAnywhere():Void {
		for (chunk in [1, 2, 3, 7, 64]) {
			var pair:Pair = new Pair();
			pair.chunk = chunk;
			pair.pump();
			pair.client.sendString("after");
			pair.pump();
			Assert.equals(Session.OPEN, pair.server.readyState, 'chunk $chunk');
			Assert.equals("after", text(pair.server.messages[0]), 'chunk $chunk');
		}
	}

	public function testFramesArrivingWithTheHeadAreRead():Void {
		var pair:Pair = new Pair();
		var request:Bytes = pair.client.takeSent();
		var frame:Bytes = clientFrame(Frame.FIN | Opcode.TEXT, Bytes.ofString("early"));
		var both:Bytes = Bytes.alloc(request.length + frame.length);
		both.blit(0, request, 0, request.length);
		both.blit(request.length, frame, 0, frame.length);
		pair.server.receive(both);
		Assert.equals(Session.OPEN, pair.server.readyState);
		Assert.equals("early", text(pair.server.messages[0]));
	}

	public function testMessagesGoBothWays():Void {
		var pair:Pair = Pair.opened();
		pair.client.sendString("héllo \u{1F600}");
		pair.client.sendBytes(Bytes.ofHex("00ff10"));
		pair.client.sendString("");
		pair.server.sendString("back");
		pair.pump();
		Assert.equals(3, pair.server.messages.length);
		Assert.equals(Opcode.TEXT, pair.server.messages[0].opcode);
		Assert.equals("héllo \u{1F600}", text(pair.server.messages[0]));
		Assert.equals(Opcode.BINARY, pair.server.messages[1].opcode);
		Assert.equals("00ff10", pair.server.messages[1].data.toHex());
		Assert.equals(0, pair.server.messages[2].data.length);
		Assert.equals("back", text(pair.client.messages[0]));
	}

	public function testAClientMasksAndAServerDoesNot():Void {
		var pair:Pair = Pair.opened();
		pair.client.sendString("x");
		pair.server.sendString("y");
		Assert.isTrue((pair.client.takeSent().get(1) & Frame.MASK) != 0);
		Assert.isTrue((pair.server.takeSent().get(1) & Frame.MASK) == 0);
	}

	public function testALongMessageGoesInFramesAndArrivesWhole():Void {
		var pair:Pair = Pair.opened();
		pair.server.maxMessageSize = 0;
		var data:Bytes = Bytes.alloc(Session.FRAGMENT_SIZE * 3 + 17);
		for (i in 0...data.length) {
			data.set(i, i & 0xFF);
		}
		pair.client.sendBytes(data);
		Assert.equals(4, pair.client.sent.length);
		pair.chunk = 1000;
		pair.pump();
		Assert.equals(1, pair.server.messages.length);
		Assert.equals(data.length, pair.server.messages[0].data.length);
		Assert.equals(0, data.compare(pair.server.messages[0].data));
	}

	public function testAPingIsAnsweredWithItsPayload():Void {
		var pair:Pair = Pair.opened();
		pair.client.ping(Bytes.ofString("are you there"));
		pair.client.takeSent();
		pair.server.receive(clientFrame(Frame.FIN | Opcode.PING, Bytes.ofString("are you there")));
		var pong:Bytes = pair.server.takeSent();
		Assert.equals(Frame.FIN | Opcode.PONG, pong.get(0));
		Assert.equals("are you there", pong.getString(2, pong.get(1)));
	}

	public function testPingsFasterThanTheyAreAnsweredGetOneAnswerEach():Void {
		var pair:Pair = Pair.opened();
		// The first answer sits behind ten bytes the network has not taken.
		pair.server.holding = 10;
		pair.server.receive(clientFrame(Frame.FIN | Opcode.PING, Bytes.ofString("1")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.PING, Bytes.ofString("2")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.PING, Bytes.ofString("3")));
		Assert.equals(1, pair.server.sent.length);
		Assert.isTrue(pair.server.__pongOwed);
		// Taken: the newest ping, and only it, is answered.
		pair.server.holding = 0;
		pair.server.bytesSent = 100;
		pair.server.__settlePong();
		Assert.equals(2, pair.server.sent.length);
		Assert.equals("3", pair.server.sent[1].getString(2, 1));
	}

	public function testTheClosingHandshakeReportsThePeersCode():Void {
		var pair:Pair = Pair.opened();
		pair.client.close(4001, "done here");
		Assert.equals(Session.CLOSING, pair.client.readyState);
		pair.pump();
		Assert.equals(Session.CLOSED, pair.client.readyState);
		Assert.equals(Session.CLOSED, pair.server.readyState);
		Assert.equals(4001, pair.server.closeCode);
		Assert.equals("done here", pair.server.closeReason);
		Assert.equals(4001, pair.client.closeCode);
		Assert.equals(1, pair.client.closes);
	}

	public function testAReasonIsCutBetweenCharacters():Void {
		var pair:Pair = Pair.opened();
		var reason:String = "";
		// 140 bytes: cut at 123 would split the 62nd character.
		for (i in 0...70) {
			reason += "é";
		}
		pair.server.close(1000, reason);
		var frame:Bytes = pair.server.takeSent();
		Assert.equals(2 + 122, frame.get(1));
		Assert.isTrue(Utf8.isValid(frame, 4, 122));
	}

	public function testDataAfterACloseIsNotDelivered():Void {
		var pair:Pair = Pair.opened();
		pair.server.close();
		pair.server.receive(clientFrame(Frame.FIN | Opcode.TEXT, Bytes.ofString("late")));
		Assert.equals(0, pair.server.messages.length);
	}

	public function testAClientsUnmaskedFrameFails1002():Void {
		assertFails(1002, unmaskedFrame(Frame.FIN | Opcode.TEXT, Bytes.ofString("x")));
	}

	public function testAReservedBitWithoutCompressionFails1002():Void {
		assertFails(1002, clientFrame(Frame.FIN | Frame.RSV1 | Opcode.TEXT, Bytes.ofString("x")));
		assertFails(1002, clientFrame(Frame.FIN | Frame.RSV2 | Opcode.BINARY, Bytes.ofString("x")));
	}

	public function testAnUnknownOpcodeFails1002():Void {
		assertFails(1002, clientFrame(Frame.FIN | 0x3, Bytes.ofString("x")));
		assertFails(1002, clientFrame(Frame.FIN | 0xB, Bytes.alloc(0)));
	}

	public function testAControlFrameFragmentedOrLongFails1002():Void {
		assertFails(1002, clientFrame(Opcode.PING, Bytes.alloc(0)));
		assertFails(1002, clientFrame(Frame.FIN | Opcode.PING, Bytes.alloc(126)));
	}

	public function testFragmentsOutOfOrderFail1002():Void {
		assertFails(1002, clientFrame(Frame.FIN | Opcode.CONTINUATION, Bytes.ofString("x")));
		var pair:Pair = Pair.opened();
		pair.server.receive(clientFrame(Opcode.TEXT, Bytes.ofString("a")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.TEXT, Bytes.ofString("b")));
		Assert.equals(1002, pair.server.closeCode);
	}

	public function testAControlFrameBetweenFragmentsIsTaken():Void {
		var pair:Pair = Pair.opened();
		pair.server.receive(clientFrame(Opcode.TEXT, Bytes.ofString("he")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.PING, Bytes.ofString("p")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.CONTINUATION, Bytes.ofString("llo")));
		Assert.equals("hello", text(pair.server.messages[0]));
		Assert.equals(Session.OPEN, pair.server.readyState);
	}

	public function testTextThatIsNotUtf8Fails1007():Void {
		assertFails(1007, clientFrame(Frame.FIN | Opcode.TEXT, Bytes.ofHex("c0af")));
		var pair:Pair = Pair.opened();
		// A character split between frames is checked whole.
		pair.server.receive(clientFrame(Opcode.TEXT, Bytes.ofHex("e282")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.CONTINUATION, Bytes.ofHex("ac")));
		Assert.equals("€", text(pair.server.messages[0]));
		pair.server.receive(clientFrame(Opcode.TEXT, Bytes.ofHex("e282")));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.CONTINUATION, Bytes.ofHex("41")));
		Assert.equals(1007, pair.server.closeCode);
	}

	public function testATooLongFrameFails1009OnItsHeader():Void {
		var pair:Pair = Pair.opened();
		pair.server.maxMessageSize = 1000;
		// Only the header: no wait for a payload that would be refused.
		var header:Bytes = clientFrame(Frame.FIN | Opcode.BINARY, Bytes.alloc(1001)).sub(0, 8);
		pair.server.receive(header);
		Assert.equals(1009, pair.server.closeCode);
		Assert.equals(0, pair.server.largestRoom);
	}

	public function testAMessageTooLongAcrossFramesFails1009():Void {
		var pair:Pair = Pair.opened();
		pair.server.maxMessageSize = 1000;
		pair.server.receive(clientFrame(Opcode.BINARY, Bytes.alloc(600)));
		pair.server.receive(clientFrame(Frame.FIN | Opcode.CONTINUATION, Bytes.alloc(401)).sub(0, 8));
		Assert.equals(1009, pair.server.closeCode);
		Assert.equals(600, pair.server.largestRoom);
	}

	public function testALengthPast2GiBFails1009():Void {
		assertFails(1009, Bytes.ofHex("82ff0000000080000000"));
		assertFails(1009, Bytes.ofHex("82ff0000000100000000"));
	}

	public function testABadCloseFails():Void {
		assertFails(1002, clientFrame(Frame.FIN | Opcode.CLOSE, Bytes.ofHex("03")));
		assertFails(1002, clientFrame(Frame.FIN | Opcode.CLOSE, Bytes.ofHex("03ed")));
		assertFails(1002, clientFrame(Frame.FIN | Opcode.CLOSE, Bytes.ofHex("07d0")));
		assertFails(1007, clientFrame(Frame.FIN | Opcode.CLOSE, Bytes.ofHex("03e8c0af")));
	}

	public function testACloseWithNoCodeReports1000():Void {
		var pair:Pair = Pair.opened();
		pair.server.receive(clientFrame(Frame.FIN | Opcode.CLOSE, Bytes.alloc(0)));
		Assert.equals(1000, pair.server.closeCode);
		Assert.equals(Frame.FIN | Opcode.CLOSE, pair.server.takeSent().get(0));
	}

	public function testAWrongVersionIsRefusedWithTheRightOne():Void {
		var server:TestHost = new TestHost();
		server.receive(Bytes.ofString("GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 8\r\n\r\n"));
		var answer:String = server.takeSent().toString();
		Assert.isTrue(StringTools.startsWith(answer, "HTTP/1.1 400 Bad Request\r\n"));
		Assert.isTrue(answer.indexOf("Sec-WebSocket-Version: 13\r\n") > 0);
		Assert.equals(Session.CLOSED, server.readyState);
		Assert.equals(1002, server.closeCode);
	}

	public function testANonGetIsRefused():Void {
		var server:TestHost = new TestHost();
		server.receive(Bytes.ofString("POST / HTTP/1.1\r\n\r\n"));
		Assert.isTrue(StringTools.startsWith(server.takeSent().toString(), "HTTP/1.1 400 "));
	}

	public function testAHeadPastTheLimitIs431():Void {
		var server:TestHost = new TestHost();
		server.maxHeaderSize = 64;
		server.receive(Bytes.ofString("GET / HTTP/1.1\r\nX-Padding: " + StringTools.lpad("", "x", 80)));
		Assert.isTrue(StringTools.startsWith(server.takeSent().toString(), "HTTP/1.1 431 "));
	}

	public function testTheServersSayRefuses():Void {
		var pair:Pair = new Pair(null, (_, server) -> server.admit = headers -> false);
		pair.pump();
		Assert.equals(Session.CLOSED, pair.client.readyState);
		Assert.equals(1006, pair.client.closeCode);
		Assert.isTrue(pair.client.errors[0].indexOf("403") > 0);
	}

	public function testAClientRefusesABadAnswer():Void {
		for (answer in [
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n",
			"SSH-2.0-OpenSSH\r\n\r\n"
		]) {
			var client:TestHost = new TestHost("ws://localhost/");
			client.receive(Bytes.ofString(answer));
			Assert.equals(Session.CLOSED, client.readyState);
			Assert.equals(1006, client.closeCode);
			Assert.equals(1, client.errors.length);
		}
	}

	public function testAClientRefusesASubprotocolItDidNotAskFor():Void {
		var client:TestHost = new TestHost("ws://localhost/", ["a"]);
		var key:String = client.__key;
		client.receive(Bytes.ofString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
			+ Handshake.accept(key) + "\r\nSec-WebSocket-Protocol: b\r\n\r\n"));
		Assert.equals(1006, client.closeCode);
	}

	public function testCompressionIsAgreedWhenBothAsk():Void {
		var pair:Pair = Pair.opened(null, (client, server) -> {
			client.perMessageDeflate = true;
			server.perMessageDeflate = true;
		});
		Assert.isTrue(pair.server.compressed);
		Assert.isTrue(pair.client.compressed);
		Assert.equals(PerMessageDeflate.OFFER, pair.server.extensions);
		Assert.equals(PerMessageDeflate.OFFER, pair.client.extensions);
	}

	public function testCompressionIsNotUsedUnlessBothAsk():Void {
		var pair:Pair = Pair.opened(null, (client, server) -> client.perMessageDeflate = true);
		Assert.equals(Session.OPEN, pair.client.readyState);
		Assert.isFalse(pair.client.compressed);
		pair = Pair.opened(null, (client, server) -> server.perMessageDeflate = true);
		Assert.isFalse(pair.server.compressed);
	}

	public function testTheURLIsRead():Void {
		var client:TestHost = new TestHost("wss://[::1]/a/b?c=d");
		Assert.equals("::1", client.__host);
		Assert.equals(443, client.__port);
		Assert.equals("/a/b?c=d", client.__path);
		Assert.isTrue(client.__secure);
		Assert.raises(() -> new TestHost("http://x/"));
		Assert.raises(() -> new TestHost("ws://x:70000/"));
		Assert.raises(() -> new TestHost("nonsense"));
	}

	public function testTheHeartbeatPingsAQuietPeerAndDropsASilentOne():Void {
		var pair:Pair = Pair.opened();
		var server:TestHost = pair.server;
		Assert.equals(Session.DEFAULT_PING_INTERVAL, server.beat);
		server.pingInterval = 10;
		server.idleTimeout = 25;
		Assert.equals(10.0, server.beat);
		server.heartbeat();
		Assert.equals(Frame.FIN | Opcode.PING, server.takeSent().get(0));
		server.receive(clientFrame(Frame.FIN | Opcode.PONG, Bytes.alloc(0)));
		server.heartbeat();
		Assert.equals(0, server.sent.length);
		server.heartbeat();
		server.heartbeat();
		Assert.equals(Session.OPEN, server.readyState);
		server.heartbeat();
		Assert.equals(Session.CLOSED, server.readyState);
		Assert.equals(1006, server.closeCode);
		Assert.equals(-1.0, server.beat);
	}

	public static function clientFrame(first:Int, payload:Bytes):Bytes {
		var key:Bytes = Bytes.ofHex("1f2e3d4c");
		var frame:Bytes = Bytes.alloc(Frame.headerLength(payload.length, true) + payload.length);
		var at:Int = Frame.writeHeader(frame, 0, first, payload.length, true);
		frame.blit(at, key, 0, 4);
		Frame.maskInto(frame, at + 4, payload, 0, payload.length, key, 0);
		return frame;
	}

	public static function unmaskedFrame(first:Int, payload:Bytes):Bytes {
		var frame:Bytes = Bytes.alloc(Frame.headerLength(payload.length, false) + payload.length);
		var at:Int = Frame.writeHeader(frame, 0, first, payload.length, false);
		frame.blit(at, payload, 0, payload.length);
		return frame;
	}

	private static function assertFails(code:Int, frame:Bytes, ?pos:haxe.PosInfos):Void {
		var pair:Pair = Pair.opened();
		pair.server.receive(frame);
		Assert.equals(Session.CLOSED, pair.server.readyState, pos);
		Assert.equals(code, pair.server.closeCode, pos);
		Assert.equals(0, pair.server.messages.length, pos);
		// Told why, where it could be.
		var sent:Bytes = pair.server.takeSent();
		Assert.equals(Frame.FIN | Opcode.CLOSE, sent.get(0), pos);
		Assert.equals(code, (sent.get(2) << 8) | sent.get(3), pos);
	}

	private static function text(message:{opcode:Int, data:Bytes}):String {
		return message.data.toString();
	}
}

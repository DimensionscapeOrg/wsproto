package wsproto;

#if (cpp || hl || neko)
import haxe.Timer;
import haxe.io.Bytes;
import utest.Assert;
import wsproto.socket.Connection;
import wsproto.socket.ConnectionError;
import wsproto.socket.FlexSocket;
import wsproto.socket.Loop;
import wsproto.socket.Server;

/**
	Clients and servers of the socket layer over loopback TCP, on a loop of
	their own that each test polls while it waits: plain, and over TLS where
	the target has it.
**/
@:access(wsproto.Session)
class SocketTest extends utest.Test {
	private var __loop:Loop;
	private var __servers:Array<Server>;
	private var __connections:Array<Connection>;

	public function setup():Void {
		__loop = new Loop();
		__servers = [];
		__connections = [];
		// Not secure: a test's, so a run repeats, and Windows has no
		// /dev/urandom to fall back on
		var state:Int = 0x51DE;
		Connection.random = function(bytes:Bytes, offset:Int, length:Int):Bool {
			for (i in 0...length) {
				state = Seeded.step(state);
				bytes.set(offset + i, state >> 16);
			}
			return true;
		};
	}

	public function teardown():Void {
		for (connection in __connections) {
			connection.abort();
		}
		for (server in __servers) {
			server.close();
		}
		pump(() -> false, 0.05);
		Connection.random = null;
	}

	public function testMessagesGoBothWays():Void {
		var server:Server = echoServer(false);
		var client:Connection = track(new Connection(__loop));
		var opened:Bool = false;
		var texts:Array<String> = [];
		var binaries:Array<Bytes> = [];
		client.onOpen = () -> opened = true;
		client.onText = text -> texts.push(text);
		client.onBinary = data -> binaries.push(data);
		client.connect("ws://127.0.0.1:" + server.localPort + "/echo");

		Assert.isFalse(client.sendText("too early"));
		Assert.isTrue(pump(() -> opened), "the client did not open");
		Assert.equals("127.0.0.1", client.remoteAddress);
		Assert.equals(server.localPort, client.remotePort);

		var sent:Array<Bytes> = [pattern(10, 1), Bytes.alloc(0), pattern(70000, 2), pattern(300 * 1024, 3)];
		Assert.isTrue(client.sendText("héllo \u{1F600}"));
		for (message in sent) {
			Assert.isTrue(client.send(message, 0, message.length));
		}

		Assert.isTrue(pump(() -> texts.length == 1 && binaries.length == sent.length), "the echoes did not all arrive");
		Assert.equals("héllo \u{1F600}", texts[0]);
		for (i in 0...binaries.length) {
			Assert.equals(0, sent[i].compare(binaries[i]), 'message $i came back changed');
		}
	}

	public function testASubprotocolIsAgreed():Void {
		var server:Server = echoServer(false);
		server.protocols = ["chat.v2", "chat.v1"];
		var client:Connection = track(new Connection(__loop));
		var opened:Bool = false;
		client.onOpen = () -> opened = true;
		client.connect("ws://127.0.0.1:" + server.localPort + "/", ["chat.v1", "chat.v2"]);
		Assert.isTrue(pump(() -> opened));
		Assert.equals("chat.v1", client.protocol);
	}

	public function testTheClosingHandshakeReportsThePeersCode():Void {
		var server:Server = trackServer(new Server(__loop));
		var serverClose:Null<Array<Dynamic>> = null;
		server.onConnection = connection -> connection.onClose = (code, reason) -> serverClose = [code, reason];
		Assert.isTrue(server.listen(0, "127.0.0.1"));

		var client:Connection = track(new Connection(__loop));
		var opened:Bool = false;
		var clientClose:Null<Array<Dynamic>> = null;
		client.onOpen = () -> opened = true;
		client.onClose = (code, reason) -> clientClose = [code, reason];
		client.connect("ws://127.0.0.1:" + server.localPort + "/");
		Assert.isTrue(pump(() -> opened));

		client.close(4001, "done here");
		Assert.isTrue(pump(() -> clientClose != null && serverClose != null), "the close was not reported at both ends");
		Assert.equals(4001, serverClose[0]);
		Assert.equals("done here", serverClose[1]);
		Assert.equals(4001, clientClose[0]);
	}

	public function testAConnectNobodyAnswersFails():Void {
		var probe:Server = new Server(__loop);
		Assert.isTrue(probe.listen(0, "127.0.0.1"));
		var port:Int = probe.localPort;
		probe.close();

		var client:Connection = track(new Connection(__loop));
		var errors:Array<ConnectionError> = [];
		var closed:Int = -1;
		client.onError = (error, _) -> errors.push(error);
		client.onClose = (code, _) -> closed = code;
		client.connect("ws://127.0.0.1:" + port + "/", null, 5);
		Assert.isTrue(pump(() -> closed != -1, 10), "the failed connect was not reported");
		Assert.equals(1006, closed);
		Assert.equals(1, errors.length);
		Assert.equals(ConnectionError.CONNECT_FAILED, errors[0]);
	}

	public function testAConnectThatTakesTooLongTimesOut():Void {
		// An address nothing answers from
		var client:Connection = track(new Connection(__loop));
		var errors:Array<ConnectionError> = [];
		var closed:Int = -1;
		client.onError = (error, _) -> errors.push(error);
		client.onClose = (code, _) -> closed = code;
		var started:Float = Timer.stamp();
		client.connect("ws://10.255.255.1:81/", null, 0.3);
		Assert.isTrue(pump(() -> closed != -1, 5), "the connect did not time out");
		Assert.equals(1006, closed);
		Assert.equals(1, errors.length);
		// Unreachable can be said at once, as well as waited out
		Assert.isTrue(errors[0] == ConnectionError.TIMEOUT || errors[0] == ConnectionError.CONNECT_FAILED);
		Assert.isTrue(Timer.stamp() - started < 3, "took " + (Timer.stamp() - started) + " s");
	}

	public function testAServerThatDoesNotSpeakWebSocketIsRefused():Void {
		var listener:sys.net.Socket = new sys.net.Socket();
		listener.bind(new sys.net.Host("127.0.0.1"), 0);
		listener.listen(1);
		listener.setBlocking(false);
		var port:Int = listener.host().port;

		var client:Connection = track(new Connection(__loop));
		var errors:Array<ConnectionError> = [];
		var closed:Int = -1;
		client.onError = (error, _) -> errors.push(error);
		client.onClose = (code, _) -> closed = code;
		client.connect("ws://127.0.0.1:" + port + "/");

		var accepted:Null<sys.net.Socket> = null;
		Assert.isTrue(pump(() -> {
			if (accepted == null) {
				try {
					accepted = listener.accept();
					accepted.output.writeString("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
				} catch (_:Dynamic) {}
			}
			return closed != -1;
		}), "the refusal was not reported");
		Assert.equals(1006, closed);
		Assert.equals(ConnectionError.REFUSED, errors[0]);
		if (accepted != null) {
			accepted.close();
		}
		listener.close();
	}

	public function testAPeerThatStopsReadingOverflows():Void {
		var server:Server = trackServer(new Server(__loop));
		server.maxQueuedBytes = 256 * 1024;
		var serverSide:Null<Connection> = null;
		var errors:Array<ConnectionError> = [];
		var closed:Int = -1;
		server.onConnection = connection -> {
			serverSide = connection;
			connection.onError = (error, _) -> errors.push(error);
			connection.onClose = (code, _) -> closed = code;
		};
		Assert.isTrue(server.listen(0, "127.0.0.1"));

		// A client that upgrades and then reads nothing
		var raw:sys.net.Socket = new sys.net.Socket();
		raw.connect(new sys.net.Host("127.0.0.1"), server.localPort);
		raw.output.writeString("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
		Assert.isTrue(pump(() -> serverSide != null));

		var chunk:Bytes = pattern(64 * 1024, 9);
		var sent:Int = 0;
		while (serverSide.connected && sent < 4096) {
			serverSide.send(chunk, 0, chunk.length);
			sent++;
		}
		Assert.isTrue(pump(() -> closed != -1));
		Assert.equals(1011, closed);
		Assert.equals(ConnectionError.OVERFLOW, errors[0]);
		raw.close();
	}

	public function testSecureWebSocketsGoThroughTLS():Void {
		var server:Server = echoServer(true);
		var client:Connection = trusting(track(new Connection(__loop)));
		var echoed:Null<String> = null;
		client.onOpen = () -> client.sendText("over TLS");
		client.onText = text -> echoed = text;
		client.connect("wss://localhost:" + server.localPort + "/");
		Assert.isTrue(pump(() -> echoed != null, 10), "nothing came back over wss://");
		Assert.equals("over TLS", echoed);
	}

	public function testSecureWebSocketsCheckCertificates():Void {
		var server:Server = echoServer(true);
		var client:Connection = track(new Connection(__loop));
		var errors:Array<ConnectionError> = [];
		var closed:Int = -1;
		client.onError = (error, _) -> errors.push(error);
		client.onClose = (code, _) -> closed = code;
		client.connect("wss://127.0.0.1:" + server.localPort + "/");
		Assert.isTrue(pump(() -> closed != -1, 10), "the untrusted certificate was not reported");
		Assert.equals(1006, closed);
		Assert.equals(ConnectionError.CONNECT_FAILED, errors[0]);
	}

	#if (cpp || hl)
	public function testVerificationCanBeTurnedOff():Void {
		var server:Server = echoServer(true);
		var client:Connection = track(new Connection(__loop));
		// The certificate is for localhost, and self-signed
		client.verifyCertificates = false;
		var opened:Bool = false;
		client.onOpen = () -> opened = true;
		client.connect("wss://127.0.0.1:" + server.localPort + "/");
		Assert.isTrue(pump(() -> opened || !client.__hasTransport(), 10));
		Assert.isTrue(opened, "a server was checked with verification off");
	}
	#end

	public function testTlsConnectionsOutliveTheirServer():Void {
		var server:Server = echoServer(true);
		var client:Connection = trusting(track(new Connection(__loop)));
		var opened:Bool = false;
		var texts:Array<String> = [];
		client.onOpen = () -> opened = true;
		client.onText = text -> texts.push(text);
		client.connect("wss://localhost:" + server.localPort + "/");
		Assert.isTrue(pump(() -> opened, 10));

		// The listener's configuration freed: each connection holds its own
		server.close();
		client.sendText("still here");
		Assert.isTrue(pump(() -> texts.length == 1, 5), "a connection did not outlive its server");
		Assert.equals("still here", texts[0]);
	}

	#if hl
	public function testACollectionDoesNotWaitOnAStalledTlsServer():Void {
		// A server that takes the connection and never answers the TLS hello
		var listener:sys.net.Socket = new sys.net.Socket();
		listener.bind(new sys.net.Host("127.0.0.1"), 0);
		listener.listen(1);
		var port:Int = listener.host().port;

		var client:Connection = track(new Connection(__loop));
		client.verifyCertificates = false;
		client.connect("wss://127.0.0.1:" + port + "/", null, 0);
		var accepted:sys.net.Socket = listener.accept();
		// The client's thread is now waiting in its TLS handshake
		Sys.sleep(0.2);

		// With an ssl.hdll older than HashLink 1.16's, whose own reads do not
		// say they wait, the collector would wait for that thread until the
		// server answered, or here until it hangs up: TlsSocket's callbacks
		// are what keep it from waiting there. 1.16 marks its reads itself.
		sys.thread.Thread.create(() -> {
			Sys.sleep(3);
			try {
				accepted.close();
			} catch (_:Dynamic) {}
		});
		var started:Float = Timer.stamp();
		hl.Gc.major();
		var took:Float = Timer.stamp() - started;
		Assert.isTrue(took < 1.5, 'a collection waited $took s on a thread stuck in a TLS handshake');
		listener.close();
	}
	#end

	private function echoServer(secure:Bool):Server {
		var server:Server = trackServer(new Server(__loop));
		if (secure) {
			server.setCertificate(sys.ssl.Certificate.fromString(TestCertificate.CERTIFICATE), sys.ssl.Key.readPEM(TestCertificate.KEY, false));
		}
		server.maxMessageSize = 0;
		server.onConnection = connection -> {
			connection.onText = text -> connection.sendText(text);
			connection.onBinary = data -> connection.send(data, 0, data.length);
		};
		Assert.isTrue(server.listen(0, "127.0.0.1"), "the server did not listen: " + server.error);
		Assert.isTrue(server.listening);
		Assert.isTrue(server.localPort > 0);
		return server;
	}

	// A client that trusts the test certificate, for wss://localhost
	private function trusting(connection:Connection):Connection {
		connection.certificateAuthority = sys.ssl.Certificate.fromString(TestCertificate.CERTIFICATE);
		return connection;
	}

	private function track(connection:Connection):Connection {
		__connections.push(connection);
		return connection;
	}

	private function trackServer(server:Server):Server {
		__servers.push(server);
		return server;
	}

	private function pump(done:Void->Bool, seconds:Float = 5):Bool {
		var deadline:Float = Timer.stamp() + seconds;
		while (!done()) {
			if (Timer.stamp() >= deadline) {
				return false;
			}
			__loop.poll();
			Sys.sleep(0.001);
		}
		return true;
	}

	private static function pattern(length:Int, seed:Int):Bytes {
		var bytes:Bytes = Bytes.alloc(length);
		for (i in 0...length) {
			bytes.set(i, (i * 131 + seed * 7) & 0xFF);
		}
		return bytes;
	}
}
#end

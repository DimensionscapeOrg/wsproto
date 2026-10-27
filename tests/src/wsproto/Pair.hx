package wsproto;

import haxe.io.Bytes;

/**
	A client and a server session wired back to back: `pump` carries what
	each has sent to the other until neither has anything left to say.
	`chunk` cuts what is carried into pieces that long, as a network might.
**/
class Pair {
	public var client:TestHost;
	public var server:TestHost;
	public var chunk:Int = 0;

	public function new(?protocols:Array<String>, ?configure:TestHost->TestHost->Void) {
		client = new TestHost("ws://example.com:8080/chat", protocols);
		server = new TestHost();
		if (configure != null) {
			configure(client, server);
		}
		client.start();
	}

	public function pump():Void {
		var moved:Bool = true;
		while (moved) {
			moved = carry(client, server);
			moved = carry(server, client) || moved;
		}
	}

	public static function opened(?protocols:Array<String>, ?configure:TestHost->TestHost->Void):Pair {
		var pair:Pair = new Pair(protocols, configure);
		pair.pump();
		return pair;
	}

	private function carry(from:TestHost, to:TestHost):Bool {
		if (from.sent.length == 0) {
			return false;
		}
		var bytes:Bytes = from.takeSent();
		if (chunk <= 0) {
			to.receive(bytes);
		} else {
			var at:Int = 0;
			while (at < bytes.length) {
				var length:Int = bytes.length - at < chunk ? bytes.length - at : chunk;
				to.receive(bytes, at, length);
				at += length;
			}
		}
		return true;
	}
}

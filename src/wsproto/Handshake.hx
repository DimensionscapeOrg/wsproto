package wsproto;

import haxe.crypto.Base64;
import haxe.crypto.Sha1;
import haxe.ds.StringMap;
import haxe.io.Bytes;

/**
	The opening handshake (RFC 6455 4): the HTTP/1.1 upgrade request a
	client sends, the answers a server gives it, and how each side reads
	the other's head.
**/
class Handshake {
	/** The GUID a key is hashed with into `Sec-WebSocket-Accept` (RFC 6455 1.3). **/
	public static inline var GUID:String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	/** The only version of the protocol, as `Sec-WebSocket-Version` names it. **/
	public static inline var VERSION:String = "13";

	private static inline var CRLF:String = "\r\n";
	private static inline var CRLFCRLF:String = "\r\n\r\n";

	/** What a server answers `key` with in `Sec-WebSocket-Accept`. **/
	public static function accept(key:String):String {
		return Base64.encode(Sha1.make(Bytes.ofString(key + GUID)));
	}

	/**
		A client's upgrade request for `path` on `host` and `port`, asking for
		`protocols` (none for null or empty) and `extensions` (none for null),
		with `key` for the server to answer.
	**/
	public static function clientRequest(path:String, host:String, port:Int, key:String, origin:String, ?protocols:Array<String>,
			?extensions:String):Bytes {
		var headers:Array<String> = [
			'GET ${path} HTTP/1.1',
			// Bracketed when it is an IPv6 literal, as RFC 3986 writes one.
			'Host: ${urlHost(host)}:${port}',
			'Pragma: no-cache',
			'Cache-Control: no-cache',
			'Upgrade: websocket',
			'Sec-WebSocket-Version: 13',
			'Connection: Upgrade',
			"Sec-WebSocket-Key: " + key,
			'Origin: ${origin}',
			'User-Agent: Mozilla/5.0'
		];

		if (protocols != null && protocols.length > 0) {
			headers.insert(5, 'Sec-WebSocket-Protocol: ' + protocols.join(', '));
		}

		if (extensions != null) {
			headers.push('Sec-WebSocket-Extensions: ' + extensions);
		}

		return Bytes.ofString(headers.join(CRLF) + CRLFCRLF);
	}

	/**
		A server's `101` for the request that sent `key`, echoing the
		subprotocol accepted (none for null) and the extensions agreed (none
		for null).
	**/
	public static function serverResponse(key:String, ?protocol:String, ?extensions:String):Bytes {
		var lines:Array<String> = [
			"HTTP/1.1 101 Switching Protocols",
			"Upgrade: websocket",
			"Connection: Upgrade",
			"Sec-WebSocket-Accept: " + accept(key)
		];

		// The subprotocol accepted, echoed: a browser that offered one
		// and hears none back fails the connection outright.
		if (protocol != null) {
			lines.push("Sec-WebSocket-Protocol: " + protocol);
		}

		if (extensions != null) {
			lines.push("Sec-WebSocket-Extensions: " + extensions);
		}

		return Bytes.ofString(lines.join(CRLF) + CRLFCRLF);
	}

	/**
		A server's refusal of an upgrade, with `status`, the connection
		closing after it, and any `extraHeaders` (whole lines).
	**/
	public static function refusal(status:Int, ?extraHeaders:Array<String>):Bytes {
		var lines:Array<String> = ['HTTP/1.1 $status ${statusText(status)}', "Connection: close", "Content-Length: 0"];
		if (extraHeaders != null) {
			for (line in extraHeaders) {
				lines.push(line);
			}
		}

		return Bytes.ofString(lines.join(CRLF) + CRLFCRLF);
	}

	/** The reason phrase a refusal's status line gives `status`. **/
	public static function statusText(status:Int):String {
		return switch (status) {
			case 400: "Bad Request";
			case 401: "Unauthorized";
			case 403: "Forbidden";
			case 404: "Not Found";
			case 426: "Upgrade Required";
			case 429: "Too Many Requests";
			case 431: "Request Header Fields Too Large";
			case 500: "Internal Server Error";
			case 503: "Service Unavailable";
			default: "Refused";
		}
	}

	/**
		Where the blank line ending a head starts in `bytes`, searched from
		`start` to `end`, or -1 if it has not arrived.
	**/
	public static function findHeaderEnd(bytes:Bytes, start:Int, end:Int):Int {
		var last:Int = end - 3;
		var i:Int = start;
		while (i < last) {
			if (bytes.get(i) == 13 && bytes.get(i + 1) == 10 && bytes.get(i + 2) == 13 && bytes.get(i + 3) == 10) {
				return i;
			}
			i++;
		}
		return -1;
	}

	/**
		The header lines of a head, after its first, by lower-cased name: a
		header sent more than once folded into one value.
	**/
	public static function parseHeaderLines(lines:Array<String>):StringMap<String> {
		var headers:StringMap<String> = new StringMap();

		// Skip the first line, since it contains the request method or status code
		for (i in 1...lines.length) {
			var line:String = lines[i];

			// Check if this is the end of the headers
			if (line == "") {
				break;
			}

			// Split the header into name and value
			var index:Int = line.indexOf(":");
			if (index != -1) {
				var name:String = line.substring(0, index).toLowerCase();
				var value:String = StringTools.trim(line.substring(index + 1));

				// A header sent twice is both its values, folded as HTTP folds
				// them, rather than the second one alone: a client may offer its
				// subprotocols on two lines.
				var earlier:Null<String> = headers.get(name);
				if (earlier != null) {
					value = earlier + (name == "cookie" ? "; " : ", ") + value;
				}

				headers.set(name, value);
			}
		}

		return headers;
	}

	/**
		Whether `headers`, a client's, ask for a WebSocket this side speaks:
		an upgrade to `websocket`, a key, and version 13.
	**/
	public static function isValidRequest(headers:StringMap<String>):Bool {
		var upgrade:String = headers.get("upgrade");
		var connection:String = headers.get("connection");
		var key:String = headers.get("sec-websocket-key");
		var version:String = headers.get("sec-websocket-version");

		if (upgrade == null || upgrade.toLowerCase() != "websocket") {
			return false;
		}
		if (connection == null || connection.toLowerCase().indexOf("upgrade") == -1) {
			return false;
		}
		if (key == null || key.length == 0) {
			return false;
		}
		if (version != VERSION) {
			return false;
		}

		return true;
	}

	/**
		`host` as a URL and a `Host` header write it: an IPv6 literal in
		brackets, anything else as it is.
	**/
	public static inline function urlHost(host:String):String {
		return host != null && host.indexOf(":") >= 0 ? "[" + host + "]" : host;
	}
}

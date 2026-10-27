package wsproto;

import haxe.ds.StringMap;

/**
	The permessage-deflate extension (RFC 7692) as a session agrees to it:
	each message compressed on its own, in both directions, since neither
	end keeps a compressor's window from one message to the next.

	This is the negotiation. The compressing is the host's, with whatever
	DEFLATE its platform has; see `Session.__inflateIncoming` and
	`Session.__compress`.
**/
class PerMessageDeflate {
	/** The extension named in the handshake. **/
	public static inline var NAME:String = "permessage-deflate";

	/**
		What a session offers, or answers an offer with: no context takeover
		either way.
	**/
	public static inline var PARAMETERS:String = "server_no_context_takeover; client_no_context_takeover";

	/** A client's offer, whole. **/
	public static inline var OFFER:String = NAME + "; " + PARAMETERS;

	/**
		The extensions a `Sec-WebSocket-Extensions` value lists, each with its
		parameters, in order; null when the value does not parse, or names a
		parameter twice.
	**/
	public static function parse(value:String):Null<Array<{name:String, params:StringMap<Null<String>>}>> {
		var parsed:Array<{name:String, params:StringMap<Null<String>>}> = [];
		for (item in value.split(",")) {
			var parts:Array<String> = item.split(";");
			var name:String = StringTools.trim(parts[0]).toLowerCase();
			if (name == "") {
				return null;
			}

			var params:StringMap<Null<String>> = new StringMap();
			for (i in 1...parts.length) {
				var part:String = StringTools.trim(parts[i]);
				if (part == "") {
					return null;
				}
				var equals:Int = part.indexOf("=");
				var key:String = StringTools.trim(equals < 0 ? part : part.substr(0, equals)).toLowerCase();
				var setting:Null<String> = equals < 0 ? null : StringTools.trim(part.substr(equals + 1));
				if (setting != null && setting.length >= 2 && StringTools.startsWith(setting, "\"") && StringTools.endsWith(setting, "\"")) {
					setting = setting.substr(1, setting.length - 2);
				}
				if (key == "" || params.exists(key)) {
					return null;
				}
				params.set(key, setting);
			}
			parsed.push({name: name, params: params});
		}
		return parsed;
	}

	/** Whether `setting` is a window size RFC 7692 allows: 8 to 15 bits. **/
	public static function isWindowBits(setting:Null<String>):Bool {
		if (setting == null) {
			return false;
		}
		var bits:Int = Decimal.parse(setting, 15);
		return bits >= 8;
	}

	/**
		A server's answer to a client's offers, in the client's order of
		preference: the first permessage-deflate offer this side can keep,
		answered, or null for none. An offer that would narrow this side's
		window is passed over (its compressor looks back the whole 32 KB),
		and so is one naming a parameter this side does not know.

		The answer says `server_no_context_takeover`, so the client inflates
		each message on its own, and what the server sends may go
		compressed.
	**/
	public static function answer(offered:String):Null<String> {
		var offers = parse(offered);
		if (offers == null) {
			return null;
		}

		for (offer in offers) {
			if (offer.name != NAME) {
				continue;
			}

			var keepable:Bool = true;
			var windowAsked:Bool = false;
			for (key in offer.params.keys()) {
				var setting:Null<String> = offer.params.get(key);
				switch (key) {
					case "server_no_context_takeover", "client_no_context_takeover":
						keepable = keepable && setting == null;
					case "server_max_window_bits":
						windowAsked = true;
						keepable = keepable && setting == "15";
					case "client_max_window_bits":
						// A client that may be told to narrow its window; this
						// side inflates any, and tells it nothing.
						keepable = keepable && (setting == null || isWindowBits(setting));
					default:
						keepable = false;
				}
			}

			if (keepable) {
				return '$NAME; $PARAMETERS' + (windowAsked ? "; server_max_window_bits=15" : "");
			}
		}
		return null;
	}

	/** `answerTaken`: the server's answer cannot be kept, and the connection fails. **/
	public static inline var REFUSED:Int = -1;

	/** `answerTaken`: kept; what arrives is inflated, and what is sent goes as it is. **/
	public static inline var RECEIVE:Int = 0;

	/** `answerTaken`: kept both ways. **/
	public static inline var BOTH:Int = 1;

	/**
		A server's answer to this client's offer, taken if this side can keep
		it: permessage-deflate alone, without context takeover on the
		server's side (this side inflates each message on its own), and
		with nothing asked of this side's compressor but its full window.

		What this side sends goes compressed only where the server said
		`client_no_context_takeover` too. Each message compressed here ends
		its DEFLATE stream (RFC 7692 7.2.3.4): a server inflating every
		message on its own reads that like any other, but one keeping a
		single stream across messages, as it may without that parameter,
		would lose every message after the first. Without it this side sends
		uncompressed, which RFC 7692 allows of any message, and still
		inflates what arrives.

		Answers `REFUSED`, `RECEIVE` or `BOTH`.
	**/
	public static function answerTaken(value:String):Int {
		var answered = parse(value);
		if (answered == null || answered.length != 1 || answered[0].name != NAME) {
			return REFUSED;
		}

		var params:StringMap<Null<String>> = answered[0].params;
		if (!params.exists("server_no_context_takeover")) {
			return REFUSED;
		}
		for (key in params.keys()) {
			var setting:Null<String> = params.get(key);
			switch (key) {
				case "server_no_context_takeover", "client_no_context_takeover":
					if (setting != null) {
						return REFUSED;
					}
				case "server_max_window_bits":
					// Any window: this side keeps a whole one to inflate into.
					if (!isWindowBits(setting)) {
						return REFUSED;
					}
				case "client_max_window_bits":
					// This side's compressor looks back the whole 32 KB.
					if (setting != "15") {
						return REFUSED;
					}
				default:
					return REFUSED;
			}
		}

		return params.exists("client_no_context_takeover") ? BOTH : RECEIVE;
	}
}

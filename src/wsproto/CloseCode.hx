package wsproto;

/**
	The codes a close frame carries (RFC 6455 7.4).
**/
class CloseCode {
	public static inline var NORMAL:Int = 1000;
	public static inline var GOING_AWAY:Int = 1001;
	public static inline var PROTOCOL_ERROR:Int = 1002;
	public static inline var UNSUPPORTED_DATA:Int = 1003;

	/** Reported when a close frame carried no code; never sent. **/
	public static inline var NO_STATUS:Int = 1005;

	/** Reported when the connection ended without a close frame; never sent. **/
	public static inline var ABNORMAL:Int = 1006;

	public static inline var INVALID_DATA:Int = 1007;
	public static inline var POLICY_VIOLATION:Int = 1008;
	public static inline var MESSAGE_TOO_BIG:Int = 1009;
	public static inline var MANDATORY_EXTENSION:Int = 1010;
	public static inline var INTERNAL_ERROR:Int = 1011;

	/** Reported when the TLS handshake failed; never sent. **/
	public static inline var TLS_HANDSHAKE:Int = 1015;

	/**
		Whether `code` may travel in a close frame.

		The ranges carry the rule, not just the handful of holes inside them:
		1000-2999 belongs to the protocol and only the assigned part of it may
		travel, 3000-3999 is for libraries and 4000-4999 is private. A peer
		closing with 1016, 2000 or 65535, none of which mean anything, is
		answered 1002.
	**/
	public static inline function isValid(code:Int):Bool {
		if (code >= 3000 && code <= 4999) {
			return true;
		}
		if (code < 1000 || code > 1014) {
			return false;
		}
		// 1004 was never assigned; 1005 and 1006 are what a local close
		// reports when no code arrived, so neither may appear on the wire.
		// 1015 is the same kind of code and is already past the bound above.
		return code != 1004 && code != 1005 && code != 1006;
	}
}

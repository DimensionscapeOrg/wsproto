package wsproto;

/**
	A frame's opcode (RFC 6455 5.2): the low four bits of its first byte.
**/
enum abstract Opcode(Int) from Int to Int {
	public static inline var CONTINUATION:Int = 0x00;
	public static inline var TEXT:Int = 0x01;
	public static inline var BINARY:Int = 0x02;
	public static inline var CLOSE:Int = 0x08;
	public static inline var PING:Int = 0x09;
	public static inline var PONG:Int = 0x0A;
}

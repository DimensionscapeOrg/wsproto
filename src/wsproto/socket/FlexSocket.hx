package wsproto.socket;

#if (cpp || hl || neko)
import haxe.io.Error;
import haxe.io.Input;
import haxe.io.Output;
import sys.net.Host;
import sys.net.Socket;
#if (cpp || hl || neko)
import sys.ssl.Certificate;
import sys.ssl.Key;
#end

typedef HostInfo = {port:Int, host:Host};
typedef Sockets = {write:Array<Socket>, read:Array<Socket>, others:Array<Socket>};

/**
	A TCP socket, plain or TLS, as one type: CrossByte's `FlexSocket`.

	Over `sys.net.Socket`, which every TLS socket extends, rather than
	`EitherType<Socket, sys.ssl.Socket>`, which is `Dynamic` underneath: every
	forwarded call would convert it back to a `Socket`, natively a type check
	per call. A secure one is a `TlsSocket`, the standard library's TLS socket
	with what it gets wrong on HashLink, Neko and hxcpp put right.

	Built for hxcpp, HashLink and Neko: the JVM's and the interpreter's
	standard sockets cannot be made non-blocking, which the socket layer
	needs.
**/
@:forward
abstract FlexSocket(Socket) from Socket to Socket #if (cpp || hl || neko) from TlsSocket #end {
	/** Whether this target has TLS: `new FlexSocket(true)` succeeds. **/
	public static inline var tlsSupported:Bool = #if (cpp || hl || neko) true #else false #end;

	public static function select(read:Array<FlexSocket>, write:Array<FlexSocket>, others:Array<FlexSocket>, ?timeout:Float):Sockets {
		return Socket.select(cast read, cast write, cast others, timeout);
	}

	/**
		Whether `error` means the operation would have blocked: a non-blocking
		socket with a full send buffer, or nothing yet to read, says so four
		ways across the targets. As `haxe.io.Error.Blocked`; wrapped in
		`Error.Custom` by the hxcpp debugger; and as the bare strings
		`"Blocking"` or `"Blocked"` from the TLS layer, which throws before the
		error is mapped to a type. A would-block mistaken for a failure closes
		a healthy connection, and a failure mistaken for a would-block
		silently drops what was being written.
	**/
	public static function isBlocked(error:Dynamic):Bool {
		if (error == null) {
			return false;
		}
		if (Std.isOfType(error, Error)) {
			return switch ((error : Error)) {
				// Custom wraps the underlying value, which may itself be
				// either a nested Error or one of the string forms.
				case Custom(value): isBlocked(value);
				case Blocked: true;
				default: false;
			}
		}
		var text:String = Std.string(error);
		return text == "Blocking" || text == "Blocked";
	}

	private static inline function __requireTLS(field:String, instance:FlexSocket):Void {
		if (!instance.isSecure) {
			throw '$field::Field only available when using a secure socket';
		}
	}

	public var custom(get, set):Dynamic;

	public var input(get, never):Input;

	public var isSecure(get, never):Bool;

	public var output(get, never):Output;

	#if (cpp || hl || neko)
	public var verifyCert(get, set):Null<Bool>;
	#end

	public inline function new(secure:Bool = false) {
		if (secure) {
			#if (cpp || hl || neko)
			this = new TlsSocket();
			#else
			throw "TLS is not available on this target";
			#end
		} else {
			this = new Socket();
		}
	}

	private inline function get_custom():Dynamic {
		return this.custom;
	}

	private inline function set_custom(value:Dynamic):Dynamic {
		return this.custom = value;
	}

	private inline function get_input():Input {
		return this.input;
	}

	private inline function get_isSecure():Bool {
		#if (cpp || hl || neko)
		return Std.isOfType(this, sys.ssl.Socket);
		#else
		return false;
		#end
	}

	private inline function get_output():Output {
		return this.output;
	}

	public inline function accept():Socket {
		return this.accept();
	}

	public inline function bind(host:String, port:Int):Void {
		this.bind(new Host(host), port);
	}

	public inline function close():Void {
		this.close();
	}

	/**
		Connects to `host`, looking it up first if it is a name: here, on the
		calling thread, for as long as the resolver takes.
	**/
	public inline function connect(host:String, port:Int):Void {
		this.connect(new Host(host), port);
	}

	/** Connects to an address already resolved. **/
	public inline function connectHost(host:Host, port:Int):Void {
		this.connect(host, port);
	}

	public inline function host():HostInfo {
		return this.host();
	}

	public inline function listen(connections:Int = 0):Void {
		// Past what any system grants, and within neko's 31-bit Int, which
		// the largest Int is not.
		if (connections == 0)
			connections = 0x7FFFFFF;
		this.listen(connections);
	}

	public inline function peer():HostInfo {
		return this.peer();
	}

	public inline function setBlocking(value:Bool):Void {
		this.setBlocking(value);
	}

	public inline function setFastSend(value:Bool):Void {
		this.setFastSend(value);
	}

	public inline function setTimeout(value:Float):Void {
		this.setTimeout(value);
	}

	public inline function shutdown(read:Bool, write:Bool):Void {
		this.shutdown(read, write);
	}

	#if (cpp || hl || neko)
	private inline function get_verifyCert():Null<Bool> {
		__requireTLS("verifyCert", this);
		return (cast this : sys.ssl.Socket).verifyCert;
	}

	private inline function set_verifyCert(value:Null<Bool>):Null<Bool> {
		__requireTLS("verifyCert", this);
		return (cast this : sys.ssl.Socket).verifyCert = value;
	}

	public inline function addSNICertificate(cbServernameMatch:String->Bool, cert:Certificate, key:Key):Void {
		__requireTLS("addSNICertificate", this);
		(cast this : sys.ssl.Socket).addSNICertificate(cbServernameMatch, cert, key);
	}

	public inline function handshake():Void {
		__requireTLS("handshake", this);
		(cast this : sys.ssl.Socket).handshake();
	}

	public inline function peerCertificate():Certificate {
		__requireTLS("peerCertificate", this);
		return (cast this : sys.ssl.Socket).peerCertificate();
	}

	public inline function setCA(cert:Certificate):Void {
		__requireTLS("setCA", this);
		(cast this : sys.ssl.Socket).setCA(cert);
	}

	public inline function setCertificate(cert:Certificate, key:Key):Void {
		__requireTLS("setCertificate", this);
		(cast this : sys.ssl.Socket).setCertificate(cert, key);
	}

	public inline function setHostname(name:String):Void {
		__requireTLS("setHostname", this);
		(cast this : sys.ssl.Socket).setHostname(name);
	}
	#end
}
#end

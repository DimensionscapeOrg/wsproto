package wsproto.socket;

#if (cpp || hl || neko)
import haxe.Timer;

/**
	What a host polls: every `Connection` and `Server` made on it, read,
	written and timed as `poll` is called. A loop belongs to one thread,
	the one that polls it; `shared` is for a host with one.

	Nothing runs between polls, so how often a host polls is how soon what
	arrives is delivered: once a frame, for an application drawing frames.
**/
class Loop {
	/** A loop for a host that has one thread for its connections. **/
	public static var shared(get, null):Loop;

	private var __connections:Array<Connection> = [];
	private var __servers:Array<Server> = [];

	#if target.threaded
	// Connects given up on while their thread was still connecting: what
	// each opens is closed once it arrives.
	private var __abandoned:Array<sys.thread.Deque<Dynamic>> = [];
	#end

	public function new() {}

	private static function get_shared():Loop {
		if (shared == null) {
			shared = new Loop();
		}
		return shared;
	}

	/** Whether there is anything to poll. **/
	public var active(get, never):Bool;

	private function get_active():Bool {
		#if target.threaded
		if (__abandoned.length > 0) {
			return true;
		}
		#end
		return __connections.length > 0 || __servers.length > 0;
	}

	/**
		Takes what every server has accepted, then reads what every connection
		has, hands it to its session, writes what waits to go, and fires what
		is due: a deadline, a heartbeat. Callbacks run here, on this thread.
	**/
	public function poll():Void {
		if (__servers.length > 0) {
			for (server in __servers.copy()) {
				@:privateAccess server.__accept();
			}
		}

		#if target.threaded
		if (__abandoned.length > 0) {
			for (dial in __abandoned.copy()) {
				var result:Dynamic = dial.pop(false);
				if (result == null) {
					continue;
				}
				__abandoned.remove(dial);
				if (Std.isOfType(result, sys.net.Socket)) {
					try {
						(result : sys.net.Socket).close();
					} catch (_:Dynamic) {}
				}
			}
		}
		#end

		if (__connections.length == 0) {
			return;
		}

		var now:Float = Timer.stamp();
		for (connection in __connections.copy()) {
			@:privateAccess connection.__poll(now);
		}
	}
}
#end

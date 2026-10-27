package wsproto;

/**
	A non-negative decimal read from text, bounded as it is read:
	`Std.parseInt` answers a number too big for an Int differently on every
	target (its low 32 bits on Linux native, the largest Int on Windows, an
	exception on the jvm, nothing at all on eval), so a port past 65535
	would become some other port, or the default, depending where it ran.
**/
@:noCompletion
class Decimal {
	/** `text` as a decimal no greater than `max`, or -1. **/
	public static function parse(text:String, max:Int = 0x7FFFFFFF):Int {
		if (text == null || text.length == 0 || max < 0) {
			return -1;
		}

		// The classic strtol bound: past `cutoff`, or at it with a digit past
		// `cutlim`, the next step would exceed `max`. One division, before the
		// loop, and no intermediate ever leaves the range of an Int.
		final cutoff:Int = Std.int(max / 10);
		final cutlim:Int = max - cutoff * 10;
		var value:Int = 0;
		for (i in 0...text.length) {
			final digit:Int = StringTools.fastCodeAt(text, i) - 48;
			if (digit < 0 || digit > 9) {
				return -1;
			}
			if (value > cutoff || (value == cutoff && digit > cutlim)) {
				return -1;
			}
			value = value * 10 + digit;
		}
		return value;
	}
}

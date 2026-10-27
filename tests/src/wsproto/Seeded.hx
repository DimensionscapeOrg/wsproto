package wsproto;

/**
	The tests' random numbers: a linear congruential generator, seeded, so a
	red run repeats.

	Stepped in 64 bits. In 32 the multiply overflows, which C++ leaves
	undefined, and clang, taking it never to, dropped the mask that keeps the
	state positive: on macOS the fuzz drew negative lengths and looped for
	good. In 64 bits nothing overflows, and the low 31 bits are what every
	other target computed.
**/
class Seeded {
	public static function step(state:Int):Int {
		return haxe.Int64.toInt((haxe.Int64.ofInt(state) * 1103515245 + 12345) & 0x7FFFFFFF);
	}
}

# wsproto

The WebSocket protocol without its connection: RFC 6455's opening handshake,
framing and closing handshake, and RFC 7692's permessage-deflate agreed in the
handshake, for client and server sessions. It is Haxe, depends on nothing but
the standard library, and builds for every target: hxcpp, HashLink, Neko, the
JVM, Node.js and the interpreter.

It moves no bytes. A host (a runtime, a framework, an application) owns the
socket, TLS, threads and timers, and hands each session what arrives; the
session hands back what to send. CrossByte's WebSocket is one host and Lime's
`lime.net.WebSocket` another, so the two speak the protocol the same way,
from the same code.

## Two layers

**Primitives.** Static functions on `haxe.io.Bytes`, allocating nothing:

- `Frame`: a frame's header, written; masking, in place or as a payload is
  copied into a frame.
- `Utf8`: strict validation, as a text message and a close reason are
  checked, and well-formed encoding.
- `CloseCode`: which codes may travel.
- `Handshake`: the client's request, the server's `101` and its refusals,
  `Sec-WebSocket-Accept`, and reading a head.
- `PerMessageDeflate`: an offer, and the answers each side can keep.

**`Session`.** One session, either end, as a class a host extends:

- the opening handshake, read where it lands, with `maxHeaderSize`
- frames checked on their header (reserved bits, masking, opcodes,
  control-frame limits, `maxMessageSize`), before anything waits for a
  payload
- messages assembled in storage the host gives, unmasked in place, checked
  as UTF-8 where they are text
- pings answered (the newest only, where they arrive faster than they go),
  and the closing handshake, with the codes RFC 6455 has each side report
- what is sent, framed in fragments of at most 64 KiB, and masked on a client
- the heartbeat's decisions: when to ping a quiet peer, and when to give up
  on a silent one

## Using it

```sh
haxelib install wsproto
```

For development, clone this repository and register it:

```sh
haxelib dev wsproto /path/to/wsproto
```

A host extends `Session`, and:

- **while connecting**, hands what has arrived to `__findHead`, and the
  head it finds to `__takeHead`; a client starts with `__client(url)` and
  `__doHandshake()`
- **once open**, hands each frame to `__frameHeader`, then to
  `__controlFrame` or `__dataFrame`, from wherever its reads put the bytes
- **overrides the hooks** for what only it can do: `__sendFrameOf` and
  `__writeBytes` to send, `__messageBegin`, `__roomForMessage`, `__message`
  and `__dispatchMessage` to keep and deliver a message, `__close` to end the
  connection, `__scheduleHeartbeat` for its timer, and `__randomBytes` for a
  client's key

`Session`'s documentation says what each hook is owed. The tests' `TestHost`
is a whole host in two hundred lines.

## Testing

```sh
cd tests
haxe interp.hxml
haxe neko.hxml && neko ../export/tests.n
haxe hl.hxml && hl ../export/tests.hl
haxe jvm.hxml && java -jar ../export/tests.jar
haxe js.hxml && node ../export/tests.js
haxe cpp.hxml && ../export/cpp/TestMain
```

The suite runs RFC 6455's examples, two sessions back to back through every
part of the protocol, every way a peer can break it, and a seeded fuzz of
malformed frames after a real handshake.

## License

Apache-2.0. See [LICENSE](LICENSE).

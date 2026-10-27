# wsproto

The WebSocket protocol: RFC 6455's opening handshake, framing and closing
handshake, and RFC 7692's permessage-deflate agreed in the handshake, for
client and server sessions; and `ws://` and `wss://` clients and servers over
Haxe's own sockets, for a host that has none of its own. It is Haxe, depends
on nothing but the standard library, and belongs to no framework.

A host with its own sockets, TLS, threads and timers (CrossByte's runtime)
uses the protocol alone, and hands each session what arrives; the session
hands back what to send. A host without them (Lime) uses the socket layer,
and polls it from its loop. Either way the protocol is the same code.

## Three layers

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

**`wsproto.socket`: clients and servers.** For hxcpp, HashLink and Neko,
whose standard sockets can be made non-blocking:

- `Connection`: a client (`connect("wss://...")`) or a connection a server
  accepted, with callbacks for opening, messages, errors and the close, a
  send limit (`maxQueuedBytes`), and the heartbeat.
- `Server`: plain or TLS (`setCertificate`, `addSNICertificate`), with
  subprotocol preference and an opening-handshake deadline.
- `Loop`: what a host polls, once a frame or as often as it likes. A
  client's lookup, connect and TLS handshake run on a thread of their own,
  so a poll never waits on the network.
- `FlexSocket` and `TlsSocket`: CrossByte's plain-or-TLS socket, and the
  standard library's TLS socket with what it gets wrong put right: each
  connection a TLS server accepts gets a configuration of its own, so it
  outlives the server's `close()`, and on HashLink before 1.16 a client's
  TLS reads tell the collector they wait.

A client's masks and key come from `Connection.random`, which a host sets to
its platform's secure source; Haxe's standard library has none.
`/dev/urandom` is read where it is not set.

Neko's TLS checks a server's certificate however `verifyCertificates` is set:
trust a server's own certificate through `certificateAuthority` there.

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

Or, with no transport of its own:

```haxe
var client = new wsproto.socket.Connection();
client.onOpen = () -> client.sendText("hello");
client.onText = text -> trace(text);
client.onClose = (code, reason) -> trace('closed $code');
client.connect("wss://example.com/chat");

// From the host's loop:
wsproto.socket.Loop.shared.poll();
```

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
malformed frames after a real handshake. On hxcpp, HashLink and Neko it also
runs clients and servers over loopback sockets, plain and TLS.

## License

Apache-2.0. See [LICENSE](LICENSE).

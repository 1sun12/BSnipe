# BSnipe

> `BSnipe` is a CLI packet-sniffer written by me (1sun12) in C using the Linux Sockets API.
> Must be ran using `sudo` or it will not work!

**I am not responsible for what anyone does with this tool if you download and experiment with it**, not compatible with Windows.

You are free to fork or copy my works for educational purposes! I only ask that you credit me :] !

`VERSION 1001` was written over the course of (2) weeks; roughly +(40) hours total.

Present day is probably over +(100) hours of total research and work.

Resources used at bottom (I started with these first before starting).

## Why should I install and use this when WireShark exist?

It's light weight and can me embedded into very small spaces.

It also produces a full .pcap output, which can then be imported into WireShark.

## Installing

1. Clone this repository
2. From the project root, run `make` to build it
3. This creates the binary at `bin/packet_sniffer`
4. Type `sudo ./bin/packet_sniffer` to run it

> There is also `sudo make run`, but be aware it cleans up after itself and deletes the binary once you exit.

## How to Use

> Pressing `Enter` after typing a character is assumed for each option

1. Press `s` to start, `s` again to stop
2. Press `o` for options (configure the sniffer)
3. Press `e` to exit (only on home menu)
4. Press `b` to go back from the options menu to the home menu
5. To turn `TCP` to `true`, you would type `1t` as an example
6. File output is off by default, can be set to `true` in `options`

### Dump Options

Each captured packet can be dumped two different ways, and they are independent; you can have both
on, one, or neither.

| Option | What it does |
| --- | --- |
| `[5] Full frame dump` | The entire ethernet frame, headers and all. Off by default |
| `[6] Payload dump` | Only what is riding behind the headers. On by default |
| `[7] Frame hex to frames.txt` | Writes every frame as `text2pcap`-ready hex. Off by default |
| `[8] Write capture.pcap` | Writes a real `.pcap` capture file. Off by default |

Options `[5]` and `[6]` print to wherever `[3]` and `[4]` are pointing. Options `[7]` and `[8]` each
write their own file and nothing else goes in them, which is what keeps them readable by other tools.

### Opening a Capture in WireShark

`[3] Output to file` writes `dump.txt` for a human to read, so the MAC/IP/Port lines sit in between
the hex and no other tool can parse it. `[8]` exists for that job instead:

1. Turn on `[8]` in `options`
2. Capture for a while, then stop with `s`
3. Open what you caught:

```
wireshark capture.pcap
```

That is it, there is no conversion step. `capture.pcap` is a genuine libpcap file, so `tcpdump -r
capture.pcap` and `tshark -r capture.pcap` read it just as happily.

> Heads up: `[8]` truncates `capture.pcap` every time you start a new capture, so move the file
> somewhere safe if you want to keep it.

### Pasting Into an Online Decoder

If you would rather not open WireShark at all, `[7]` writes the same frames out as plain hex:

```
000000  bc 9b 68 fb 90 8a 60 18 95 41 a2 ad 08 00 45 00
000010  00 4b 1c 2e 40 00 40 06 00 00 c0 a8 00 7d 22 6b
000020  f3 5d d2 28 01 bb
```

That pastes straight into any online packet decoder. It is also what `text2pcap` eats, if you ever
want the conversion route:

```
text2pcap frames.txt out.pcap
```

## Future Plans

If I ever come back to this project to flesh it out some more, here are some ideas I would love to add from my backlog:

- `Monitor Mode` sniffing; captures A LOT more data
- ~~Exports everything in `.pcap` format, make it cross compatible with `WireShark` and `tcpdump`~~
  **Done!** Option `[8]` writes a real `.pcap` (see above), and `[7]` covers the `text2pcap` route

## Resources

- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [Effective C](https://www.amazon.com/Effective-Introduction-Professional-Robert-Seacord/dp/1718501048)
- [Pack. Sniff. in C from Scratch Youtube Tutorial](https://www.youtube.com/watch?v=1Quv19IVFsc&t=566s)

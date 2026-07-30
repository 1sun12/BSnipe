# BSnipe

> `BSnipe` is a CLI packet-sniffer written by me (1sun12) in C using the Linux Sockets API.
> Must be ran using `sudo` or it will not work!

**I am not responsible for what anyone does with this tool if you download and experiment with it**, not compatible with Windows.

You are free to fork or copy my works for educational purposes! I only ask that you credit me :] !

`VERSION 1001` was written over the course of (2) weeks; roughly +(40) hours total.

I think originality in my work is very important; this entire project was hand-typed C in my conquest to learn networking better. 
Use of A.I. was only used at the end for polish and catching unforseen bugs. ("Make the CLI look pretty", "Can you catch any memory leaks?").

Resources used at bottom (I started with these first before starting).

## Installing

1. Clone this repository
2. Head on over to `/bin`
3. Inside you will find an already compiled Linux Binary
4. type `sudo ./packet_sniffer`

## How to Use

> Pressing `Enter` after typing a character is assumed for each option

1. Press `s` to start, `s` again to stop
2. Press `o` for options (configure the sniffer)
3. Press `e` to exit (only on home menu)
4. Press `b` to go back from the options menu to the home menu
5. To turn `TCP` to `true`, you would type `1t` as an example
6. File output is off by default, can be set to `true` in `options`

## Future Plans

If I ever come back to this project to flesh it out some more, here are some ideas I would love to add from my backlog:

- `Monitor Mode` sniffing; captures A LOT more data
- Exports everything in `.pcap` format, make it cross compatible with `WireShark` and `tcpdump`

## Resources

- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [Effective C](https://www.amazon.com/Effective-Introduction-Professional-Robert-Seacord/dp/1718501048)
- [Pack. Sniff. in C from Scratch Youtube Tutorial](https://www.youtube.com/watch?v=1Quv19IVFsc&t=566s)

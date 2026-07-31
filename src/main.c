/*
==================================================
HEADERS
==================================================
*/
#include "debug.h"
#include "sock.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "payl.h"
#include "cli.h"
#include "output.h"
#include "pcapw.h"

/*
==================================================
MAIN
==================================================
*/
int main(void) {
    OUTPUT_D_MSG("~ MAIN EXECUTION STARTING ~");

    ssize_t brvd = 0;
    char input[16];
    int exit_code = EXIT_SUCCESS;

    // ~ Testing: create a CLI
    cli_t *c = cli_create();

    // ~ Testing: create an output handler
    output_t *o = output_create();

    // ~ A second output handler, pointed at its own file, for the machine-readable frame hex.
    // ~ It never writes to the terminal, that is what the one above is for
    output_t *of = output_create();

    // ~ The pcap writer, which puts frames into a real capture file rather than into text
    pcapw_t *pw = pcapw_create();

    // ~ Testing: create a socket
    sock_t *s = sock_create();

    // ~ Every one of those needed memory to exist. If any of them came back empty there is
    // ~ nothing to run, and touching them would be a crash, so leave before we get that far
    if (c == NULL || o == NULL || of == NULL || pw == NULL || s == NULL) {
        fprintf(stderr, "\n[ERROR]:main : could not set up the sniffer\n");
        cli_destroy(&c);
        output_destroy(&o);
        output_destroy(&of);
        pcapw_destroy(&pw);
        sock_destroy(&s);
        return EXIT_FAILURE;
    }

    // ~ Testing: fill out hints
    s->fill_hints(s);

    // ~ Testing: open socket
    s->open(s);

    // ~ Raw sockets are root-only, so this is where a run without `sudo` gives up.
    // ~ Carrying on with a (-1) descriptor would hand a negative file descriptor to select()
    if (s->sockfd < 0) {
        fprintf(stderr, "\n[ERROR]:main : could not open the socket, are you running with sudo?\n");
        s->destroy(&s);
        c->destroy(&c);
        o->destroy(&o);
        of->destroy(&of);
        pw->destroy(&pw);
        return EXIT_FAILURE;
    }

    while (c->exit_program == 0) {
        c->display_menu(c);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            // ~ stdin is finished (EOF, or it broke), so no further command is ever coming
            // ~ Looping back around here would spin forever and eat a whole CPU core
            OUTPUT_D_MSG("main : stdin has run out, shutting down.");
            c->exit_program = 1;
            continue;
        }

        // ~ Toss any overflow so a long line cannot turn into a second, unasked-for command
        cli_drain_line(input);

        if (input[0] == 's' || input[0] == 'S') {
            c->running = 1;
            printf("\nCapturing... (type 's' + Enter to stop)\n");

            o->to_file = c->opt_output_file;
            o->to_terminal = c->opt_output_terminal;

            if (o->to_file == 1) {
                o->open_file(o);
            }

            // ~ The frame-hex handler lives on its own file and never touches the terminal, so the
            // ~ hex in there stays clean enough for text2pcap to read back
            of->filename = FRAME_FILENAME;
            of->to_terminal = 0;
            of->to_file = c->opt_frame_file;

            if (of->to_file == 1) {
                of->open_file(of);
            }

            // ~ The pcap file gets its (24) byte header laid down now, before any frame arrives
            if (c->opt_pcap_file == 1) {
                pw->open(pw);
            }

            while (c->running == 1) {
                int status = c->check_for_input(c, s->sockfd);

                if (status == CLI_INPUT_STOPPED) {
                    break;
                }

                // ~ select() itself broke; staying in this loop would just print the same error forever
                if (status == CLI_INPUT_FAILED) {
                    c->running = 0;
                    c->exit_program = 1;
                    exit_code = EXIT_FAILURE;
                    break;
                }

                if (status == CLI_INPUT_PACKET) {
                    // ~ Testing: recieve a frame
                    brvd = s->recv(s);

                    // ~ If recieve came back with -1, it failed and a force exit must be made :'[
                    // ~ Break out rather than return, so the destructors below still get to run
                    if (brvd < 0) {
                        c->running = 0;
                        c->exit_program = 1;
                        exit_code = EXIT_FAILURE;
                        break;
                    }

                    // ~ A frame too short to even hold an Ethernet Header has nothing in it for us.
                    // ~ Every length check from here down exists because these bytes came off the
                    // ~ wire; anyone on this network decides what they say, so none of it is trusted
                    if (brvd < (ssize_t)sizeof(struct ethhdr)) {
                        continue;
                    }

                    // ~ Testing: Ethernet Header parsing
                    eth_t *e = eth_create();
                    if (e == NULL) {
                        continue;
                    }
                    e->set_buffer(e, s->buffer);
                    e->parse(e);

                    // ~ Skip non-IPv4 packets (ethertype must be ETH_P_IP, which is 0x0800)
                    if (ntohs(e->hdr->h_proto) != ETH_P_IP) {
                        e->destroy(&e);
                        continue;
                    }

                    // ~ The IP Header sits directly behind the Ethernet Header, so the frame has to
                    // ~ be long enough to actually hold one before we go casting it into place
                    if (brvd < (ssize_t)(ETH_HLEN + sizeof(struct iphdr))) {
                        e->destroy(&e);
                        continue;
                    }

                    // ~ Testing: IP parsing
                    ip_t *i = ip_create();
                    if (i == NULL) {
                        e->destroy(&e);
                        continue;
                    }
                    i->set_buffer(i, s->buffer);
                    i->parse_src(i);
                    i->parse_dst(i);

                    // ~ Skip non-TCP packets (protocol must be IPPROTO_TCP, which is 6), and skip
                    // ~ them too if the user switched TCP off over in the options menu
                    if (i->hdr->protocol != IPPROTO_TCP || c->opt_tcp == 0) {
                        e->destroy(&e);
                        i->destroy(&i);
                        continue;
                    }

                    // ~ ihl counts 32-bit words, so the header is really (ihl * 4) bytes long.
                    // ~ Under (20) bytes is a malformed header, and an oversized one would push the
                    // ~ TCP Header out past the end of what recv() actually handed us
                    size_t ip_hdr_len = (size_t)i->hdr->ihl * 4;
                    if (ip_hdr_len < sizeof(struct iphdr) || (size_t)brvd < ETH_HLEN + ip_hdr_len + sizeof(struct tcphdr)) {
                        e->destroy(&e);
                        i->destroy(&i);
                        continue;
                    }

                    // ~ Testing: tcp parsing
                    tcp_t *t = tcp_create();
                    if (t == NULL) {
                        e->destroy(&e);
                        i->destroy(&i);
                        continue;
                    }
                    t->set_buffer(t, s->buffer, (uint8_t)ip_hdr_len);
                    t->parse_src(t);
                    t->parse_dst(t);

                    // ~ Testing: payload parsing into hex-dump
                    // ~ doff counts 32-bit words exactly like ihl does, same two worries apply
                    size_t tcp_hdr_len = (size_t)t->hdr->doff * 4;
                    size_t headers_len = ETH_HLEN + ip_hdr_len + tcp_hdr_len; // ~ Calculate the length in bytes (Eth Hdr) + (IP Hdr) + (TCP Hdr)
                    if (tcp_hdr_len < sizeof(struct tcphdr) || headers_len > (size_t)brvd) {
                        e->destroy(&e);
                        i->destroy(&i);
                        t->destroy(&t);
                        continue;
                    }

                    payl_t *p = payl_create();
                    if (p == NULL) {
                        e->destroy(&e);
                        i->destroy(&i);
                        t->destroy(&t);
                        continue;
                    }
                    o->writef(o, "\nSource MAC: \t%s", e->src_mac);
                    o->writef(o, "\nDst MAC: \t%s", e->dst_mac);
                    o->writef(o, "\nNext Layer: \t%s", e->ethertype);

                    o->writef(o, "\nSource IP: \t%s", i->src_ip);
                    o->writef(o, "\nDst IP: \t%s", i->dst_ip);

                    o->writef(o, "\nSource Port: \t%s", t->src_port);
                    o->writef(o, "\nDst Port: \t%s", t->dst_port);

                    // ~ The whole frame, headers and all. Starting the dump at (0) instead of at
                    // ~ headers_len is the only difference between this and the payload dump below
                    if (c->opt_dump_frame == 1) {
                        p->set_buffer(p, s->buffer, (size_t)brvd, 0);
                        o->writef(o, "\n~~ Full Frame ~~\n");
                        p->parse(p, o);
                        o->writef(o, "\n");
                    }

                    // ~ Just what is riding behind the headers
                    if (c->opt_dump_payload == 1) {
                        p->set_buffer(p, s->buffer, (size_t)brvd, headers_len);
                        o->writef(o, "\n~~ Payload ~~\n");
                        p->parse(p, o);
                        o->writef(o, "\n");
                    }

                    // ~ Same full frame again, but written out in text2pcap format to its own file,
                    // ~ so it can be turned into a real capture later
                    if (c->opt_frame_file == 1) {
                        p->set_buffer(p, s->buffer, (size_t)brvd, 0);
                        p->parse_pcap(p, of);
                    }

                    // ~ And the same frame again into the real capture file. No hex involved here,
                    // ~ the raw bytes go down exactly as they came off the wire
                    if (c->opt_pcap_file == 1) {
                        pw->write(pw, s->buffer, (size_t)brvd);
                    }

                    e->destroy(&e);
                    i->destroy(&i);
                    t->destroy(&t);
                    p->destroy(&p);
                }
            }

            if (o->to_file == 1) {
                o->close_file(o);
            }

            if (of->to_file == 1) {
                of->close_file(of);
                printf("\nFrame hex written to %s (convert with: text2pcap %s out.pcap)\n", FRAME_FILENAME, FRAME_FILENAME);
            }

            if (c->opt_pcap_file == 1) {
                unsigned long written = pw->frames_written;
                pw->close(pw);
                printf("\nWrote %lu frame(s) to %s (open with: wireshark %s)\n", written, PCAPW_FILENAME, PCAPW_FILENAME);
            }
        } else if (input[0] == 'o' || input[0] == 'O') {
            c->display_options(c);
            c->handle_options(c);
        } else if (input[0] == 'e' || input[0] == 'E') {
            c->exit_program = 1;
        }
    }

    s->destroy(&s);
    c->destroy(&c);
    o->destroy(&o);
    of->destroy(&of);
    pw->destroy(&pw);

    printf("\nGoodbye!\n");
    return exit_code;
}

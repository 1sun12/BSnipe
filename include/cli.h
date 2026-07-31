#ifndef CLI_H
#define CLI_H

#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>

/**
 * @brief What `cli_check_for_input` found while it was waiting around
 * - CLI_INPUT_STOPPED  |   The user asked to stop capturing (or stdin ran out)
 * - CLI_INPUT_PACKET   |   A frame is sitting on the socket, go and read it
 * - CLI_INPUT_WAITING  |   Nothing happened before the timeout, just come back around
 * - CLI_INPUT_FAILED   |   select() genuinely broke, capturing cannot continue
 */
#define CLI_INPUT_STOPPED   0
#define CLI_INPUT_PACKET    1
#define CLI_INPUT_WAITING   (-1)
#define CLI_INPUT_FAILED    (-2)

typedef struct cli_t cli_t;
struct cli_t {
    int running;
    int exit_program;

    int opt_tcp;
    int opt_udp;
    int opt_arp;
    int opt_output_file;
    int opt_output_terminal;

    // ~ What each captured packet gets dumped as; the two are independent, so you can have
    // ~ both, either, or neither
    int opt_dump_frame;     // ~ The whole ethernet frame, headers and all
    int opt_dump_payload;   // ~ Just the payload sitting behind the headers
    int opt_frame_file;     // ~ Also write the frame as text2pcap-ready hex to FRAME_FILENAME
    int opt_pcap_file;      // ~ Also write the frame into a real .pcap at PCAPW_FILENAME

    void (*display_menu)(cli_t *self);
    void (*display_options)(cli_t *self);
    void (*handle_options)(cli_t *self);
    int (*check_for_input)(cli_t *self, int sockfd);
    void (*destroy)(cli_t **self_ptr);
};

/**
 * @brief Throws away whatever is left of a line that was too long for the buffer it was read into
 * @param input The buffer that `fgets` just filled
 * @note fgets only stops before the newline when the line did not fit. Anything it left behind is
 *       still sitting in stdin, and the next read would pick it up as a command of its own
 */
void cli_drain_line(const char *input);

cli_t *cli_create(void);

void cli_destroy(cli_t **self_ptr);

void cli_display_menu(cli_t *self);

void cli_display_options(cli_t *self);

void cli_handle_options(cli_t *self);

int cli_check_for_input(cli_t *self, int sockfd);

#endif

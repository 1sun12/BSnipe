
#include "cli.h"
#include "output.h"     // ~ For FRAME_FILENAME, so the menu names the same file main.c writes
#include "pcapw.h"      // ~ ...and PCAPW_FILENAME, for the same reason

/*
 * ==========================================================================
 * HELPERS - Small bits of housekeeping
 * ==========================================================================
 */

void cli_drain_line(const char *input) {
    // ~ A newline made it into the buffer, so fgets swallowed the whole line, nothing to drain
    if (strchr(input, '\n') != NULL) {
        return;
    }

    // ~ Otherwise keep pulling characters off stdin until this line is gone
    int ch = 0;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        // ~ Nothing to do with these, they were never meant for us
    }
}

cli_t *cli_create(void) {
    OUTPUT_D_MSG("cli_create : Attempting to create a CLI object...");

    cli_t *new = NULL;

    if ((new = (cli_t *)calloc(1, sizeof(cli_t))) == NULL) {
        perror("\n[ERROR]:cli_create");
        return NULL;
    }

    new->running = 0;
    new->exit_program = 0;

    new->opt_tcp = 1;
    new->opt_udp = 0;
    new->opt_arp = 0;
    new->opt_output_file = 0;
    new->opt_output_terminal = 1;

    // ~ Payload only by default, which is how the sniffer has always behaved
    new->opt_dump_frame = 0;
    new->opt_dump_payload = 1;
    new->opt_frame_file = 0;
    new->opt_pcap_file = 0;

    new->display_menu = cli_display_menu;
    new->display_options = cli_display_options;
    new->handle_options = cli_handle_options;
    new->check_for_input = cli_check_for_input;
    new->destroy = cli_destroy;

    OUTPUT_D_MSG("cli_create : Successfully created a CLI object!");
    return new;
}

void cli_destroy(cli_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    cli_t *self = *self_ptr;

    OUTPUT_D_MSG("cli_destroy : CLI object being destroyed...");

    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("cli_destroy : CLI object destroyed successfully!");
}

void cli_display_menu(cli_t *self) {
    does_exist(self);

    printf("\n=== Packet Sniffer ===\n");
    printf("[s] Start capture\n");
    printf("[o] Options\n");
    printf("[e] Exit\n");
    printf("\n> ");
    fflush(stdout);
}

void cli_display_options(cli_t *self) {
    does_exist(self);

    printf("\n=== Options ===\n");
    printf("[0] TCP: %s\n", self->opt_tcp ? "true" : "false");
    printf("[1] UDP: %s\n", self->opt_udp ? "true" : "false");
    printf("[2] ARP: %s\n", self->opt_arp ? "true" : "false");
    printf("[3] Output to file: %s\n", self->opt_output_file ? "true" : "false");
    printf("[4] Output to terminal: %s\n", self->opt_output_terminal ? "true" : "false");
    printf("[5] Full frame dump: %s\n", self->opt_dump_frame ? "true" : "false");
    printf("[6] Payload dump: %s\n", self->opt_dump_payload ? "true" : "false");
    printf("[7] Frame hex to %s: %s\n", FRAME_FILENAME, self->opt_frame_file ? "true" : "false");
    printf("[8] Write %s: %s\n", PCAPW_FILENAME, self->opt_pcap_file ? "true" : "false");
    printf("\nType number + 't' or 'f' (e.g., \"1t\" to enable UDP)\n");
    printf("Type 'b' to go back\n");
    printf("\nWARNING: Only TCP is currently supported. Changing settings may cause errors.\n");
    printf("\n[8] writes a real capture file, open it straight up with: wireshark %s\n", PCAPW_FILENAME);
    printf("[7] writes the same frames as plain hex instead, for pasting into a decoder,\n");
    printf("    or converting by hand with: text2pcap %s out.pcap\n", FRAME_FILENAME);
    printf("\n> ");
    fflush(stdout);
}

void cli_handle_options(cli_t *self) {
    does_exist(self);

    char input[16];
    int in_options = 1;

    while (in_options == 1) {
        if (fgets(input, sizeof(input), stdin) == NULL) {
            // ~ stdin is finished (EOF, or it broke), so another line is never coming
            // ~ Looping back around here would spin forever and eat a whole CPU core
            OUTPUT_D_MSG("cli_handle_options : stdin has run out, leaving the options menu.");
            in_options = 0;
            break;
        }

        // ~ Toss any overflow so a long line cannot turn into a second, unasked-for command
        cli_drain_line(input);

        if (input[0] == 'b' || input[0] == 'B') {
            in_options = 0;
            break;
        }

        if (input[1] == 't' || input[1] == 'T' || input[1] == 'f' || input[1] == 'F') {
            int value = (input[1] == 't' || input[1] == 'T') ? 1 : 0;

            if (input[0] == '0') {
                self->opt_tcp = value;
            } else if (input[0] == '1') {
                self->opt_udp = value;
            } else if (input[0] == '2') {
                self->opt_arp = value;
            } else if (input[0] == '3') {
                self->opt_output_file = value;
            } else if (input[0] == '4') {
                self->opt_output_terminal = value;
            } else if (input[0] == '5') {
                self->opt_dump_frame = value;
            } else if (input[0] == '6') {
                self->opt_dump_payload = value;
            } else if (input[0] == '7') {
                self->opt_frame_file = value;
            } else if (input[0] == '8') {
                self->opt_pcap_file = value;
            }
        }

        self->display_options(self);
    }
}

int cli_check_for_input(cli_t *self, int sockfd) {
    does_exist_ret(self, CLI_INPUT_FAILED);

    fd_set read_fds;
    struct timeval tv;

    // ~ FD_SET on a negative descriptor is undefined behaviour, so never let one through
    if (sockfd < 0) {
        fprintf(stderr, "\n[ERROR]:cli_check_for_input : the socket is not open\n");
        return CLI_INPUT_FAILED;
    }

    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    FD_SET(0, &read_fds);

    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    int max_fd = sockfd > 0 ? sockfd : 0;

    int result = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

    if (result < 0) {
        // ~ EINTR only means a signal arrived while we were waiting; that is routine, go around again
        if (errno == EINTR) {
            return CLI_INPUT_WAITING;
        }

        // ~ Anything else is a real failure. Say so, so the caller stops instead of
        // ~ looping straight back in here and printing this same error forever
        perror("\n[ERROR]:cli_check_for_input");
        return CLI_INPUT_FAILED;
    }

    if (FD_ISSET(0, &read_fds)) {
        char input[16];
        if (fgets(input, sizeof(input), stdin) != NULL) {
            cli_drain_line(input);

            if (input[0] == 's' || input[0] == 'S') {
                self->running = 0;
                return CLI_INPUT_STOPPED;
            }
        } else {
            // ~ stdin ran out, so the user has no way left to ask us to stop
            OUTPUT_D_MSG("cli_check_for_input : stdin has run out, stopping the capture.");
            self->running = 0;
            return CLI_INPUT_STOPPED;
        }
    }

    if (FD_ISSET(sockfd, &read_fds)) {
        return CLI_INPUT_PACKET;
    }

    // ~ The timeout simply expired without anything showing up
    return CLI_INPUT_WAITING;
}
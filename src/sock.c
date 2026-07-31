#include "sock.h"

/*
 * ==========================================================================
 * Constructor & Destructor - Initialize and freeing "this" object
 * ==========================================================================
 */

sock_t *sock_create(void) {
    OUTPUT_D_MSG("sock_create : Initializing a socket...");

    // ~ Initialize a socket pointer
    sock_t *new = NULL;

    // ~ Allocate however many bytes of memory it needs and zero the entire space
    new = (sock_t *)calloc(1, sizeof(sock_t));

    // ~ Error check: did calloc fail?
    if (new == NULL) {
        perror("\n[ERROR]:sock_create");
        return NULL;
    }

    // ~ Load default values
    new->sockfd = -1;

    // ~ Hints has already been zeroed out by calloc

    // ~ Allocate memory to the buffer and error check
    // ~ A socket with no buffer has nowhere to put a frame, so throw the whole thing away
    if ((new->buffer = malloc(MAX_FRAME_SIZE)) == NULL) {
        perror("\n[ERROR]:sock_create");
        free(new);
        return NULL;
    }

    // ~ Wire up function pointers
    new->fill_hints = sock_fill_hints;
    new->open = sock_open;
    new->close = sock_close;
    new->recv = sock_recv;
    new->destroy = sock_destroy;

    // ~ Return the newly init struct
    OUTPUT_D_MSG("sock_create : Socket initialized successfully!");
    return new;
}

void sock_destroy(sock_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    sock_t *self = *self_ptr;

    OUTPUT_D_MSG("sock_destroy : Socket being destroyed...");

    // ~ Close the linux file descriptor for the socket
    // ~ sock_close already knows how to do this safely, no reason to write it twice
    self->close(self);

    // ~ Deallocate the buffer
    free(self->buffer);
    self->buffer = NULL;

    // ~ Deallocate this entire memory block
    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("sock_destroy : Socket destroyed successfully!");
}

/*
 * ==========================================================================
 * METHODS - Functions that operate on the object
 * ==========================================================================
 *
 */

void sock_fill_hints(sock_t *self) {
    does_exist(self);

    // ~ Set address family to packets
    self->hints.ai_family = AF_PACKET;

    // ~ Set socket type to raw
    self->hints.ai_socktype = SOCK_RAW;

    // ~ Set protocol to capture every packet that hits our Network Interface Card
    self->hints.ai_protocol = htons(ETH_P_ALL);

    OUTPUT_D_MSG("sock_fill_hints : Hints have been templated...");
}

void sock_open(sock_t *self) {
    does_exist(self);
    OUTPUT_D_MSG("sock_open : Opening a new socket...");

    // ~ Creates a new socket given the templated information from our address information
    if ((self->sockfd = socket(self->hints.ai_family, self->hints.ai_socktype, self->hints.ai_protocol)) < 0) {
        perror("\n[ERROR]:sock_open");
        return;
    }

    OUTPUT_D_MSG("sock_open : Successfully opened a new socket!");
}

void sock_close(sock_t *self) {
    does_exist(self);
    OUTPUT_D_MSG("sock_close : Closing an existing socket...");

    // ~ There is nothing to close if the socket never opened in the first place (-1 is our "unopened" value)
    if (self->sockfd < 0) {
        OUTPUT_D_MSG("sock_close : There was no open socket to close.");
        return;
    }

    if (close(self->sockfd) < 0) {
        perror("\n[ERROR]:sock_close");
        return;
    }

    // ~ Back to "unopened" so nobody tries to close this descriptor a second time
    self->sockfd = -1;

    OUTPUT_D_MSG("sock_close : Successfully closed an existing socket!");
}

ssize_t sock_recv(sock_t *self) {
    does_exist_ret(self, -1);
    OUTPUT_D_MSG("sock_recv : Attempting to recieve message...");

    // ~ Total number of bytes recieved from the socket's packet capture
    // ~ ssize_t is similar to size_t but instead of its range being ~(+18) quintillion, its ~(-9) - ~(+9) quintillion, this being a (64)bit system
    // ~ recv() has a chance of returning -1, which will cause big issues with an unsigned max-size integer!
    // ~ You can still account for really large numbers and a possible -1 by using double(s)ize_t
    ssize_t brvd = 0;

    // ~ Recieve a raw ethernet frame from your Network Interface Card
    // ~ Hand -1 back on purpose; the caller checks for a negative to know this failed
    if ((brvd = (recv(self->sockfd, self->buffer, MAX_FRAME_SIZE, 0))) < 0) {
        perror("\n[ERROR]:sock_recv");
        return -1;
    }

    OUTPUT_D_MSG("sock_recv : Successfully recieved an ethernet frame!");
    return brvd;
}

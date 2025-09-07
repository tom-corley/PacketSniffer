#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <stddef.h>
#include "dispatch.h"

// === Imported Variables ===

extern long long packet_count; // defined in dispatch.c

// Counts from analysis.c
extern long long syn_count;
extern long long ip_count;
extern long long arp_resp_count;
extern long long blk_url_count;
extern long long ggl_count;
extern long long analysed;

// === Functions ===
// * see .c file for documentation *

// Entry point of application.
void sniff(char *interface, int verbose);

// Signal handler function for handling Ctrl C signal.
void signal_handler(int signal);

// Prints packets to terminal.
void dump(const unsigned char *data, int length);

// Safe memory allocation on heap, to prevent segmentation faults.
void *safe_mlc(size_t size);

#endif

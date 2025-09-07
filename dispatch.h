#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>

#include "analysis.h"
#include "sniff.h"

// === Data Structures ===

// Packet
typedef struct Packet {
  struct Packet *next;
  struct pcap_pkthdr *header;
  unsigned char *packet_data;
} Packet;

// Packet Queue
typedef struct PacketQueue {
  struct Packet *head;
  struct Packet *tail;
} PacketQueue;

// === Imported Variables ===

extern int verbose; // Defined in sniff.c

// === Functions ===
// * see .c file for documentation *

// Function for dispatching packets to the queue, passed as callback to pcap_loop()
void dispatch(unsigned char *user,
              const struct pcap_pkthdr *header, 
              const unsigned char *packet);

// Thread entry function for worker thread
void* worker_thread_function();

// Functions to manage packet queue 
void initialise_packet_queue();
int is_pkt_q_empty();
void enqueue_packet(Packet *p);
Packet *dequeue_packet();
void free_packet(Packet *p);
void dismantle_packet_queue();

// Functions to manage thread pool
void initialise_thread_pool();
void dismantle_thread_pool();

// IP tree initialisation function
void initialise_ip_tree();
#endif
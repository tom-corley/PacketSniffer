#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#include "sniff.h"

// === Data Structures ===

// Binary IP Tree
typedef struct IpNode {
    struct IpNode *left;
    struct IpNode *right;
    char *ip;
} IpNode;

typedef struct IpTree {
  struct IpNode *root;
 } IpTree;

// Structure to track thread statistics
typedef struct ThreadStats {
  long long syn_ct;
  long long arp_ct;
  long long url_ct;
  long long ays_ct;
  long long ggl_ct;
} ThreadStats;

// === Imported variables ===

extern IpTree *ip_tree; // Defined in dispatch.c
extern int verbose; 

// === Functions ===
// * see .c file for documentation *

// Function for packet analysis
void analyse(const struct pcap_pkthdr *header,
              const unsigned char *packet_data,
              int verbose, ThreadStats *stats);

// Functions on IP Tree
IpNode *add_ip(char* ip, IpNode *node, int* added);
void inorder(struct IpNode* root);
void dismantle_tree();
void postorder_deallocate(IpNode *n);

#endif


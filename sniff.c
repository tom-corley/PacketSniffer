// === Include Statements ===
#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stddef.h>
#include <time.h>

#include <pcap.h>
#include <netinet/if_ether.h>

#include "dispatch.h"
#include "analysis.h"

// === Global Variables ===
int verbose;
pcap_t *pcap_handle = NULL;

// === Functions === 

/*
 * Entry point of application.
 * Initiialises handle to network interface, signal handler, threads, and data structures.
 * Intercepts packets and sends them for processing using the callback function dispatch (see dispatch.c).
 * Cleans up threads and memory and outputs report to the user once Ctrl C signal sent.
 * Arguments:
 *  interface: char pointer to indicate which network interface (lo or eth0) to use, passed in on command line
 *  verbose: flag to indicate whether details of all packets should be printed to the terminal 
*/
void sniff(char *interface, int verbose_arg) {
  
  // Setting global verbose flag.
  verbose = verbose_arg;
  if (verbose) {printf("Output set to verbose. \n");}

  // Setting up signal handler for Ctrl^C signal, to stop packet collection and processing.
  if (signal(SIGINT, signal_handler) == SIG_ERR)
  {
    fprintf(stderr, "[-] Unable to set up SIGINT handler...\n");
    exit(EXIT_FAILURE);
  }
  printf("Succesful Signal Processor set up\n\n");
  
  // Creates packet handle to and opens network interface given in command line argument.
  // Captures up to 4096 bytes, promisciously (intercept everything), read timeout of second (1000 milliseconds), errors written into errbuf.
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf); 
  
  // Checks if handle to network interface was opened succesfully, exits if unsuccessful.
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  // Set up packet queue and IP tree.
  initialise_packet_queue();
  initialise_ip_tree();

  // Attempt to set up the pool of threads, exit if unsuccesful.
  int error = 0;
  initialise_thread_pool(&error);
  if (error != 0) {
    fprintf(stderr, "[-] Unable to start threads with error code: %d...\n", error);
    exit(EXIT_FAILURE);
  }

  // Main packet processing loop, each packet triggers callback function dispatch (see dispatch.c).
  pcap_loop(pcap_handle, -1, dispatch, NULL);

  // Program exectution only continues past this point after Ctrl^C signal is handled and pcap_breakloop() is called.

  // Cleanup: close handle, and dismantle threadpool, packet queue and ip_tree, freeing all memory still on the heap to avoid memory leaks.
  pcap_close(pcap_handle);
  dismantle_thread_pool();
  
  // Output intrusion detection report to user.
  printf("\n======INTRUSION DETECTION REPORT======\n");
  printf("=== TOTAL PACKETS RECIEVED = %lld, ANALYSED = %lld ===\n", packet_count, analysed);
  printf("%lld SYN packets detected from %lld different IPs (syn attack)...\n", syn_count, ip_count);
  printf("%lld ARP responses (cache poisoning)...\n", arp_resp_count);
  printf("%lld URL blacklist violations... (%lld google and %lld bbc)\n", blk_url_count, ggl_count, blk_url_count - ggl_count);
  printf("======END OF REPORT======\n");
   dismantle_packet_queue();
   dismantle_tree();
}

/*
 * Signal handling function for processing the Ctrl C signal, stops packet processing.
 * Arguments:
 *  signal: integer which represents the signal given during runtime
*/
void signal_handler(int signal) {
  if (signal == SIGINT) {
    pcap_breakloop(pcap_handle); // signal-safe function to end execution of pcap_loop()
  }
}

/*
 * Utility/Debugging method for dumping raw packet data (Unchanged from skeleton).
 * Arguments:
 *  data: raw packet data
 *  length: integer length of data
*/
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;

  // Decode Packet Header.
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount+1);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }

  printf("\nType: %hu\n", eth_header->ether_type);

  printf(" === PACKET %ld DATA == \n", pcount+1);
  // Decode Packet Data (Skipping over the header).
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time.
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form.
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines.
      }
    }
    printf ("| ");
    // Print data in ascii form.
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range.
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}

/*
 * Safe version of malloc function, to prevent segmentation faults
 * Arguments:
 *  size: Number of bytes to allocate.
 * Returns: The memory address of the allocated memory (a void pointer).    
*/
void *safe_mlc(size_t size) {
  // Attempt to allocate memory
  void *memory = malloc(size);
  // Exit program execution upon failure, to avoid segmentation
  if (memory == NULL) {
    printf("[-] Failed to allocate memory...\n");
    exit(EXIT_FAILURE);
  } else {
    return memory;
  }
}
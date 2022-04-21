#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_
#define MAC_LEN 6
#define MAX_ENTRIES 100000

#include "skel.h"
#include "queue.h"

struct ether_header *get_ether_header(packet *m);
struct iphdr *get_ip_header(packet *m);
struct arp_header *get_arp_header(packet *m);
struct icmphdr *get_icmp_header(packet *m);

int compare_function(const void *p, const void *q);
struct arp_entry *get_arp_entry(uint32_t dest_ip, struct arp_entry *arp_table,
                                int arp_table_size);

void echo_reply_ICMP(packet *m);
void error_reply_ICMP(packet *m, uint8_t type);
void reply_ICMP(struct ether_header *ether_h, struct iphdr *ip_h,
                uint32_t interface, uint8_t type, uint8_t code,
                uint16_t id, uint16_t seq);

void build_ethhdr(struct ether_header *ether_h, uint8_t *src_mac,
                  uint8_t *dst_mac, unsigned short type);

void build_iphdr(struct iphdr *new_ip_h, uint32_t source_ip,
                 uint32_t dest_ip, uint8_t protocol);
void build_icmphdr(struct icmphdr *new_icmp_h, uint8_t type,
                   uint8_t code, uint16_t id, uint16_t seq);


void request_ARP(struct route_table_entry* route);
void my_send_ARP(uint32_t daddr, uint32_t saddr,
                uint8_t src_mac[MAC_LEN], uint8_t dst_mac[MAC_LEN],
                uint16_t arp_op, uint32_t  interface);
void reply_ARP(packet *m);

struct route_table_entry *get_best_route(uint32_t dest_ip,
                                        struct route_table_entry *rtable,
                                        int r_table_size);

queue dequeue_packet(struct route_table_entry *rtable, int rtable_len,
                    queue packets_queue, uint32_t target_ip,
                    uint8_t* target_mac);

void enqueue_packet(packet *m, queue packets_queue);


#endif /* _FUNCTIONS_H_ */

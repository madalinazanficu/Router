#include "skel.h"
#include "functions.h"
#define MAC_LEN 6

struct route_table_entry *rtable;
int rtable_len = 0;

struct arp_entry *arp_table;
int arp_table_len = 0;

/* Creating and parsing the routing table */
void create_rtable(char *file_path) {
	rtable = malloc(MAX_ENTRIES * sizeof(struct route_table_entry));
	DIE(rtable == NULL, "Failed in create_rtable");
	rtable_len = read_rtable(file_path, rtable);
}

/* Creating and parsing the arp table */
void create_arp_table() {
	arp_table = malloc(MAX_ENTRIES * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Failed in create_arp_table");
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;
	init(argc - 2, argv + 2);
	create_rtable(argv[1]);
	create_arp_table();

	// Sorting the routing table
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_function);

	// Keeping a track of the packets for ARP Protocol
	queue packets_queue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *ether_h = get_ether_header(&m);
		struct iphdr *ip_h = get_ip_header(&m);

		/* IPv4 Packet */
		if (ntohs(ether_h->ether_type) == ETHERTYPE_IP) {

			/* The current router is the final destination */
			if ((inet_addr(get_interface_ip(m.interface))) == ip_h->daddr
						 && ip_h->protocol == IPPROTO_ICMP) {

				/* Received an icmp request => reply with my MAC address */
				struct icmphdr *icmp_h = (struct icmphdr *)(m.payload +
										  sizeof(struct ether_header) +
										  sizeof(struct iphdr));

				if (icmp_h->type == ICMP_ECHO) {
					echo_reply_ICMP(&m);
				}
				/* Drop the packet */
				continue;
			}

			/* Wrong checksum => drop the packet */
			if (ip_checksum((void *) ip_h, sizeof(struct iphdr)) != 0) {
				continue;
			}

			/* TTL of the packed expired => Send TIME LIMIT EXCEEDED 
											error back to the source
			 							 => Drop the packet */
			if (ip_h->ttl <= 1) {
				error_reply_ICMP(&m, ICMP_TIME_EXCEEDED);
				continue;
			}

			/* Searching for the best route, send the packet to the destination */
			struct route_table_entry *route = get_best_route(ip_h->daddr,
															rtable, rtable_len);
			if (route == NULL) {
				error_reply_ICMP(&m, ICMP_DEST_UNREACH);
				continue;
			}
			/* Bonus checksum */
			uint16_t prev_ttl = ip_h->ttl--;
			uint16_t prev_checksum = ip_h->check;
			uint16_t curr_ttl = ip_h->ttl;
			ip_h->check = ~(~prev_checksum + ~prev_ttl + curr_ttl) - 1;


			/* Search the IP of the next hope to extract the mac address later*/
			struct arp_entry *nei = get_arp_entry(route->next_hop, arp_table,
												  arp_table_len);

			/* The searched mac address is not availabe in the tabel.
			   Create an ARP request (a broadcast message in the network
			   of the next hop).
			   Until receving a reply => put the packet in a waiting queue.
			*/
			if (nei == NULL) {
				m.interface = route->interface;
				enqueue_packet(&m, packets_queue);
				request_ARP(route);
				continue;
			}
			
			/* Rewrite the Ethernet header of the packet to send it forward.
			   The destination host is the mac address of the next hop.
			   The source host is the mac address of the interface
			   the packet will be transmitted.
			   The interface is the interface of the best route. */
			memcpy(ether_h->ether_dhost, nei->mac, MAC_LEN);
			get_interface_mac(route->interface, ether_h->ether_shost);
			m.interface = route->interface;
			send_packet(&m);
		}

		/* ARP Packet */
		if ((ntohs(ether_h->ether_type)) == ETHERTYPE_ARP) {
			struct arp_header *arp_h = get_arp_header(&m);

			/* Received a request => reply */
			if ((ntohs(arp_h->op)) == ARPOP_REQUEST) {
				uint32_t ip_target = arp_h->tpa;
				uint32_t my_address = inet_addr(get_interface_ip(m.interface));

				/* The target ip address (TPA) is mine => reply with my mac address */
				if (ip_target == my_address) {
					reply_ARP(&m);
				}
				continue;
			}

			/* Received a reply to a request
				=> add the received SHA / SPA in the cache
				=> deque the specific packet from the queue and send it
				SPA = sender IP Addres
				SHA = sender hardware Address - MAC address
			*/
			if ((ntohs(arp_h->op)) == ARPOP_REPLY) {
				struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
				memcpy(&new_entry->ip, &arp_h->spa, sizeof(arp_h->spa));
				memcpy(&new_entry->mac, &arp_h->sha, sizeof(arp_h->sha));

				uint32_t ok = 0;
				for (uint32_t i = 0; i < arp_table_len; i++) {
					if (new_entry->ip == arp_table[i].ip) {
						ok = 1;
						break;
					}
				}
				if (ok == 0) {
					memcpy(&arp_table[arp_table_len], new_entry,
						   sizeof(struct arp_entry));
					arp_table_len++;
				}
				packets_queue = dequeue_packet(rtable, rtable_len, packets_queue,
											   new_entry->ip, new_entry->mac);
				continue;
			}
		}
	}
	free(rtable);
	free(arp_table);
}
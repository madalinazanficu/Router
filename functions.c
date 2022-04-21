#include "functions.h"
#include "queue.h"
#include "skel.h"

// Extract the Ethernet header
struct ether_header *get_ether_header(packet* m) {
	return (struct ether_header *)(m->payload);
}

// Extract the IP header
struct iphdr *get_ip_header(packet *m) {
    return (struct iphdr *)(m->payload + sizeof(struct ether_header));
}

// Extract the ARP header
struct arp_header *get_arp_header(packet *m) {
    struct ether_header *ether_h = get_ether_header(m);
	if (ntohs(ether_h->ether_type) == ETHERTYPE_ARP) {
		return (struct arp_header *) (m->payload + sizeof(struct ether_header));
	} else {
		return NULL;
	}
}
// Extract the ICMP header
struct icmphdr *get_icmp_header(packet *m) {
    struct ether_header *ether_h = get_ether_header(m);
	if (ntohs(ether_h->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip_h = get_ip_header(m);
		if (ip_h->protocol == 1) {
			return (struct icmphdr *)(m->payload + sizeof(struct ether_header)
                    + sizeof(struct iphdr));
		}
	}
	return NULL;
}

// Compare function used for sorting the r_table
int compare_function(const void *p, const void *q) {

	struct route_table_entry entry1 = *(struct route_table_entry *) p;
	struct route_table_entry entry2 = *(struct route_table_entry *) q;
	if (entry1.mask != entry2.mask) {
		return ntohl(entry1.mask) - ntohl(entry2.mask);
	} else {
		return ntohl(entry1.prefix) - ntohl(entry2.prefix);
	}
}

// Searching the ip of the next hope in arp_table
struct arp_entry *get_arp_entry(uint32_t dest_ip, struct arp_entry *arp_table,
                                int arp_table_size) {

	for (int i = 0; i < arp_table_size; i++) {
			if (arp_table[i].ip == dest_ip) {
				return &arp_table[i];
			}
	}
	return NULL;
}


// Updating IP and MAC info and sending back the packet
void echo_reply_ICMP(packet *m) {
    
    /* The headers of the recevied packet */
    struct ether_header *ether_h = get_ether_header(m); 
    struct iphdr *ip_h = get_ip_header(m);
    struct icmphdr* icmp_h = get_icmp_header(m);

    reply_ICMP(ether_h, ip_h, m->interface, ICMP_ECHOREPLY, ICMP_ECHOREPLY,
                icmp_h->un.echo.id, icmp_h->un.echo.sequence);
}

void error_reply_ICMP(packet* m, uint8_t type) {

    /* The headers of the recevied packet */
    struct ether_header *ether_h = get_ether_header(m); 
    struct iphdr *ip_h = get_ip_header(m);

    /* Received type could be TTL or Destination Unreacheble */
    reply_ICMP(ether_h, ip_h, m->interface, type, 0, 0, 0);
}

void reply_ICMP(struct ether_header *ether_h, struct iphdr *ip_h,
                uint32_t interface, uint8_t type, uint8_t code,
                uint16_t id, uint16_t seq) {

    /* Build a new packet and his headers in order to
       send it back to the source as a reply */
    packet packet;

    /* Build Ethernet Header [DESTIONATION MAC][SOURCE MAC][ETHER-TYPE]
       Reverse the dest/source mac addresses of the received packet */
    struct ether_header new_ether_h;
    build_ethhdr(&new_ether_h, ether_h->ether_dhost,
                 ether_h->ether_shost, htons(ETHERTYPE_IP));

    /* Build IP Header, reversing the dest/source
       IP addresses of the received packet */
    struct iphdr new_ip_h;
    build_iphdr(&new_ip_h, ip_h->daddr, ip_h->saddr, IPPROTO_ICMP);

    /* Build ICMP Header */
    struct icmphdr new_icmp_h;
    build_icmphdr(&new_icmp_h, type, code, id, seq);
    new_icmp_h.checksum = icmp_checksum((uint16_t *)&new_icmp_h,
                          sizeof(struct icmphdr));

    /* Build the payload */
    void *payload = packet.payload;
	memcpy(payload, &new_ether_h, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &new_ip_h, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &new_icmp_h, sizeof(struct icmphdr));

    /* Complete the len of the packet and the interface */
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr)
                + sizeof(struct icmphdr);
    packet.interface = interface;

    /* Send the packet */
	send_packet(&packet);
}

void request_ARP(struct route_table_entry* route) {
    
    /* Send a packet with: Ethernet Header [DESTIONATION MAC][SOURCE MAC][ETHER-TYPE]
                                       <=> [0XFF][source_mac][ARP] */
    uint8_t dst_mac[MAC_LEN] = {0xff};
    uint8_t src_mac[MAC_LEN];
    get_interface_mac(route->interface, src_mac);

    uint32_t daddr = route->next_hop;
    uint32_t saddr = inet_addr(get_interface_ip(route->interface));
    my_send_ARP(daddr, saddr, src_mac, dst_mac,
                htons(ARPOP_REQUEST), route->interface);
}
void reply_ARP(packet *m) {
    struct arp_header *arp_h = get_arp_header(m);

    /* send a packet with: Ethernet Header [DESTIONATION MAC][SOURCE MAC][ETHER-TYPE]
                                       <=> [SENDER HARDWARE ADDRESS][MY MAC][ARP] */
    
    /* Sender Ip Address */
    uint32_t daddr = arp_h->spa;
    /* Target Ip Address */
    uint32_t saddr = arp_h->tpa;

    uint8_t dst_mac[MAC_LEN];
    memcpy(dst_mac, arp_h->sha, MAC_LEN);
    uint8_t src_mac[MAC_LEN];
	get_interface_mac(m->interface, src_mac);
    
    my_send_ARP(daddr, saddr, src_mac, arp_h->sha,
                htons(ARPOP_REPLY), m->interface);
}

void my_send_ARP(uint32_t daddr ,uint32_t saddr, uint8_t src_mac[MAC_LEN],
                uint8_t dst_mac[MAC_LEN], uint16_t arp_op, uint32_t interface) {

    /* Build the packet */
    packet packet;

    /* Build the ether-header */
    struct  ether_header *new_ether_h = malloc(sizeof(struct ether_header));
    DIE(new_ether_h == NULL, "Error in my_send_ARP");
    build_ethhdr(new_ether_h, src_mac, dst_mac, htons(ARP_TYPE));

    /* Build ARP HEADER [IP Addres Type][IP ADDRESS][IP Search Type][MAC ADDRESS]*/
    struct arp_header arp_hdr;
    arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arp_op;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
    /* MAC addresses */
    memcpy(arp_hdr.sha, new_ether_h->ether_shost, MAC_LEN);
    memcpy(arp_hdr.tha, new_ether_h->ether_dhost, MAC_LEN);
    /* IP addresses */
    arp_hdr.spa = saddr;
    arp_hdr.tpa = daddr;

    /* Build the PAYLOAD */
    memset(packet.payload, 0, 1600);
	memcpy(packet.payload, new_ether_h, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr,
            sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	packet.interface = interface;
	send_packet(&packet);
}


void build_ethhdr(struct ether_header *ether_h, uint8_t *src_mac,
                  uint8_t *dst_mac, unsigned short type) {

	memcpy(ether_h->ether_dhost, dst_mac, ETH_ALEN);
	memcpy(ether_h->ether_shost, src_mac, ETH_ALEN);
	ether_h->ether_type = type;
}

void build_iphdr(struct iphdr *new_ip_h, uint32_t source_ip,
                uint32_t dest_ip, uint8_t protocol) {

    new_ip_h->version = 4;
	new_ip_h->ihl = 5;
	new_ip_h->tos = 0;
	new_ip_h->protocol = protocol;
	new_ip_h->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_h->id = htons(1);
	new_ip_h->frag_off = 0;
	new_ip_h->ttl = 64;
	new_ip_h->check = 0;
	new_ip_h->daddr = dest_ip;
	new_ip_h->saddr = source_ip;
	new_ip_h->check = ip_checksum((void *)new_ip_h, sizeof(struct iphdr));
}

void build_icmphdr(struct icmphdr *new_icmp_h, uint8_t type,
                   uint8_t code, uint16_t id, uint16_t seq) {

    new_icmp_h->type = type;
    new_icmp_h->code = code;
    new_icmp_h->checksum = 0;
    new_icmp_h->un.echo.id = id;
    new_icmp_h->un.echo.sequence = seq;
}


/*	Returns a pointer to the best matching route.
	Or NULL if there is no matching route. */
struct route_table_entry *get_best_route(uint32_t dest_ip,
                                        struct route_table_entry *rtable,
                                        int r_table_size) {
	int left = 0;
	int right = r_table_size - 1;
	int target = -1;

	while (left <= right) {
		int middle = (left + right) / 2;
		if ((dest_ip & rtable[middle].mask) == rtable[middle].prefix) {
			target = middle;
			left = middle + 1;
		} else {
			if (ntohl(dest_ip & rtable[middle].mask) > ntohl(rtable[middle].prefix)) {
				left = middle + 1;
			} else {
				right = middle - 1;
			}
		}
	}
	if (target != -1) {
		return &rtable[target];
	}
	return NULL;
}
queue dequeue_packet(struct route_table_entry *rtable, int rtable_len,
                    queue packets_queue, uint32_t target_ip, uint8_t* target_mac) {

    queue new_queue =  queue_create();
    while (!queue_empty(packets_queue)) {
        packet *m = queue_deq(packets_queue);

        struct ether_header *ether_h = get_ether_header(m);
        struct iphdr *ip_h = get_ip_header(m);
        struct route_table_entry *destination = get_best_route(ip_h->daddr,
                                                rtable, rtable_len);

        if (destination->next_hop == target_ip) {
            uint8_t source_mac[MAC_LEN];
			get_interface_mac(m->interface, source_mac);
			memcpy(ether_h->ether_dhost, target_mac, MAC_LEN);
			memcpy(ether_h->ether_shost, source_mac, MAC_LEN);

			// send the packet to the next hop
			send_packet(m);
        } else {
            queue_enq(new_queue, m);
        }

    }
    free(packets_queue);
    return new_queue;
}
void enqueue_packet(packet* m, queue packets_queue) {
    packet *entry = malloc(sizeof(packet));
    DIE(entry == NULL, "Error in enqueue packet!");
    memcpy(entry, m, sizeof(packet));
    queue_enq(packets_queue, entry);
}
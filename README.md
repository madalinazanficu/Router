### CopyRight Madalina Zanficu 323CA
### **Homework Communications Protocols**
### Basic **Routing Protocols** implemented: 
### **Forwarding**, **ICMP Protocol**, **ARP Protocol**, 
### **Longest Prefix Match Efficient**, **Bonus checksum**

#### **Structure and flow**
- **router.c** - contains the overall flow of forwarding packages.
    - At the most abstract level, a packet contains: [len][Payload][interface].
    - The Paylod is formed by the headers [ETHERNET HEADER]
                                          [ARP HEADER / IPV4 HEADER]
                                          [ICMP (optional)].
    - The transmission of the packets is influenced by **Ipv4 Header**
    or **Arp Header** : 

    - If the router receives an **Ipv4** packet: the router could be the final
    destination, the packet could be corrupted, the TTL of the packet may have
    passed, or the **forwarding process continues**.
    - For the last case: **the best route** to destination is found using binary
    search implementation. Once the next hop is found, the mac address needs to be
    found as well.
    - At first, to search the mac address, a **broadcast message** will be
    transmitted in the network of the next hop. Until the response is received,
    the packet will be in a **waiting queue**.
    - After receving a response, the mac will be stored in arp_table.
    - In case the mac address is already in the arp_table, we have all
    the information in order to **send the packet forward**.

    - **Arp Case**: The router is in charge of replying to requests or managing
    replies.

    - ***Reply to request***: in case the message from the broadcast was
    intened for the current router, it will send a packet replying with
    his MAC address. Used reply_ARP function for handling this case.
    - ***Manage a reply***: The current router recevied the needed
    MAC address in order to send forward the packet. Used dequeue_packet
    to take care of sending the specific waiting packet. 

- **functions.c**
- Get_best_route: binary searching the entry with the suitable prefix 
and the biggest mask.
- Compare_function: used in order to sort the route_table.
The main criteria in sorting is the mask (increasing order)
and the second criteria is the prefix.

- Functions for ICMP Protocol:
    - echo_reply_ICMP, error_reply_ICMP (TTP or Destionation Unreacheble).
    - Both of them use reply_ICMP which build a new packet
    (with all the specified headers), and send the packet back to the source.
- Functions for ARP Proctol:
    - request_ARP, reply_ARP, my_send_ARP
- Implemented functions for extracting headers:
    - get_ether_header
    - get_ip_header
    - get_arp_header
    - get_icmp_header
- Implemented functions for building headers:
    - build_ethhdr
    - build_iphdr
    - build_icmphdr

Source and documentation: My program basis was Lab04-Forwarding implementation.
It was really useful to study forwarding at lab before.
Also, the previous skeleton that included send_ICMP and send_ARP
was useful to understand how the packet is constructed in order to be sent,
but I have implemented my own version of these functions.
Bonus checksum: https://datatracker.ietf.org/doc/rfc1624/.
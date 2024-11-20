#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8


struct route_table_entry *rtable;
int rtable_entries;

struct arp_table_entry *arp_table;
int arp_entries;

struct arp_table_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_entries; i++)
	{
		if(arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

//functie care compara 2 intrări din tabela de rutare pentru sortare
int compare(const void *a, const void *b)
{
	int prima = ntohl(((struct route_table_entry *)a)->prefix);
	int a_doua = ntohl(((struct route_table_entry *)b)->prefix);
	if (prima == a_doua)
	{
		int masca_a = ntohl(((struct route_table_entry *)a)->mask);
		int masca_b = ntohl(((struct route_table_entry *)b)->mask);
		return (masca_a - masca_b);
	}
	return (prima - a_doua);
}


int binarySearch(int start, int end, uint32_t ip, uint32_t mask)
{
    while (end >= start)
    {
        int center = start + (end - start) / 2;
        uint32_t maskedPrefix = ntohl(rtable[center].prefix) & mask;

        if (maskedPrefix == (ntohl(ip) & mask))
        {
            if (ntohl(rtable[center].mask) == mask)
                return center;
            else if (ntohl(rtable[center].mask) > mask)
                end = center - 1;
            else
                start = center + 1;
        }
        else if (maskedPrefix > (ntohl(ip) & mask))
            end = center - 1;
        else
            start = center + 1;
    }

    return -1;
}


struct route_table_entry *get_best_route(uint32_t ip_address)
{
	uint32_t subnet_mask = 1;
    int index, found_index;

    for (index = 0; index < 32; index++)
    {
        uint32_t search_mask = ~(subnet_mask - 1);

        found_index = binarySearch(0, rtable_entries - 1, ip_address, search_mask);

        if (found_index != -1)
            return &rtable[found_index];
        
        subnet_mask = subnet_mask << 1;
    }
    return NULL;

}

void send_icmp_reply(char *buf, size_t len, int interface, uint8_t type) {
	//accesez/modific headerele pachetului
    struct ether_header *eth_hdr = (struct ether_header *)buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // setez tipul ICMP și recalcularea checksum-ului ICMP
	icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
    icmp_hdr->type = type;
    icmp_hdr->code = 0;
   

    // schimb adresele IP sursă/destinație pentru a raspunde
    uint32_t temp_ip = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = temp_ip;

    // modific TTL și recalculez checksum IP
    ip_hdr->ttl = 64;
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    uint8_t mac_temp[ETH_ALEN];
    memcpy(mac_temp, eth_hdr->ether_shost, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETH_ALEN);
    memcpy(eth_hdr->ether_dhost, mac_temp, ETH_ALEN);

    //apoi trimit pachetul înapoi pe aceeași interfață
    send_to_link(interface, buf, len);
}


int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];
    init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 65000);
    DIE(rtable == NULL, "memory");
	rtable_entries = read_rtable(argv[1], rtable);

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	arp_entries = parse_arp_table("arp_table.txt", arp_table);
    
    qsort((void *)rtable, rtable_entries, sizeof(struct route_table_entry), compare); //sortez tabela de rutare


    while (1) {
        int interface;
        size_t len;
		
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct iphdr *ip_hdr = NULL;
		struct icmphdr *icmp_hdr = NULL;


		//verific daca primesc packet IPv4
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			continue;
		} 
		
		ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
		
		uint16_t checksum_packet = 0;
		checksum_packet = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t router_sum =  htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		if(checksum_packet != router_sum) {
			continue;
		}


		//obțin cea mai bună rută pentru adresa IP de destinație
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if(best_route == NULL) {
			send_icmp_reply(buf, len, interface, ICMP_DEST_UNREACH);
			continue;
		}

		//verific daca pachetul pe care-l primesc e de tip icmp
		if (icmp_hdr->type == ICMP_ECHO && ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
		{
			send_icmp_reply(buf, len, interface, ICMP_ECHOREPLY);
			continue;
		}

		//verific valoarea TTL și face modificari daca e necesar
		if(ip_hdr->ttl <= 1) {
			//printf("TTL < 1\n");
			send_icmp_reply(buf, len, interface, ICMP_TIME_EXCEEDED);
			continue;
		} else {
			ip_hdr->ttl--;
		}

		uint8_t smac[6];
		struct arp_table_entry *dest_mac_entry = get_arp_entry(best_route->next_hop);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		// recalculez checksum-ul după ajustarea TTL
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		if (dest_mac_entry == NULL) {
			continue;
		}

		// setez adresele MAC destinație și sursă
		for(int i = 0; i < 6; i++){
			eth_hdr->ether_dhost[i] = dest_mac_entry->mac[i];
			eth_hdr->ether_shost[i] = smac[i];
		}
		
		// trimit pachetul la interfața specificată
		send_to_link(best_route->interface, buf, len);
        }
		free(rtable);
		free(arp_table);
    return 0;
}
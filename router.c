#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>
#include <stdbool.h>
// definim tipurile de protocoale:
#define ETHERTYPE_IP 0x0800	 /* IP protocol */
#define ETHERTYPE_ARP 0x0806 /* ARP protocol */
#define TIME_EXCEDED_CODE 11
#define TIME_EXCEDED_TYPE 0
#define DEST_UNREACHABLE_CODE 0
#define DEST_UNREACHABLE_TYPE 3

// varianta cu trie
typedef struct node
{
	struct node *left;				// bit de 0
	struct node *right;				// bit de 1
	bool end;						// setat pe 1 daca am ajuns la sfarsit
	struct route_table_entry *info; // route table entry
} node;

/*
	functia parcurge tabela de rutare a routerului si transforma fiecare prefix in binar
	dupa care asigneaza fiecare bit in arborele binar, daca se ajunge la finalul prefixului,
	se marcheaza variabila end cu 1 in nodul corespunzator
	@rtable contine tabela de rutare
	@tree_root este radacina arborelui binar de cautare
	@path este fisierul care contine tabela de rutare a routerului
*/
int read_prefix_tree(const char *path, struct route_table_entry *rtable, node *tree_root)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return -1;
	int j = 0;
	char line[64];
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char *p = strtok(line, " .\n");
		int i = 0;

		while (p != NULL)
		{
			if (i < 4)
				((unsigned char *)&rtable[j].prefix)[i] = (unsigned char)atoi(p);
			else if (i >= 4 && i < 8)
				((unsigned char *)&rtable[j].next_hop)[i - 4] = (unsigned char)atoi(p);
			else if (i >= 8 && i < 12)
				((unsigned char *)&rtable[j].mask)[i - 8] = (unsigned char)atoi(p);
			else if (i == 12)
				rtable[j].interface = atoi(p);

			p = strtok(NULL, " .\n");
			i++;
		}

		uint32_t prefix = ntohl(rtable[j].prefix);
		uint32_t mask = ntohl(rtable[j].mask);

		int prefix_len = 0;
		for (int k = 31; k >= 0; k--)
		{
			if (mask & (1 << k))
				prefix_len++;
		}

		node *current = tree_root;

		for (int bit_index = 0; bit_index < prefix_len; bit_index++)
		{
			int bit = (prefix >> (31 - bit_index)) & 1;

			if (bit == 0)
			{
				if (!current->left)
					current->left = calloc(1, sizeof(node));
				current = current->left;
			}
			else
			{
				if (!current->right)
					current->right = calloc(1, sizeof(node));
				current = current->right;
			}
		}

		current->end = 1;
		current->info = &rtable[j];
		j++;
	}
	fclose(fp);
	return j;
}

struct node *best_match_node(struct node *tree, uint32_t ip)
{
	struct node *current_node = tree;
	struct node *best_match = NULL;
	for (int i = 31; i >= 0; i--)
	{
		int bit = (ip >> i) & 1;

		if (bit == 0)
		{
			if (current_node->left != NULL)
			{
				current_node = current_node->left;
			}
			else
			{
				break;
			}
		}
		else
		{
			if (current_node->right != NULL)
			{
				current_node = current_node->right;
			}
			else
			{
				break;
			}
		}

		if (current_node->end)
		{
			best_match = current_node;
		}
	}

	return best_match;
}

// functie de cautare in tabela arp
struct arp_table_entry *find_arp_entry(struct arp_table_entry *arp_table, int len, uint32_t ip)
{
	for (int i = 0; i < len; i++)
	{
		if (ip == arp_table[i].ip)
			return &arp_table[i];
	}
	return NULL;
}

/*
	varianta liniara a best route-ului
	@route_table tabela de rutare ip
	@table_size dimensiunea tabelei de rutare
	@destination ip destinatie
*/
struct route_table_entry *find_route_table_match(struct route_table_entry *route_table,
												 int table_size, uint32_t destination)
{
	struct route_table_entry *best_match = NULL;

	for (int i = 0; i < table_size; i++)
	{
		if ((destination & route_table[i].mask) == (route_table[i].prefix & route_table[i].mask))
		{
			if (best_match == NULL || (ntohl(route_table[i].mask) > ntohl(best_match->mask)))
			{
				best_match = &route_table[i];
			}
		}
	}
	return best_match;
}

/*
	@buf frame-ul initial care trebuie trimis
	@code cod-ul pentru icmp
	@type tipul de request icmp
	@out_interface interfata pe unde se trimit pachetele
*/
void send_icmp_req(char *buf, int code, int type, int out_interface)
{
	// (ETH_header + IP_header + ICMP_header + IP_header initial + 8 octeti din payload-ul IP)
	// payload (imediat de dupa ip header)
	struct icmp_hdr *icmp_hdr = calloc(1, sizeof(struct icmp_hdr));
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = code;
	// trebuie modificat header-ul curent sa trimita unde trebuie

	// TO DO:_______________________adresa MAC?_________________________
	// momentan o sa inversez adresele mac intre ele ca nu am implementat ARP

	// Construim pachetul
	// Copiem cei 64 biti inainte de a modifica payload-ul de dupa ip header in icmp(payload)
	memcpy(buf + sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), &icmp_hdr + sizeof(struct icmp_hdr), 64);
	// adaug header-ul icmp
	memcpy(buf + sizeof(struct ether_hdr) +
			   sizeof(struct ip_hdr),
		   &icmp_hdr, sizeof(struct icmp_hdr));
	// adaug header-ul ip
	memcpy(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   &buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr));
	// trimit pachetul
	free(icmp_hdr);
	send_to_link(sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + 64 + sizeof(struct icmp_hdr), buf, out_interface);
}

/*
	@interface e interfata din tabela de rutare
	@ip e ip-ul caruia vrem sa ii gasim adresa mac
*/
void send_arp_req(int interface, uint32_t ip)
{
	char *frame = calloc(MAX_PACKET_LEN, sizeof(char));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)frame;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(frame + sizeof(struct ether_hdr));
	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
	arp_hdr->proto_type = htons(1);		 // request
	arp_hdr->proto_type = htons(0x0800); // IPv4
	arp_hdr->hw_len = 6;				 // MAC length
	arp_hdr->proto_len = 4;				 // IPv4 length
	arp_hdr->opcode = htons(1);
	send_to_link(sizeof(eth_hdr) + sizeof(arp_hdr), frame, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);
	struct route_table_entry *route_table = calloc(64500, sizeof(struct route_table_entry));
	struct node *prefix_tree_root = calloc(1, sizeof(struct node));
	//_________________________tabela de rutare si dimensiunea ei(liniar)__________________________
	// int route_table_len = read_rtable(argv[1], route_table);

	//_________________________tabela de rutare si dimensiunea ei(trie)__________________________
	int route_table_len = read_prefix_tree(argv[1], route_table, prefix_tree_root);

	//_________________________tabela arp si dimensiunea ei________________________________
	struct arp_table_entry *arp_table = calloc(7, sizeof(struct arp_table_entry));
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	while (1)
	{

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// TODO: Implement the router forwarding logic
		printf("%ld	", interface);
		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */
		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		switch (ntohs(eth_hdr->ethr_type))
		{
		case ETHERTYPE_IP:
			/* code */
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + (sizeof(struct ether_hdr)));
			uint32_t ip_interfata = inet_addr(get_interface_ip(interface)); // valoarea adresei in format big endian, mare atentie
			if (ntohl(ip_hdr->dest_addr == ip_interfata))
			{
				printf("Adresa destinatie este chiar cea a routerului");
				// trebuie sa verific daca e de tip icmp

				// if (ip_hdr->proto == 1)
				// { // 1 pentru tipul icmp
				// 	uint32_t tmp_addr = ip_hdr->dest_addr;
				// 	ip_hdr->dest_addr = ip_hdr->source_addr;
				// 	ip_hdr->source_addr = tmp_addr;
				// 	struct route_table_entry *route_match =
				// 		find_route_table_match(route_table, route_table_len, ip_hdr->dest_addr);
				// 	send_icmp_req(buf, 0, 0, route_match->interface);
				// }
				// daca e de tip icmp o sa trimit un req
			}
			else
			{
				// verificam checksum:
				uint16_t old_checksum = ntohs(ip_hdr->checksum);
				ip_hdr->checksum = 0;
				uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
				if (old_checksum != new_checksum)
				{
					continue;
				}
				// verificam ttl:
				// ttl-ul nu il inversez ca e pe 8 biti si o sa fie acelasi
				// si pe little endian si pe big endian

				struct node *best_match = best_match_node(prefix_tree_root, ntohl(ip_hdr->dest_addr));
				//struct route_table_entry *route_match = find_route_table_match(route_table, route_table_len, ip_hdr->dest_addr);
				if(best_match == NULL){
					//trimite catre un host necunoscut
					continue;
				}
				struct route_table_entry *route_match = best_match->info;
				if (ip_hdr->ttl <= 1)
				{
					// va trebui sa intorc la sursa un pachet ICMP cu mesajul Time exceded
					// trebuie modificat header-ul curent sa trimita unde trebuie
					// send_icmp_req(buf, TIME_EXCEDED_CODE, TIME_EXCEDED_TYPE, route_match->interface);
					continue;
				}

				ip_hdr->ttl = ip_hdr->ttl - 1;

				// if (route_match == NULL)
				// {
				// 	// TO DO: ICMP de tip Destination unreachable
				// 	// nu exista destinatie pentru acest caz
				// 	// send_icmp_req(buf, DEST_UNREACHABLE_CODE, DEST_UNREACHABLE_TYPE, route_match->interface);
				// 	continue;
				// }
				// nu actualizez ce trebuie, nici macar nu modific adresa ip cum trebuie
				// actualizare checksum

				// trimiterea pachetului
				struct arp_table_entry *arp_entry = find_arp_entry(arp_table, arp_table_len, route_match->next_hop);
				get_interface_mac(route_match->interface, eth_hdr->ethr_shost);
				memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6 * sizeof(uint8_t));
				ip_hdr->checksum = 0;
				new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
				ip_hdr->checksum = htons(new_checksum);
				send_to_link(len, buf, route_match->interface);
			}
			break;

		case ETHERTYPE_ARP:
			// de impementat ARP
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + (sizeof(struct ether_hdr)));
			break;
		default:
			printf("Routerul nu cunoaste acest tip de protocol, dam drop la pachet");
			continue;
		}
	}
}

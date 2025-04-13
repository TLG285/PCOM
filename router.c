#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>
#include <stdbool.h>

#define ETHERTYPE_IP 0x0800	 /* IP protocol */
#define ETHERTYPE_ARP 0x0806 /* ARP protocol */
#define ARP_PACKET_LEN 42	 // in bytes
#define ARP_OPCODE_REQ 1
#define ARP_OPCODE_RECV 2
#define TIME_EXCEDED_CODE 0
#define TIME_EXCEDED_TYPE 11
#define DEST_UNREACHABLE_CODE 0
#define DEST_UNREACHABLE_TYPE 3
#define ICMP_PACKET_LEN (sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + 8 + sizeof(struct icmp_hdr))

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
	if (len == 0)
	{
		return NULL;
	}
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
void send_icmp_dest(char *buf, int interface)
{
	char *frame = calloc(MAX_PACKET_LEN, sizeof(char));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	icmp_hdr->mtype = DEST_UNREACHABLE_TYPE;
	icmp_hdr->mcode = DEST_UNREACHABLE_CODE;

	// (ETH_header + IP_header + ICMP_header + IP_header initial + 8 octeti din payload-ul IP)
	// payload (imediat de dupa ip header)
	// Copiem cei 64 biti inainte de a modifica payload-ul de dupa ip header in icmp(payload)
	memcpy(frame, eth_hdr, sizeof(struct ether_hdr));
	memcpy(frame + sizeof(struct ether_hdr), ip_hdr, sizeof(struct ip_hdr));
	// adaug header-ul icmp
	memcpy(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), icmp_hdr, sizeof(struct icmp_hdr));
	// adaug header-ul ip initial
	memcpy(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr));
	memcpy(frame + sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), 8);

	// lucram cu frame-ul acum:
	eth_hdr = (struct ether_hdr *)frame;
	ip_hdr = (struct ip_hdr *)(frame + sizeof(struct ether_hdr));
	icmp_hdr = (struct icmp_hdr *)(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// schimb adresele mac:
	uint8_t tmp_mac[6];
	memcpy(tmp_mac, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, tmp_mac, 6);
	// schimb adresele ip:
	uint32_t tmp_ip = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	// resetez ttl:
	ip_hdr->ttl = 64;
	// calculez checksum ip + icmp
	ip_hdr->checksum = 0;
	ip_hdr->checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
	icmp_hdr->check = 0;
	icmp_hdr->check = checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr));
	// schimbam dimensiunea ip_hdr
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	ip_hdr->proto = 1;

	// trimit pachetul
	send_to_link(MAX_PACKET_LEN, frame, interface);
}
void send_icmp_time(char *buf, int interface)
{
	char *frame = calloc(MAX_PACKET_LEN, sizeof(char));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	icmp_hdr->mtype = TIME_EXCEDED_TYPE;
	icmp_hdr->mcode = TIME_EXCEDED_CODE;

	// (ETH_header + IP_header + ICMP_header + IP_header initial + 8 octeti din payload-ul IP)
	// payload (imediat de dupa ip header)
	// Copiem cei 64 biti inainte de a modifica payload-ul de dupa ip header in icmp(payload)
	memcpy(frame, eth_hdr, sizeof(struct ether_hdr));
	memcpy(frame + sizeof(struct ether_hdr), ip_hdr, sizeof(struct ip_hdr));
	// adaug header-ul icmp
	memcpy(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), icmp_hdr, sizeof(struct icmp_hdr));
	// adaug header-ul ip initial
	memcpy(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr));
	// pun cei 8 bytes din buffer-ul original
	memcpy(frame + sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), 8);

	// lucram cu frame-ul acum:
	eth_hdr = (struct ether_hdr *)frame;
	ip_hdr = (struct ip_hdr *)(frame + sizeof(struct ether_hdr));
	icmp_hdr = (struct icmp_hdr *)(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// schimb adresele mac:
	uint8_t tmp_mac[6];
	memcpy(tmp_mac, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, tmp_mac, 6);
	// schimb adresele ip:
	uint32_t tmp_ip = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	// resetez ttl:
	ip_hdr->ttl = 64;
	// calculez checksum ip + icmp
	ip_hdr->checksum = 0;
	checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
	icmp_hdr->check = 0;
	checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr));
	// schimbam dimensiunea ip_hdr
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	//  trimit pachetul
	ip_hdr->proto = 1;
	send_to_link(ICMP_PACKET_LEN, frame, interface);
}
void send_icmp(char *buf, int interface, int type, int code)
{
	char *frame = calloc(MAX_PACKET_LEN, sizeof(char));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	icmp_hdr->mtype = type;
	icmp_hdr->mcode = code;

	// (ETH_header + IP_header + ICMP_header + IP_header initial + 8 octeti din payload-ul IP)
	// payload (imediat de dupa ip header)
	// Copiem cei 64 biti inainte de a modifica payload-ul de dupa ip header in icmp(payload)
	memcpy(frame, eth_hdr, sizeof(struct ether_hdr));
	memcpy(frame + sizeof(struct ether_hdr), ip_hdr, sizeof(struct ip_hdr));
	// adaug header-ul icmp
	memcpy(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), icmp_hdr, sizeof(struct icmp_hdr));
	// adaug header-ul ip initial
	memcpy(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr));
	// pun cei 8 bytes din buffer-ul original
	memcpy(frame + sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), 8);

	// lucram cu frame-ul acum:
	eth_hdr = (struct ether_hdr *)frame;
	ip_hdr = (struct ip_hdr *)(frame + sizeof(struct ether_hdr));
	icmp_hdr = (struct icmp_hdr *)(frame + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// schimb adresele mac:
	uint8_t tmp_mac[6];
	memcpy(tmp_mac, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, tmp_mac, 6);
	// schimb adresele ip:
	uint32_t tmp_ip = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	// resetez ttl:
	ip_hdr->ttl = 64;
	// calculez checksum ip + icmp
	ip_hdr->checksum = 0;
	checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
	icmp_hdr->check = 0;
	checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr));
	// schimbam dimensiunea ip_hdr
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	ip_hdr->proto = 1;
	//  trimit pachetul
	send_to_link(ICMP_PACKET_LEN, frame, interface);
}
/*
	@interface e interfata din tabela de rutare
	@ip e ip-ul caruia vrem sa ii gasim adresa mac
*/
void send_arp_req(int interface, uint32_t ip_dest)
{
	int len = ARP_PACKET_LEN;
	char *frame = calloc(len, sizeof(uint8_t));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)frame;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(frame + sizeof(struct ether_hdr));
	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
	arp_hdr->opcode = htons(ARP_OPCODE_REQ);   // request
	arp_hdr->proto_type = htons(ETHERTYPE_IP); // IPv4
	arp_hdr->hw_len = 6;					   // MAC length
	arp_hdr->proto_len = 4;					   // IPv4 length
	arp_hdr->hw_type = htons(1);			   // motivul pentru care nu primeam de la host raspuns
	memcpy(arp_hdr->shwa, eth_hdr->ethr_shost, 6);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	arp_hdr->tprotoa = ip_dest;
	send_to_link(len, frame, interface);
}

/*functie care trimite un arp reply*/
void send_arp_reply(char *frame, int len, int interface)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *)frame;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(frame + sizeof(struct ether_hdr));
	uint8_t temp_mac[6];
	memcpy(temp_mac, eth_hdr->ethr_shost, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	memcpy(eth_hdr->ethr_dhost, temp_mac, 6);
	eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
	arp_hdr->opcode = htons(ARP_OPCODE_RECV);	 // request
	arp_hdr->proto_type = htons(ETHERTYPE_IP);	 // IPv4
	arp_hdr->hw_len = 6;						 // MAC length
	arp_hdr->proto_len = 4;						 // IPv4 length
	memcpy(arp_hdr->thwa, temp_mac, 6);			 // punem adresa mac destinatie in arp
	get_interface_mac(interface, arp_hdr->shwa); // punem adresa mac sursa in arp
	// inversam adresele ip
	uint32_t tmp_ip = arp_hdr->sprotoa;
	arp_hdr->sprotoa = arp_hdr->tprotoa;
	arp_hdr->tprotoa = tmp_ip;

	send_to_link(len, frame, interface);
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
	struct arp_table_entry *arp_table = calloc(8, sizeof(struct arp_table_entry));
	int arp_table_len = 0;
	//________________________coada si initializarea ei____________________________________
	struct queue *packets = create_queue();

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
			if (ip_hdr->dest_addr == ip_hdr->source_addr)
			{
				send_icmp(buf, interface, 11, 0);
				continue;
			}
			if (ip_hdr->dest_addr == ip_interfata)
			{
				printf("Adresa destinatie este chiar cea a routerului");
				// trebuie sa verific daca e de tip icmp
				if (ip_hdr->proto == 1)
				{
					send_icmp(buf, interface, 0, 0);
				}
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
				// o pun doar pt test
				// verificam ttl:
				// ttl-ul nu il inversez ca e pe 8 biti si o sa fie acelasi
				// si pe little endian si pe big endian
				struct node *best_match = best_match_node(prefix_tree_root, ntohl(ip_hdr->dest_addr));
				// struct route_table_entry *route_match = find_route_table_match(route_table, route_table_len, ip_hdr->dest_addr);
				if (best_match == NULL)
				{
					// trimite catre un host necunoscut
					// TO DO: ICMP de tip Destination unreachable
					// nu exista destinatie pentru acest caz
					send_icmp_dest(buf, interface);
					continue;
				}
				struct route_table_entry *route_match = best_match->info;
				if (route_match == NULL)
				{
					send_icmp_dest(buf, interface);
					continue;
				}
				if (ip_hdr->ttl <= 1)
				{
					// va trebui sa intorc la sursa un pachet ICMP cu mesajul Time exceded
					// trebuie modificat header-ul curent sa trimita unde trebuie
					send_icmp_time(buf, interface);
					continue;
				}

				ip_hdr->ttl = ip_hdr->ttl - 1;

				// trimiterea pachetului

				ip_hdr->checksum = 0;
				new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
				ip_hdr->checksum = htons(new_checksum);
				// implementare logica arp
				struct arp_table_entry *arp_entry = find_arp_entry(arp_table, arp_table_len, route_match->next_hop);
				get_interface_mac(route_match->interface, eth_hdr->ethr_shost);
				if (arp_entry == NULL)
				{
					void *packet = malloc(MAX_PACKET_LEN);
					memcpy(packet, buf, MAX_PACKET_LEN);
					queue_enq(packets, (void *)packet);
					send_arp_req(route_match->interface, route_match->next_hop);
				}
				else
				{
					memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
					send_to_link(len, buf, route_match->interface);
				}
			}
			break;

		case ETHERTYPE_ARP:
		{

			// de impementat ARP
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + (sizeof(struct ether_hdr)));
			if (ntohs(arp_hdr->opcode) == ARP_OPCODE_REQ)
			{
				uint32_t ip_sursa = ntohl(arp_hdr->sprotoa); // sursa ca vreau sa ma intorc cu raspuns
															 // aflam val urm nod
				send_arp_reply(buf, len, interface);
			}
			else if (ntohs(arp_hdr->opcode) == ARP_OPCODE_RECV)
			{
				// inseamna ca am primit un reply si trebuie sa parcurg toate
				// pachetele din coada si sa le trimit
				// pun in tabela perechea de ip si mac
				arp_table[arp_table_len].ip = arp_hdr->sprotoa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
				arp_table_len++;
				queue new_queue = create_queue();
				while (!queue_empty(packets))
				{
					char *pkt = queue_deq(packets);

					struct ether_hdr *eth_hdr = (struct ether_hdr *)pkt;
					struct ip_hdr *ip_hdr = (struct ip_hdr *)(pkt + sizeof(struct ether_hdr));

					struct route_table_entry *best_match = best_match_node(prefix_tree_root, ntohl(ip_hdr->dest_addr))->info;
					if (best_match == NULL)
					{
						// trimite catre un host necunoscut
						// TO DO: ICMP de tip Destination unreachable
						// nu exista destinatie pentru acest caz
						send_icmp_dest(buf, interface);
						continue;
					}
					if (arp_hdr->sprotoa == best_match->next_hop)
					{
						memcpy(eth_hdr->ethr_dhost, arp_hdr->shwa, 6);
						send_to_link(MAX_PACKET_LEN, pkt, best_match->interface);
						free(pkt);
					}
					else
					{
						// daca nu o sa pun pachetul inapoi in noua coada
						queue_enq(new_queue, pkt);
					}
				}
				// coada veche devine noua coada
				packets = new_queue;
			}

			break;
		}
		default:
			printf("Routerul nu cunoaste acest tip de protocol, dam drop la pachet");
			continue;
		}
	}
}

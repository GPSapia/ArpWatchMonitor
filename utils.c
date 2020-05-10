#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

char error_buff[PCAP_ERRBUF_SIZE];
char src_mac[6];
pcap_t* session;

void parse_mac (char* string_mac, char* mac)
{
  int i = 0;
  char* octet = strtok (string_mac, ":");

  while (octet)
  {
      mac[i] = (unsigned char)strtol(octet, NULL, 16);
      octet = strtok (NULL, ":");
      i++;
  }
}

void get_mac_address(char* mac, char* nic)
{
    char tmp_mac_buffer[17];
    size_t i = 0;

    char file_name[255];
    strcpy (file_name, "/sys/class/net/");
    strcat (file_name, nic);
    strcat (file_name, "/address");
    FILE* mac_file = fopen(file_name, "r");

    if (mac_file == NULL)
    {
      perror("Error while opening mac file\n");
      exit(1);
    }
    fgets (tmp_mac_buffer, 18, mac_file);

    parse_mac (tmp_mac_buffer, mac);

    fclose(mac_file);
}

void init_session(char* nic)
{
    session = pcap_open_live (nic, BUFSIZ, false, 0, error_buff);
    if (!session)
    {
      printf("%s\n", error_buff);
      exit(1);
    }
    get_mac_address (src_mac, nic);
}

void send_packet (char* nic, char* dst_mac, char* eth_type, char* message, int message_length)
{
    char destination_mac[6];

    char* packet = malloc (sizeof(char) * message_length);
    parse_mac (dst_mac, destination_mac);

    memset (packet, 0, 14+message_length);

    memcpy (packet, destination_mac, 6);                  //destination mac (broadcast)
    memcpy (packet+6, src_mac, 6);                        //source mac
    memcpy (packet+12, eth_type, 2);                      //hardware type
    memcpy (packet+14, message, message_length);

    if (pcap_inject(session, packet, 14+message_length) == -1)
      fprintf (stderr, "%s\n", "error while sending packet");

    free (packet);
}

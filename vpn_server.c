#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 16
#define CLIENT_TIMEOUT 60 // seconds

typedef struct {
  uint32_t vpn_ip;
  struct sockaddr_in real_addr;
  time_t last_active;
  int active;
} vpn_peer_t;

vpn_peer_t clients[MAX_CLIENTS];

int tun_alloc(char *dev) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Greska pri otvaranju /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet information
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
    perror("Greska pri postavljanju TUN/PPP interfejsa");
    close(fd);
    return -1;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

void update_client(uint32_t vpn_ip, struct sockaddr_in *real_addr) {
  time_t now = time(NULL);
  int free_slot = -1;

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active && clients[i].vpn_ip == vpn_ip) {
      clients[i].real_addr = *real_addr;
      clients[i].last_active = now;
      return;
    }
    if (!clients[i].active && free_slot == -1) {
      free_slot = i;
    }
  }

  if (free_slot != -1) {
    clients[free_slot].vpn_ip = vpn_ip;
    clients[free_slot].real_addr = *real_addr;
    clients[free_slot].last_active = now;
    clients[free_slot].active = 1;

    char real_ip_str[INET_ADDRSTRLEN];
    char vpn_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &real_addr->sin_addr, real_ip_str, sizeof(real_ip_str));
    inet_ntop(AF_INET, &vpn_ip, vpn_ip_str, sizeof(vpn_ip_str));
    printf("[SERVER] Novi klijent dodan: %s:%d -> VPN IP: %s\n", real_ip_str,
           ntohs(real_addr->sin_port), vpn_ip_str);
    fflush(stdout);
  }
}

vpn_peer_t *find_client_by_vpn_ip(uint32_t vpn_ip) {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active && clients[i].vpn_ip == vpn_ip) {
      return &clients[i];
    }
  }
  return NULL;
}

int main() {
  if (sodium_init() < 0) {
    perror("Greska pri inicijalizaciji libsodiuma");
    return 1;
  }

  unsigned char shared_key[crypto_secretbox_KEYBYTES] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

  char tun_name[IFNAMSIZ] = "tun0";
  char buffer[2000];

  int tun_fd = tun_alloc(tun_name);
  if (tun_fd < 0) {
    perror("Greska pri kreiranju TUN sucelja");
    return 1;
  }
  system("ip addr add 10.0.0.1/24 dev tun0");
  system("ip link set tun0 mtu 1400");
  system("ip link set tun0 up");
  printf("[SERVER] tun0 kreirano (10.0.0.1) s MTU 1400.\n");

  int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in client_addr, server_addr;
  memset(&server_addr, 0, sizeof(server_addr));

  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(55555);

  if (bind(udp_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("Greska pri povezivanju UDP soketa");
    close(udp_fd);
    close(tun_fd);
    return -1;
  }

  memset(clients, 0, sizeof(clients));

  printf("[SERVER] Slusam na UDP portu 55555...\n");

  int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;
  socklen_t client_len = sizeof(client_addr);
  int client_connected = 0;

  while (1) {
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(tun_fd, &rd_set);
    FD_SET(udp_fd, &rd_set);

    int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

    select(max_fd + 1, &rd_set, NULL, NULL, NULL);

    if (FD_ISSET(udp_fd, &rd_set)) {
      struct sockaddr_in sender_addr;
      socklen_t sender_len = sizeof(sender_addr);
      int nread = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&sender_addr, &sender_len);

      // Minimalna velicina paketa mora biti Nonce + MAC
      if (nread > (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)) {

        // 1. Izdvajamo Nonce iz primljenog paketa
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        memcpy(nonce, buffer, sizeof(nonce));

        // 2. Izračunavamo veličinu kriptiranog dijela i originala
        int cipher_len = nread - crypto_secretbox_NONCEBYTES;
        int original_len = cipher_len - crypto_secretbox_MACBYTES;

        unsigned char decrypted[original_len];

        // 3. Pokušavamo dekriptirati i provjeriti autenticnost paketa!
        if (crypto_secretbox_open_easy(
                decrypted,
                (unsigned char *)(buffer + crypto_secretbox_NONCEBYTES),
                cipher_len, nonce, shared_key) != 0) {
          // Netko je presreo i pokusao promijeniti paket!
          printf("[UPOZORENJE] Uhvacen neispravan ili modificiran paket! "
                 "Odbacujem...\n");
        } else {
          if (original_len >= sizeof(struct iphdr)) {
            struct iphdr *ip_header = (struct iphdr *)decrypted;

            uint32_t vpn_ip = ip_header->saddr;
            update_client(vpn_ip, &sender_addr);

            write(tun_fd, decrypted, original_len);
            printf("[SERVER] Dekriptiran paket (%d bajtova) gurnut u TUN\n",
                   original_len);
            fflush(stdout);
          }
        }
      }
    }

    if (FD_ISSET(tun_fd, &rd_set)) {
      int nread = read(tun_fd, buffer, sizeof(buffer));

      if (nread <= 0) {
        perror("Greska pri citanju iz TUN sucelja");
        break;
      }

      if (nread >= sizeof(struct iphdr)) {
        struct iphdr *iph = (struct iphdr *)buffer;

        // Tražimo klijenta prema odredišnom IP-u (daddr)
        vpn_peer_t *peer = find_client_by_vpn_ip(iph->daddr);

        if (peer != NULL) {
          unsigned char nonce[crypto_secretbox_NONCEBYTES];
          randombytes_buf(nonce, sizeof(nonce));

          unsigned char ciphertext[nread + crypto_secretbox_MACBYTES];
          crypto_secretbox_easy(ciphertext, (unsigned char *)buffer, nread,
                                nonce, shared_key);

          int final_len = sizeof(nonce) + sizeof(ciphertext);
          unsigned char final_packet[final_len];

          memcpy(final_packet, nonce, sizeof(nonce));
          memcpy(final_packet + sizeof(nonce), ciphertext, sizeof(ciphertext));

          sendto(udp_fd, final_packet, final_len, 0,
                 (struct sockaddr *)&peer->real_addr, sizeof(peer->real_addr));

          printf("[SERVER -> KLIJENT] Poslan kriptirani paket (%d bajtova)\n",
                 final_len);
          fflush(stdout);
        }
      }
    }
  }
  close(tun_fd);
  close(udp_fd);
  return 0;
}
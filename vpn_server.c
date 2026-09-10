#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sodium.h>
#include <sodium/crypto_kx.h>
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

  unsigned char tx[crypto_kx_SESSIONKEYBYTES]; // TX key
  unsigned char rx[crypto_kx_SESSIONKEYBYTES]; // RX key
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

void update_client(uint32_t vpn_ip, struct sockaddr_in *real_addr,
                   const unsigned char *client_pk,
                   const unsigned char *server_pk,
                   const unsigned char *server_sk) {
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

    if (crypto_kx_server_session_keys(clients[free_slot].rx,
                                      clients[free_slot].tx, server_pk,
                                      server_sk, client_pk) != 0) {
      fprintf(stderr, "Greska pri generiranju sesijskih kljuceva!\n");
      clients[free_slot].active = 0;
      return;
    }

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

vpn_peer_t *find_client_by_real_addr(struct sockaddr_in *real_addr) {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active &&
        clients[i].real_addr.sin_addr.s_addr == real_addr->sin_addr.s_addr &&
        clients[i].real_addr.sin_port == real_addr->sin_port) {
      return &clients[i];
    }
  }
  return NULL;
}

void cleanup_inactive_clients() {
  time_t now = time(NULL);
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].active && (now - clients[i].last_active > CLIENT_TIMEOUT)) {
      char real_ip_str[INET_ADDRSTRLEN];
      char vpn_ip_str[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &clients[i].real_addr.sin_addr, real_ip_str,
                sizeof(real_ip_str));
      inet_ntop(AF_INET, &clients[i].vpn_ip, vpn_ip_str, sizeof(vpn_ip_str));
      printf("[SERVER] Klijent isključen zbog neaktivnosti: %s:%d -> VPN IP: "
             "%s\n",
             real_ip_str, ntohs(clients[i].real_addr.sin_port), vpn_ip_str);
      fflush(stdout);

      clients[i].active = 0;
      clients[i].vpn_ip = 0;
      memset(&clients[i].real_addr, 0, sizeof(clients[i].real_addr));
    }
  }
}

int main() {
  // Server's static key pair (for demonstration purposes)
  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES] = {
      0x8B, 0xA4, 0x70, 0x61, 0xA7, 0x15, 0xDA, 0x3F, 0x36, 0xE5, 0x2D,
      0x31, 0xF0, 0xEB, 0x8E, 0x39, 0x94, 0xBD, 0x88, 0xB5, 0xA4, 0x01,
      0x0F, 0xAC, 0xAD, 0x51, 0x39, 0x84, 0xF7, 0xFB, 0x61, 0x56};

  unsigned char server_sk[crypto_kx_SECRETKEYBYTES] = {
      0xDE, 0x6D, 0xAC, 0xED, 0x7C, 0xC0, 0x7A, 0x0B, 0x45, 0xFA, 0x89,
      0xAB, 0x6D, 0xDC, 0x5A, 0xC5, 0xBD, 0xC5, 0xCB, 0xF4, 0xD0, 0x1B,
      0xA5, 0xD9, 0x06, 0x0D, 0x07, 0x3C, 0xFA, 0x1D, 0x2C, 0x1B};

  // Client's static public key (for demonstration purposes)
  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES] = {
      0xB9, 0x0E, 0xAF, 0xEC, 0x57, 0x34, 0x88, 0xED, 0x77, 0xAC, 0x69,
      0x1E, 0xE9, 0x88, 0xBA, 0x40, 0xE0, 0x60, 0xD5, 0x92, 0xD9, 0x09,
      0xF0, 0x60, 0xC1, 0x2C, 0x27, 0xAF, 0x06, 0x10, 0x50, 0x39};

  if (sodium_init() < 0) {
    perror("Greska pri inicijalizaciji libsodiuma");
    return 1;
  }

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

  static unsigned char default_rx[crypto_kx_SESSIONKEYBYTES];
  static unsigned char default_tx[crypto_kx_SESSIONKEYBYTES];

  if (crypto_kx_server_session_keys(default_rx, default_tx, server_pk,
                                    server_sk, client_pk) != 0) {
    fprintf(stderr, "Greska pri generiranju sesijskih kljuceva!\n");
    return -1;
  }

  while (1) {
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(tun_fd, &rd_set);
    FD_SET(udp_fd, &rd_set);

    int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

    struct timeval timeout;
    timeout.tv_sec = 5; // Check every 5 seconds
    timeout.tv_usec = 0;

    int ret = select(max_fd + 1, &rd_set, NULL, NULL, &timeout);
    if (ret < 0) {
      perror("Greska pri selectu");
      break;
    }

    cleanup_inactive_clients();

    if (ret == 0) {
      continue; // Timeout occurred, go back to select
    }

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

        vpn_peer_t *client = find_client_by_real_addr(&sender_addr);
        int decryption_success = 0;

        if (client != NULL) {
          // 3. Pokušavamo dekriptirati i provjeriti autenticnost paketa!
          if (crypto_secretbox_open_easy(
                  decrypted,
                  (unsigned char *)(buffer + crypto_secretbox_NONCEBYTES),
                  cipher_len, nonce, client->rx) == 0) {
            decryption_success = 1;
          }
        } else {
          if (crypto_secretbox_open_easy(
                  decrypted,
                  (unsigned char *)(buffer + crypto_secretbox_NONCEBYTES),
                  cipher_len, nonce, default_rx) == 0) {
            decryption_success = 1;
          }
        }
        // 3. Pokušavamo dekriptirati i provjeriti autenticnost paketa!
        if (!decryption_success) {
          printf("[UPOZORENJE] Uhvacen neispravan ili modificiran paket! "
                 "Odbacujem...\n");
          continue;
        } else {
          if (original_len >= sizeof(struct iphdr)) {
            struct iphdr *ip_header = (struct iphdr *)decrypted;

            uint32_t vpn_ip = ip_header->saddr;
            update_client(vpn_ip, &sender_addr, client_pk, server_pk,
                          server_sk);

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
        continue;
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
                                nonce, peer->tx);

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

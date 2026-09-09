#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_tun_fd = -1;
static int g_udp_fd = -1;
static char g_tun_name[IFNAMSIZ] = {0};

void handle_sigint(int sig) {
  (void)sig;
  printf("\n[CLIENT] Zatvaram TUN sucelje i UDP soket...\n");
  if (g_tun_name[0] != '\0') {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s down", g_tun_name);
    system(cmd);
    printf("[CLIENT] %s iskljuceno.\n", g_tun_name);
  }

  if (g_tun_fd >= 0)
    close(g_tun_fd);

  if (g_udp_fd >= 0)
    close(g_udp_fd);

  printf("[CLIENT] Zatvaranje dovrseno. Izlazim...\n");
  fflush(stdout);
  exit(0);
}

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

int main(int argc, char *argv[]) {
  signal(SIGINT, handle_sigint);
  char tun_name[IFNAMSIZ] = "tun1";
  char client_ip[32] = "10.0.0.2";
  char buffer[2000];

  strncpy(g_tun_name, tun_name, sizeof(g_tun_name) - 1);

  if (argc > 1) {
    strncpy(tun_name, argv[1], IFNAMSIZ - 1);
    tun_name[IFNAMSIZ - 1] = '\0';
  }
  if (argc > 2) {
    strncpy(client_ip, argv[2], sizeof(client_ip) - 1);
    client_ip[sizeof(client_ip) - 1] = '\0';
  }

  if (sodium_init() < 0) {
    fprintf(stderr, "Greška pri inicijalizaciji Libsodiuma!");
    return -1;
  }

  unsigned char shared_key[crypto_secretbox_KEYBYTES] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

  int tun_fd = tun_alloc(tun_name);
  if (tun_fd < 0) {
    perror("Greska pri kreiranju TUN sucelja");
    return 1;
  }
  g_tun_fd = tun_fd;

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", client_ip, tun_name);
  system(cmd);
  snprintf(cmd, sizeof(cmd), "ip link set %s mtu 1400 up", tun_name);
  system(cmd);

  printf("[CLIENT] sucelje %s VPN IP: %s\n", tun_name, client_ip);
  fflush(stdout);

  int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd < 0) {
    perror("Greska pri kreiranju UDP soketa");
    close(tun_fd);
    exit(1);
  }
  g_udp_fd = udp_fd;

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(55555);
  inet_pton(AF_INET, "192.168.1.212", &server_addr.sin_addr);

  printf("[CLIENT] Tunel usmjeren prema 192.168.1.212:55555\n");

  int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

  while (1) {
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(tun_fd, &rd_set);
    FD_SET(udp_fd, &rd_set);

    select(max_fd + 1, &rd_set, NULL, NULL, NULL);

    if (FD_ISSET(tun_fd, &rd_set)) {
      int nread = read(tun_fd, buffer, sizeof(buffer));
      if (nread > 0) {
        // 1. Generiramo nasumicni Nonce za ovaj paket
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        // 2. Alociramo memoriju za kriptirani dio (original + MAC)
        unsigned char ciphertext[nread + crypto_secretbox_MACBYTES];

        // 3. Kriptiramo podatke (buffer -> ciphertext)
        crypto_secretbox_easy(ciphertext, (unsigned char *)buffer, nread, nonce,
                              shared_key);

        // 4. Slazemo finalni paket: [ NONCE | CIPHERTEXT ]
        int final_len = sizeof(nonce) + sizeof(ciphertext);
        unsigned char final_packet[final_len];

        memcpy(final_packet, nonce, sizeof(nonce));
        memcpy(final_packet + sizeof(nonce), ciphertext, sizeof(ciphertext));

        // 5. Šaljemo kriptirani UDP paket
        int sent = sendto(udp_fd, final_packet, final_len, 0,
                          (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent > 0) {
          printf("[KLIJENT -> SERVER] Poslan kriptirani paket (%d bajtova)\n",
                 sent);
          fflush(stdout);
        }
      }
    }

    if (FD_ISSET(udp_fd, &rd_set)) {
      struct sockaddr_in from_addr;
      socklen_t from_len = sizeof(from_addr);
      int nread = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&from_addr, &from_len);

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
          // Paket je legitiman, gurni ga u virtualnu mrezu
          write(tun_fd, decrypted, original_len);
          printf("[SERVER -> KLIJENT] Dekriptiran paket (%d bajtova) gurnut u "
                 "TUN\n",
                 original_len);
          fflush(stdout);
        }
      }
    }
  }

  return 0;
}
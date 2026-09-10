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

#define SERVER_IP "130.61.60.21"

static int g_tun_fd = -1;
static int g_udp_fd = -1;
static char g_tun_name[IFNAMSIZ] = {0};

void handle_sigint(int sig) {
  (void)sig;
  printf("\n[CLIENT] Vracam mrezne postavke i gasim VPN...\n");

  // --- NOVO: CISCENJE RUTA I VRACANJE MREZE PRI PREKIDU (Ctrl+C) ---
  if (g_tun_name[0] != '\0') {
    char cmd[256];

    // 1. Ukloni VPN rute
    snprintf(cmd, sizeof(cmd), "ip route del 0.0.0.0/1 dev %s 2>/dev/null",
             g_tun_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route del 128.0.0.0/1 dev %s 2>/dev/null",
             g_tun_name);
    system(cmd);

    // 2. Ukloni staticku rutu do Oraclea
    snprintf(cmd, sizeof(cmd), "ip route del %s 2>/dev/null", SERVER_IP);
    system(cmd);

    // 3. Spusti sucelje
    snprintf(cmd, sizeof(cmd), "ip link set %s down", g_tun_name);
    system(cmd);
    printf("[CLIENT] %s iskljuceno i rute obrisane.\n", g_tun_name);
  }

  // Ukloni blokadu
  system("ip -6 route del unreachable default metric 1 2>/dev/null");

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
  // Client's static key pair (generated using keygen.c)
  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES] = {
      0xB9, 0x0E, 0xAF, 0xEC, 0x57, 0x34, 0x88, 0xED, 0x77, 0xAC, 0x69,
      0x1E, 0xE9, 0x88, 0xBA, 0x40, 0xE0, 0x60, 0xD5, 0x92, 0xD9, 0x09,
      0xF0, 0x60, 0xC1, 0x2C, 0x27, 0xAF, 0x06, 0x10, 0x50, 0x39};
  unsigned char client_sk[crypto_kx_SECRETKEYBYTES] = {
      0x3F, 0xDB, 0x8D, 0x2B, 0x51, 0x13, 0xFE, 0x48, 0x6E, 0x47, 0xA1,
      0xE8, 0x06, 0x52, 0x41, 0xAD, 0x5D, 0xBB, 0x71, 0xF4, 0x42, 0xEF,
      0x2A, 0xF1, 0xFC, 0xA7, 0x81, 0xD7, 0xA9, 0x9A, 0xAB, 0x2A};

  // Server's static public key (generated using keygen.c)
  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES] = {
      0x8B, 0xA4, 0x70, 0x61, 0xA7, 0x15, 0xDA, 0x3F, 0x36, 0xE5, 0x2D,
      0x31, 0xF0, 0xEB, 0x8E, 0x39, 0x94, 0xBD, 0x88, 0xB5, 0xA4, 0x01,
      0x0F, 0xAC, 0xAD, 0x51, 0x39, 0x84, 0xF7, 0xFB, 0x61, 0x56};

  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];

  if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk,
                                    server_pk) != 0) {
    fprintf(stderr, "Greska pri generiranju sesijskih kljuceva!\n");
    return -1;
  }

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

  // --- NOVO: DODAVANJE RUTA I GASENJE IPV6 ODMAH NAKON PODIZANJA TUN-a ---
  // Umjesto sysctl-a: blokiraj sav IPv6 promet dok radi VPN (nema curenja)
  system("ip -6 route add unreachable default metric 1 2>/dev/null");

  // 2. Statička ruta do Oraclea preko kućnog rutera (da tunel ne pukne sam u
  // sebe)
  snprintf(cmd, sizeof(cmd),
           "ip route add %s via 192.168.1.1 dev wlan0 2>/dev/null", SERVER_IP);
  system(cmd);

  // 3. Preusmjeri sav internet promet kroz tun1
  snprintf(cmd, sizeof(cmd), "ip route replace 0.0.0.0/1 dev %s", tun_name);
  system(cmd);
  snprintf(cmd, sizeof(cmd), "ip route replace 128.0.0.0/1 dev %s", tun_name);
  system(cmd);
  printf("[CLIENT] Rute postavljene: sav promet ide kroz %s\n", tun_name);
  fflush(stdout);
  // ----------------------------------------------------------------------

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
  inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

  printf("[CLIENT] Tunel usmjeren prema %s:55555\n", SERVER_IP);

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
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        unsigned char ciphertext[nread + crypto_secretbox_MACBYTES];
        crypto_secretbox_easy(ciphertext, (unsigned char *)buffer, nread, nonce,
                              client_tx);

        int final_len = sizeof(nonce) + sizeof(ciphertext);
        unsigned char final_packet[final_len];

        memcpy(final_packet, nonce, sizeof(nonce));
        memcpy(final_packet + sizeof(nonce), ciphertext, sizeof(ciphertext));

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

      if (nread > (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)) {
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        memcpy(nonce, buffer, sizeof(nonce));

        int cipher_len = nread - crypto_secretbox_NONCEBYTES;
        int original_len = cipher_len - crypto_secretbox_MACBYTES;

        unsigned char decrypted[original_len];

        if (crypto_secretbox_open_easy(
                decrypted,
                (unsigned char *)(buffer + crypto_secretbox_NONCEBYTES),
                cipher_len, nonce, client_rx) != 0) {
          printf("[UPOZORENJE] Uhvacen neispravan ili modificiran paket! "
                 "Odbacujem...\n");
        } else {
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
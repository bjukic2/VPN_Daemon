#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

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

int main() {

  if (sodium_init() < 0) {
    fprintf(stderr, "Greska pri inicijalizaciji libsodium\n");
    return -1;
  }

  unsigned char shared_key[crypto_secretbox_KEYBYTES] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

  char tun_name[IFNAMSIZ] = "tun1";
  char buffer[2000];

  int tun_fd = tun_alloc(tun_name);
  if (tun_fd < 0) {
    exit(1);
  }

  system("ip addr add 10.0.0.2/24 dev tun1");
  system("ip link set tun1 up");
  printf("[CLIENT] tun1 kreiran (10.0.0.2).\n");

  int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd < 0) {
    perror("Greska pri kreiranju UDP soketa");
    close(tun_fd);
    exit(1);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(55555);
  inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

  printf("[CLIENT] Tunel usmjeren prema 127.0.0.1:55555\n");

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
        }
      }
    }
  }

  return 0;
}
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2) {
    sum += *buf++;
  }
  if (len == 1) {
    sum += *(unsigned char *)buf;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

int main() {
  char tun_name[IFNAMSIZ] = "tun0";
  char buffer[1500]; // Maksimalna velicina paketa za TUN sucelje

  printf("Inicijaliziram vlastito mrezno sucelje...\n");
  int tun_fd = tun_alloc(tun_name);

  if (tun_fd < 0) {
    fprintf(stderr, "Neuspjesno kreiranje TUN sucelja\n");
    exit(1);
  }

  system("ip addr add 10.0.0.1/24 dev tun0");
  system("ip link set tun0 up");

  int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd < 0) {
    perror("Greska pri kreiranju UDP soketa");
    close(tun_fd);
    exit(1);
  }

  struct sockaddr_in client_addr;
  memset(&client_addr, 0, sizeof(client_addr));
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  client_addr.sin_port = htons(44444);

  if (bind(udp_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
    perror("Greska pri bindanju UDP soketa");
    close(udp_fd);
    close(tun_fd);
    exit(1);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(55555);
  inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

  printf("UDP socket je kreiran i vezan na port 44444. Cekam na pakete...\n");

  int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

  while (1) {
    fd_set rd_set;
    FD_ZERO(&rd_set);        // Lista za nadzor se cisti
    FD_SET(tun_fd, &rd_set); // Dodaje se tun socket u listu za nadzor
    FD_SET(udp_fd, &rd_set); // Dodaje se udp socket u listu za nadzor

    int ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0) {
      perror("Greska pri selectu");
      break;
    }

    if (FD_ISSET(tun_fd, &rd_set)) {
      int nread = read(tun_fd, buffer, sizeof(buffer));
      if (nread < 0) {
        perror("Greska pri citanju iz TUN sucelja");
        break;
      }
      printf("Primljen paket od TUN sucelja, velicina: %d\n", nread);
      sendto(udp_fd, buffer, nread, 0, (struct sockaddr *)&server_addr,
             sizeof(server_addr));
    }

    if (FD_ISSET(udp_fd, &rd_set)) {
      struct sockaddr_in src_addr;
      socklen_t addrlen = sizeof(src_addr);
      int nread = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&src_addr, &addrlen);
      if (nread < 0) {
        perror("Greska pri primanju paketa sa UDP soketa");
        break;
      }
      printf("Primljen paket od UDP soketa, velicina: %d\n", nread);
      write(tun_fd, buffer, nread);
    }
  }

  close(udp_fd);
  close(tun_fd);
  printf("Zatvaram TUN sucelje i izlazim iz programa.\n");
  return 0;
}
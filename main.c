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
    perror("Greska pri kreiranju UDP socketa");
    exit(1);
  }

  struct sockaddr_in udp_addr;
  memset(&udp_addr, 0, sizeof(udp_addr));
  udp_addr.sin_family = AF_INET;
  udp_addr.sin_port = htons(55555);

  inet_pton(AF_INET, "127.0.0.1", &udp_addr.sin_addr);

  printf("UDP socket kreiran i spreman za slanje paketa.\n");

  while (1) {
    int nread = read(tun_fd, buffer, sizeof(buffer));
    if (nread < 0) {
      perror("Greska pri citanju iz TUN sucelja");
      break;
    }

    struct iphdr *ip_header = (struct iphdr *)buffer;
    if (ip_header->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp_header =
          (struct icmphdr *)(buffer + sizeof(struct iphdr));
      if (icmp_header->type == ICMP_ECHO) {
        printf("Primljen ICMP echo request. Slanje odgovora...\n");
        icmp_header->type = ICMP_ECHOREPLY;
        icmp_header->checksum = 0;
        icmp_header->checksum =
            checksum(icmp_header, nread - sizeof(struct iphdr));

        sendto(udp_fd, buffer, nread, 0, (struct sockaddr *)&udp_addr,
               sizeof(udp_addr));
      }
    }
  }
  close(udp_fd);
  close(tun_fd);
  printf("Zatvaram TUN sucelje i izlazim iz programa.\n");
  return 0;
}
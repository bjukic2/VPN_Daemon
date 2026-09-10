#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

void print_hex_array(const char *var_name, const unsigned char *data,
                     size_t length) {
  printf("unsigned char %s[%zu]: ", var_name, length);
  for (size_t i = 0; i < length; i++) {
    printf("0x%02X%s", data[i], (i + 1 < length) ? ", " : "");
    if ((i + 1) % 8 == 0 && (i + 1) < length) {
      printf("\n    ");
    }
  }
  printf("\n};\n\n");
}

int main(void) {
  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    return EXIT_FAILURE;
  }

  unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_kx_SECRETKEYBYTES];

  crypto_kx_keypair(public_key, secret_key);

  char public_key_hex[crypto_kx_PUBLICKEYBYTES * 2 + 1];
  char secret_key_hex[crypto_kx_SECRETKEYBYTES * 2 + 1];

  sodium_bin2hex(public_key_hex, sizeof(public_key_hex), public_key,
                 sizeof(public_key));
  sodium_bin2hex(secret_key_hex, sizeof(secret_key_hex), secret_key,
                 sizeof(secret_key));

  printf("============================================================\n");
  printf("                  NOVI PAR KLJUČEVA (Curve25519)            \n");
  printf("============================================================\n\n");

  printf("--- HEX STRING FORMAT ---\n");
  printf("Javni ključ  (Public):  %s\n", public_key_hex);
  printf("Tajni ključ  (Private): %s\n\n", secret_key_hex);

  printf("--- FORMAT ZA C KOD (Copy-Paste) ---\n");
  print_hex_array("public_key", public_key, sizeof(public_key));
  print_hex_array("secret_key", secret_key, sizeof(secret_key));

  return 0;
}

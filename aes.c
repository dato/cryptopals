#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DECRYPT_KEY "YELLOW SUBMARINE"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "%s FILE\n", argv[0]);
    return 1;
  }

  int fd;
  int ret = 3; // Used during cleanup.
  struct stat stbuf;

  if ((fd = open(argv[1], O_RDONLY)) < 0 || fstat(fd, &stbuf) < 0) {
    perror("open");
    goto close;
  }

  uint8_t *in = NULL;
  uint8_t *out = NULL;
  size_t fsize = (size_t) stbuf.st_size;
  ssize_t bytes_read = 0;

  if (!(in = calloc(1, fsize + 16)) || !(out = calloc(1, fsize + 1)) ||
      ((bytes_read = read(fd, in, fsize)) < stbuf.st_size)) {
    if (out == NULL) {
      perror("calloc");
    } else if (bytes_read < 0) {
      perror("read");
    } else {
      fprintf(stderr, "Read %zu bytes, expected %zu\n", bytes_read, fsize);
    }
    goto free;
  }

  EVP_CIPHER_CTX ctx, *x = &ctx;
  const unsigned char key[] = DECRYPT_KEY;

  const EVP_CIPHER *cipher = EVP_aes_128_ecb();
  EVP_DecryptInit(x, cipher, key, NULL);
  EVP_CIPHER_CTX_set_padding(x, false);

  int bytes_out = 0;

  if (!EVP_DecryptUpdate(x, out, &bytes_out, in, (int) fsize) ||
      bytes_out != (int) fsize) {
    goto cleanup;
  }
  // FIXME: need to call EVP_DecryptFinal() if padding is disabled?
  printf("%s\n", out);
  ret--;

 cleanup:
  EVP_CIPHER_CTX_cleanup(x);
 free:
  free(in);
  free(out);
  ret--;
 close:
  if (fd >= 0)
    close(fd);
  ret--;

  return ret;
}

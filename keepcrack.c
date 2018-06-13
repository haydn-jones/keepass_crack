#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "keepcrack.h"
#include "decrypt.h"

// Useful hexdump command: hexdump -v -e '"%04_ad "' -e '4/1 "%.2X "' -e '"\n"' database.kdbx | less
void print_header_info(struct header_info_t hi, int ret);
void print_header_values(struct header_values_t hv, int ret);
void usage();

int main(int argc, char **argv)
{
        uint8_t *file_buf = NULL;
        int fd, opt, ret;
        off_t filesize;
        ssize_t nread;
        struct header_info_t header_info;
        struct header_values_t header_values;
        header_values.comment = NULL;

        fd = -1;
        while ((opt = getopt(argc, argv, "f:h")) != -1) {
                switch(opt) {
                case 'f':
                        if ((fd = open(optarg, O_RDONLY)) == -1) {
                                perror("Database");
                                exit(EXIT_FAILURE);
                        }

                        printf("Reading file: %s\n", optarg);
                        break;
                case 'h':
                default:
                        exit(EXIT_FAILURE);
                        break;
                }
        }

        if (fd == -1) {
                printf("File must be specified!\n");
                usage();
                exit(EXIT_FAILURE);
        }

        filesize = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        file_buf = malloc(sizeof(uint8_t) * filesize);

        while ((nread = read(fd, file_buf, filesize)) != filesize) {
                if (nread == -1 && errno != EINTR) {
                        perror("reading");
                        exit(EXIT_FAILURE);
                }
        }

        ret = fill_header_info(&header_info, file_buf);
        print_header_info(header_info, ret);
        if (ret) {
                printf("Invalid header info! Exiting...\n");
                exit(EXIT_FAILURE);
        }

        printf("\nBeginning header dump\n");
        ret = fill_header_values(&header_values, file_buf);
        if (ret & 0x10) {
                printf("Found invalid header field! Exiting...\n");
                exit(EXIT_FAILURE);
        }

        print_header_values(header_values, ret);
        if (ret) {
                printf("Exiting...\n");
                exit(EXIT_FAILURE);
        }

        decrypt_database();

        return 0;
}

void print_header_values(struct header_values_t hv, int ret)
{
        printf("[-] END:                 ");
        print_hex_stream(hv.end, hv.end_len, 1);

        printf("[-] COMMENT:             ");
        if (hv.comment != NULL) {
                print_hex_stream(hv.comment, hv.comment_len, 0);
        }
        puts("");

        if (ret & 0x1) {
                printf("[-] CIPHERID:            Unsupported CIPHERID!\n");
        } else {
                printf("[+] CIPHERID:            ");
                print_hex_stream(hv.cipherid, hv.cipherid_len, 1);
        }

        printf("[-] COMPRESSIONFLAGS:    ");
        print_hex_dword(hv.compressionflags, 1);

        printf("[-] MASTERSEED:          ");
        print_hex_stream(hv.masterseed, hv.masterseed_len, 1);

        printf("[-] TRANSFORMSEED:       ");
        print_hex_stream(hv.transformseed, hv.transformseed_len, 1);

        printf("[-] TRANSFORMROUNDS:     ");
        print_hex_qword(hv.transformrounds, 1);

        printf("[-] ENCRYPTIONIV:        ");
        print_hex_stream(hv.encryptioniv, hv.encryptioniv_len, 1);

        printf("[-] PROTECTEDSTREAMKEY:  ");
        print_hex_stream(hv.protectedstreamkey, hv.protectedstreamkey_len, 1);

        printf("[-] STREAMSTARTBYTES:    ");
        print_hex_stream(hv.streamstartbytes, hv.streamstartbytes_len, 1);

        printf("[-] INNERRANDOMSTREAMID: ");
        print_hex_dword(hv.innerrandomstreamid, 1);

        printf("[-] Enc Payload:         ");
        print_hex_stream(hv.payload, hv.streamstartbytes_len, 0);
        puts("...");
}

void print_header_info(struct header_info_t hi, int ret)
{
        if (ret && 0x1) {
                printf("[!] Invalid PID:         ");
        } else {
                printf("[+] Valid PID:           ");
        }
        print_hex_dword(hi.pid, 1);

        if (ret && 0x10) {
                printf("[!] Invalid SID:         ");
        } else {
                printf("[+] Valid SID:           ");
        }
        print_hex_dword(hi.sid, 1);

        printf("[-] File version:        ");
        print_hex_word(hi.file_version, 1);
        printf("[-] Major FID:           ");
        print_hex_word(hi.version_major, 1);
        printf("[-] Minor FID:           ");
        print_hex_word(hi.version_minor, 1);
}

void usage()
{
        printf("usage: ./keepcrack -f DATABASE [-h]\n");
        printf("\t-f specify location of database\n");
        printf("\t-h this useful help message\n");
}

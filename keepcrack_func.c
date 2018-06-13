#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "keepcrack.h"

static char *hexstr = "0123456789ABCDEF";

int fill_header_info(struct header_info_t *header_info, uint8_t *file_buf)
{
        uint32_t primary_id, secondary_id;
        uint16_t major_fid, minor_fid;
        uint8_t file_version;
        int err_flags = 0;

        primary_id = ((uint32_t *) file_buf)[0];                //First 4 bytes
        secondary_id = ((uint32_t *) file_buf)[1];              //Second 4 bytes
        file_version = secondary_id & 0xFF;                     //Lower byte of sid;

        minor_fid = ((uint16_t *) file_buf)[4];
        major_fid = ((uint16_t *) file_buf)[5];

        header_info->pid = primary_id;
        header_info->sid = secondary_id;
        header_info->version_minor = minor_fid;
        header_info->version_major = major_fid;
        header_info->file_version = file_version;

        if (primary_id != 0x9AA2D903) {                         //Magic number to check
                err_flags |= 0x1;
        } else if ((secondary_id & 0xFFFFFF00) != 0xB54BFB00) { //Second magic number
                err_flags |= 0x10;
        }

        return err_flags;
}

int validate_cipher_id(uint8_t *cipher, int length)
{
        int i = 0;
        uint8_t supported[] = {0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF};

        while (i < length) {
                if (cipher[i] != supported[i]) {
                        return -1;
                }

                i++;
        }

        return 0;
}

int fill_header_values(struct header_values_t *header_values, uint8_t *file_buf)
{
        uint8_t type;
        uint16_t length;
        int offset;
        uint8_t *tmp = NULL;
        int error_flags = 0;

        offset = 12; // Byte index of beginning of header values
        while (1) {
                type = *(file_buf + offset) & 0xFF;
                length = *((int *) (file_buf + offset + TYPE_LEN)) & 0xFFFF;

                tmp = malloc(sizeof(char) * ((int)length + 1));
                memcpy(tmp, file_buf + offset + TYPELEN_LEN, length);
                tmp[length] = '\0';

                switch(type) {
                case END:
                        header_values->end = tmp;
                        header_values->end_len = length;
                        memcpy(header_values->payload, file_buf + offset + TYPE_LEN + LENGTH_LEN + length, header_values->streamstartbytes_len);

                        return error_flags;
                        break;
                case COMMENT:
                        header_values->comment = tmp;
                        header_values->comment_len = length;
                        break;
                case CIPHERID:
                        if (validate_cipher_id(tmp, length)) {
                                error_flags |= 0x1;
                        }
                        header_values->cipherid = tmp;
                        header_values->cipherid_len = length;
                        break;
                case COMPRESSIONFLAGS:
                        free(tmp);
                        header_values->compressionflags = *((uint32_t *) (file_buf + offset + TYPELEN_LEN));
                        break;
                case MASTERSEED:
                        header_values->masterseed = tmp;
                        header_values->masterseed_len = length;
                        break;
                case TRANSFORMSEED:
                        header_values->transformseed = tmp;
                        header_values->transformseed_len = length;
                        break;
                case TRANSFORMROUNDS:
                        header_values->transformrounds = *((uint64_t *) (file_buf + offset + TYPELEN_LEN));
                        break;
                case ENCRYPTIONIV:
                        header_values->encryptioniv = tmp;
                        header_values->encryptioniv_len = length;
                        break;
                case PROTECTEDSTREAMKEY:
                        header_values->protectedstreamkey = tmp;
                        header_values->protectedstreamkey_len = length;
                        break;
                case STREAMSTARTBYTES:
                        header_values->streamstartbytes = tmp;
                        header_values->streamstartbytes_len = length;

                        header_values->payload = malloc(sizeof(uint8_t) * header_values->streamstartbytes_len);
                        break;
                case INNERRANDOMSTREAMID:
                        header_values->innerrandomstreamid = *((uint32_t *) (file_buf + offset + TYPELEN_LEN));
                        break;
                default:
                        error_flags |= 0x10;
                        return error_flags;
                }

                offset += TYPE_LEN + LENGTH_LEN + length;
        }

        return error_flags;
}

void print_hex_stream(uint8_t *buf, int length, int nl)
{
        int i;
        for (i = 0; i < length; i++) {
                printf("%.2X", (uint8_t)buf[i]);
        }

        if (nl == 1) {
                printf("\n");
        }
}

void print_hex_byte(uint8_t byte, int nl)
{

        putchar(hexstr[(byte >> 4) & 0xF]);
        putchar(hexstr[(byte >> 0) & 0xF]);

        if (nl == 1) {
                puts("");
        }
}

void print_hex_word(uint8_t word, int nl)
{
        putchar(hexstr[(word >> 12) & 0xF]);
        putchar(hexstr[(word >> 8) & 0xF]);
        putchar(hexstr[(word >> 4) & 0xF]);
        putchar(hexstr[(word >> 0) & 0xF]);

        if (nl == 1) {
                puts("");
        }
}

void print_hex_dword(uint32_t dword, int nl)
{
        putchar(hexstr[(dword >> 28) & 0xF]);
        putchar(hexstr[(dword >> 24) & 0xF]);
        putchar(hexstr[(dword >> 20) & 0xF]);
        putchar(hexstr[(dword >> 16) & 0xF]);
        putchar(hexstr[(dword >> 12) & 0xF]);
        putchar(hexstr[(dword >> 8) & 0xF]);
        putchar(hexstr[(dword >> 4) & 0xF]);
        putchar(hexstr[(dword >> 0) & 0xF]);

        if (nl == 1) {
                puts("");
        }
}

void print_hex_qword(uint64_t qword, int nl)
{
        putchar(hexstr[(qword >> 60) & 0xF]);
        putchar(hexstr[(qword >> 56) & 0xF]);
        putchar(hexstr[(qword >> 52) & 0xF]);
        putchar(hexstr[(qword >> 48) & 0xF]);
        putchar(hexstr[(qword >> 44) & 0xF]);
        putchar(hexstr[(qword >> 40) & 0xF]);
        putchar(hexstr[(qword >> 36) & 0xF]);
        putchar(hexstr[(qword >> 32) & 0xF]);
        putchar(hexstr[(qword >> 28) & 0xF]);
        putchar(hexstr[(qword >> 24) & 0xF]);
        putchar(hexstr[(qword >> 20) & 0xF]);
        putchar(hexstr[(qword >> 16) & 0xF]);
        putchar(hexstr[(qword >> 12) & 0xF]);
        putchar(hexstr[(qword >> 8) & 0xF]);
        putchar(hexstr[(qword >> 4) & 0xF]);
        putchar(hexstr[(qword >> 0) & 0xF]);

        if (nl == 1) {
                puts("");
        }
}


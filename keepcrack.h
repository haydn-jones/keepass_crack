#ifndef _KEEPCRACK_H
#define _KEEPCRACK_H

#define TYPE_LEN 1
#define LENGTH_LEN 2
#define TYPELEN_LEN 3

struct header_info_t {
        uint32_t pid;           // Primary ID
        uint32_t sid;           // Secondary ID
        uint16_t version_minor; // Minor version number
        uint16_t version_major; // Major version number
        uint8_t file_version;   // File version (byte 4 of file or lower 8 bits of sid)
};

enum HFIELDS {END, COMMENT, CIPHERID, COMPRESSIONFLAGS, MASTERSEED, TRANSFORMSEED, TRANSFORMROUNDS, ENCRYPTIONIV,
              PROTECTEDSTREAMKEY, STREAMSTARTBYTES, INNERRANDOMSTREAMID};

struct header_values_t {
        uint8_t  *end;
        uint16_t end_len;
        uint8_t  *comment;
        uint16_t comment_len;
        uint8_t  *cipherid;
        uint16_t cipherid_len;
        uint32_t compressionflags;
        uint8_t  *masterseed;
        uint16_t masterseed_len;
        uint8_t  *transformseed;
        uint16_t transformseed_len;
        uint64_t transformrounds;
        uint8_t  *encryptioniv;
        uint16_t encryptioniv_len;
        uint8_t  *protectedstreamkey;
        uint16_t protectedstreamkey_len;
        uint8_t  *streamstartbytes;
        uint16_t streamstartbytes_len;
        uint32_t innerrandomstreamid;
        uint8_t  *payload;
};

int validate_cipher_id(uint8_t *cipher, int length);
int fill_header_info(struct header_info_t *header_info, uint8_t *file_buf);
int fill_header_values(struct header_values_t *header_values, uint8_t *file_buf);
void print_hex_byte(uint8_t byte, int nl);
void print_hex_word(uint8_t word, int nl);
void print_hex_dword(uint32_t dword, int nl);
void print_hex_qword(uint64_t qword, int nl);
void print_hex_stream(uint8_t *buf, int length, int nl);

#endif

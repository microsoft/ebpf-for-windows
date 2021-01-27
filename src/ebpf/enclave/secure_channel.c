/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#include <stddef.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#include "log.h"
#include "secure_channel.h"

#define IF_FAILED_EXIT(x) \
{ \
    int if_failed_exit_result = x; \
    if (if_failed_exit_result < 0) { \
        char mbed_tls_error[MAX_LOG_MESSAGE_SIZE]; \
        mbedtls_strerror(if_failed_exit_result, mbed_tls_error, sizeof(mbed_tls_error)); \
        ebpf_enclave_log(error, "%s failed with retval %d : %s", #x, if_failed_exit_result, mbed_tls_error);\
        goto cleanup;\
    }\
}\

#define CERT_VALIDITY_START "20010101000000"
#define CERT_VALIDITY_END "20301231235959"
#define CERT_SERIAL "1"

#define SECURE_CHANNEL_EC_CURVE MBEDTLS_ECP_DP_SECP256R1
#define SECURE_CHANNEL_MD_ALGORITHM MBEDTLS_MD_SHA256


typedef struct secure_channel_state {
    mbedtls_entropy_context entropy_context;
    mbedtls_ctr_drbg_context ctr_drbg_context;
    mbedtls_ssl_context ssl_context;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt server_certificate;
    mbedtls_pk_context private_key_context;
} secure_channel_state;


int secure_channel_init(struct secure_channel_state** state)
{
    int return_value = -1;
    secure_channel_state* local_state = NULL;
    local_state = malloc(sizeof(secure_channel_state));
    if (local_state == NULL)
    {
        goto cleanup;
    }

    mbedtls_ssl_init(&local_state->ssl_context);
    mbedtls_ssl_config_init(&local_state->ssl_config);

    mbedtls_x509_crt_init(&local_state->server_certificate);
    mbedtls_pk_init(&local_state->private_key_context);
    mbedtls_entropy_init(&local_state->entropy_context);
    mbedtls_ctr_drbg_init(&local_state->ctr_drbg_context);

    IF_FAILED_EXIT(mbedtls_ctr_drbg_seed(&local_state->ctr_drbg_context, 
        mbedtls_entropy_func, 
        &local_state->entropy_context, 
        NULL, 
        0));

    *state = local_state;
    local_state = NULL;
    return_value = 0;

cleanup:
    if (local_state)
    {
        mbedtls_ctr_drbg_free(&local_state->ctr_drbg_context);
        mbedtls_entropy_free(&local_state->entropy_context);
        free(local_state);
    }
    return return_value;
}

int secure_channel_free(struct secure_channel_state* state)
{
    mbedtls_ctr_drbg_free(&state->ctr_drbg_context);
    mbedtls_entropy_free(&state->entropy_context);
    return 0;
}


int secure_channel_generate_cert(
    struct secure_channel_state * state, 
    const char * subject_name)
{
    int return_value = -1;
    mbedtls_x509write_cert x509write_cert;
    unsigned char output_buf[4096] = { 0 };
    int certificate_length = 0;
    mbedtls_mpi serial;

    mbedtls_x509write_crt_init(&x509write_cert);
    mbedtls_mpi_init(&serial);

    IF_FAILED_EXIT(mbedtls_mpi_read_string(&serial, 10, CERT_SERIAL));

    // Generate key pair
    IF_FAILED_EXIT(mbedtls_pk_setup(&state->private_key_context,
        mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)));

    IF_FAILED_EXIT(mbedtls_ecp_gen_key(SECURE_CHANNEL_EC_CURVE,
        mbedtls_pk_ec(state->private_key_context), 
        mbedtls_ctr_drbg_random, 
        &state->ctr_drbg_context));

    mbedtls_x509write_crt_set_issuer_key(&x509write_cert, 
        &state->private_key_context);
    mbedtls_x509write_crt_set_subject_key(&x509write_cert, 
        &state->private_key_context);
    IF_FAILED_EXIT(mbedtls_x509write_crt_set_issuer_name(&x509write_cert, 
        subject_name));
    IF_FAILED_EXIT(mbedtls_x509write_crt_set_subject_name(&x509write_cert, 
        subject_name));
    mbedtls_x509write_crt_set_version(&x509write_cert, 
        MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&x509write_cert, 
        SECURE_CHANNEL_MD_ALGORITHM);
    IF_FAILED_EXIT(mbedtls_x509write_crt_set_serial(&x509write_cert, &serial));
    IF_FAILED_EXIT(mbedtls_x509write_crt_set_validity(&x509write_cert, 
        CERT_VALIDITY_START, 
        CERT_VALIDITY_END));

    IF_FAILED_EXIT(certificate_length = 
        mbedtls_x509write_crt_der(&x509write_cert,
            output_buf, 
            sizeof(output_buf), 
            mbedtls_ctr_drbg_random, 
            &state->ctr_drbg_context));

    IF_FAILED_EXIT(mbedtls_x509_crt_parse_der(&state->server_certificate, 
        &output_buf[sizeof(output_buf) - certificate_length],
        certificate_length));

    return_value = 0;

cleanup:
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&x509write_cert);
    return return_value;
}


int secure_channel_open(struct secure_channel_state* state, 
    void* context, 
    secure_channel_send send, 
    secure_channel_receive receive)
{
    int return_value = -1;

    IF_FAILED_EXIT(mbedtls_ssl_config_defaults(&state->ssl_config, 
        MBEDTLS_SSL_IS_SERVER, 
        MBEDTLS_SSL_TRANSPORT_STREAM, 
        MBEDTLS_SSL_PRESET_DEFAULT));

    mbedtls_ssl_conf_rng(&state->ssl_config, 
        mbedtls_ctr_drbg_random, 
        &state->ctr_drbg_context);

    mbedtls_ssl_conf_ca_chain(&state->ssl_config, 
        state->server_certificate.next, 
        NULL);

    IF_FAILED_EXIT(mbedtls_ssl_conf_own_cert(&state->ssl_config, 
        &state->server_certificate, 
        &state->private_key_context));

    IF_FAILED_EXIT(mbedtls_ssl_setup(&state->ssl_context, &state->ssl_config));

    mbedtls_ssl_set_bio(&state->ssl_context, context, send, receive, NULL);

    while ((return_value = mbedtls_ssl_handshake(&state->ssl_context)) != 0)
    {
        if (return_value != MBEDTLS_ERR_SSL_WANT_READ && 
            return_value != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            char mbed_tls_error[MAX_LOG_MESSAGE_SIZE]; \
            mbedtls_strerror(return_value, mbed_tls_error, sizeof(mbed_tls_error)); \

            ebpf_enclave_log(error, "mbedtls_ssl_handshake failed with %d:%s\n", return_value, mbed_tls_error);
            goto cleanup;
        }
    }

cleanup:
    return return_value;
}

int secure_channel_send_receive_message(
    struct secure_channel_state* state,
    const unsigned char* message,
    size_t message_size,
    unsigned char* reply,
    size_t reply_buffer_size)
{
    int return_value = -1;
    int reply_size;
    int bytes_written;
    int bytes_read;

    if (message_size > MAX_SECURE_CHANNEL_MESSAGE_SIZE)
    {
        goto cleanup;
    }

    if (reply_buffer_size > MAX_SECURE_CHANNEL_MESSAGE_SIZE)
    {
        goto cleanup;
    }


    // Send the message length
    IF_FAILED_EXIT(bytes_written = mbedtls_ssl_write(&state->ssl_context,
        (const unsigned char*)&message_size,
        sizeof(message_size)));

    if (bytes_written != sizeof(message_size))
    {
        goto cleanup;
    }

    // Send the message
    IF_FAILED_EXIT(bytes_written = mbedtls_ssl_write(&state->ssl_context, 
        message, 
        message_size));
    if (bytes_written != message_size)
    {
        goto cleanup;
    }


    // Read the response length
    IF_FAILED_EXIT(bytes_read = mbedtls_ssl_read(&state->ssl_context,
        (unsigned char*)&reply_size,
        sizeof(reply_size)));

    if (bytes_read != sizeof(reply_size))
    {
        goto cleanup;
    }

    if (reply_size > reply_buffer_size)
    {
        goto cleanup;
    }

    // Read the response message
    IF_FAILED_EXIT(bytes_read = mbedtls_ssl_read(&state->ssl_context, 
        reply, 
        reply_size));

    if (bytes_read != reply_size)
    {
        goto cleanup;
    }
    
    return_value = reply_size;

cleanup:
    return return_value;
}
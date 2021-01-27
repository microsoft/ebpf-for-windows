/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once


#define MAX_SECURE_CHANNEL_MESSAGE_SIZE 1024
struct secure_channel_state;

/**
 * \brief          Allocate a secure channel state.
 *
 * \param state    pointer to pointer that holds the secure channel state.
 *
 * \return         0 if successful, -1 on failure.
 *
 * \note           Must be freed via secure_channel_free
 */
int secure_channel_init(struct secure_channel_state** state);

/**
 * \brief          Free a secure channel state.
 *
 * \param state    pointer that holds the secure channel state.
 *
 * \return         0 if successful, -1 on failure.
 *
 * \note           
 */
int secure_channel_free(struct secure_channel_state* state);

/**
 * \brief          Allocate the server certificate for the schannel
 *
 * \param state    pointer that holds the secure channel state.
 *
 * \param subject_name subject name of the cert to generate.
 *
 * \return         0 if successful, -1 on failure.
 *
 * \note
 */
int secure_channel_generate_cert(struct secure_channel_state* state,
    const char* subject_name);

typedef int (*secure_channel_send)(void* context, 
    const unsigned char* buffer, size_t length);
typedef int (*secure_channel_receive)(void* context, 
    unsigned char* buffer, 
    size_t length);

/**
 * \brief          Establish a TLS session.
 *
 * \param state    pointer that holds the secure channel state.
 *
 * \param send     callback function to send encryped bytes
 *
 * \param receive  callback function to receive encryped bytes
 *
 * \return         0 if successful, -1 on failure.
 *
 * \note
 */
int secure_channel_open(struct secure_channel_state* state, 
    void * context, 
    secure_channel_send send, 
    secure_channel_receive receive);

/**
 * \brief          Send a message and wait for a response.
 *
 * \param state    pointer that holds the secure channel state.
 *
 * \param message  message to be sent
 *
 * \param message_size size of message to be sent
 *
 * \param reply    response received
 *
 * \param reply    size of response received
 *
 * \return         0 if successful, -1 on failure.
 *
 * \note
 */
int secure_channel_send_receive_message(struct secure_channel_state* state,
    const unsigned char* message, 
    size_t message_size, 
    unsigned char* reply, 
    size_t reply_size);

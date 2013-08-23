/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* sncgss.h - The interface to the SNC Network Adapter */
/*
 * Copyright (C) 2013 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file lays out custom copies of the GSS structures which are
 * alignment-dependent (from 16-bit alignment to the native alignment on
 * the x86_64 architecture), and prototypes the SNC Adapter API.
 */

#ifndef SNCGSS_H
#define SNCGSS_H

/* Copies of GSS structures to get the native-aligned ABI */
#if 0 /* This should be ABI-compatible with 16-bit and native alignment */
typedef struct sapgss_buffer_desc_struct {
    size_t length;
    void *value;
} sapgss_buffer_desc, *sapgss_buffer_t;
#endif

typedef struct sapgss_OID_desc_struct {
    uint32_t length;
    void *elements;
} *sapgss_OID;

typedef struct sapgss_OID_set_desc_struct {
    size_t count;
    sapgss_OID elements;
} *sapgss_OID_set;

typedef struct sapgss_channel_bindings_struct {
    uint32_t initiator_addrtype;
    sapgss_buffer_desc initiator_address;
    uint32_t acceptor_addrtype;
    sapgss_buffer_desc acceptor_address;
    sapgss_buffer_desc application_data;
} *sapgss_channel_bindings_t;

#if 0 /* This should be ABI-compatible with 16-bit and native alignment */
struct sapgss_name_struct;
typedef struct sapgss_name_struct *sapgss_name_t;

struct sapgss_cred_id_struct;
typedef struct sapgss_cred_id_struct *sapgss_cred_id_t;

struct sapgss_ctx_id_struct;
typedef struct sapgss_ctx_id_struct *sapgss_ctx_id_t;

typedef int sapgss_cred_usage_t;
typedef uint32_t sapgss_qop_t;
#endif

/* Exported library routines */
uint32_t sapsnc_init_adapter(struct sapgss_info_s *info, size_t len, int n);

uint32_t sapsnc_export_cname_blob();

uint32_t sapsnc_import_cname_blob();

uint32_t sapgss_acquire_cred(
	uint32_t *minor_status,
	sapgss_name_t desired_name,
	uint32_t time_req,
	sapgss_OID_set desired_mechs,
	sapgss_cred_usage_t cred_usage,
	sapgss_cred_id_t *output_cred_handle,
	sapgss_OID_set *actual_mechs,
	uint32_t *time_rec);

uint32_t sapgss_release_cred(
	uint32_t *minor_status,
	sapgss_cred_id_t *cred_handle);

uint32_t sapgss_init_sec_context(
	uint32_t *minor_status,
	sapgss_cred_id_t claimant_cred_handle,
	sapgss_ctx_id_t *context_handle,
	sapgss_name_t target_name,
	sapgss_OID mech_type,
	uint32_t req_flags,
	uint32_t time_req,
	sapgss_channel_bindings_t input_chan_bindings,
	sapgss_buffer_t input_token,
	sapgss_OID *actual_mech_type,
	sapgss_buffer_t output_token,
	uint32_t *ret_flags,
	uint32_t *time_rec);

uint32_t sapgss_accept_sec_context(
	uint32_t *minor_status,
	sapgss_ctx_id_t *context_handle,
	sapgss_cred_id_t acceptor_cred_handle,
	sapgss_buffer_t input_token_buffer,
	sapgss_channel_bindings_t input_chan_bindings,
	sapgss_name_t *src_name,
	sapgss_OID *mech_type,
	sapgss_buffer_t output_token,
	uint32_t *ret_flags,
	uint32_t *time_rec,
	sapgss_cred_id_t *delegated_cred_handle);

uint32_t sapgss_process_context_token(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle
	sapgss_buffer_t token_buffer);

uint32_t sapgss_delete_sec_context(
	uint32_t *minor_status,
	sapgss_ctx_id_t *context_handle,
	sapgss_buffer_t token_buffer);

uint32_t sapgss_context_time(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	uint32_t *time_rec);

uint32_t sapgss_get_mic(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	sapgss_qop_t qop_req,
	sapgss_buffer_t message_buffer,
	sapgss_buffer_t message_token);

uint32_t sapgss_verify_mic(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	sapgss_buffer_t message_buffer,
	sapgss_buffer_t message_token,
	sapgss_qop_t *qop_state);

uint32_t sapgss_wrap(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	int conf_req_flag,
	sapgss_qop_t qop_req,
	sapgss_buffer_t input_message_buffer,
	int *conf_state,
	sapgss_buffer_t output_message_buffer);

uint32_t sapgss_unwrap(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	sapgss_buffer_t input_message_buffer,
	sapgss_buffer_t output_message_buffer,
	int *conf_state,
	sapgss_qop_t *qop_state);

uint32_t sapgss_display_status(
	uint32_t *minor_status,
	uint32_t status_value,
	int status_type,
	sapgss_OID mech_type,
	uint32_t *message_context,
	sapgss_buffer_t status_string);

uint32_t sapgss_indicate_mechs(
	uint32_t *minor_status,
	sapgss_OID_set *mech_set);

uint32_t sapgss_compare_name(
	uint32_t *minor_status,
	sapgss_name_t name1,
	sapgss_name_t name2,
	int *name_equal);

uint32_t sapgss_display_name(
	uint32_t *minor_status,
	sapgss_name_t input_name,
	sapgss_buffer_t output_name_buffer,
	sapgss_OID *output_name_type);

uint32_t sapgss_import_name(
	uint32_t *minor_status,
	sapgss_buffer_t input_name_buffer,
	sapgss_OID input_name_type,
	sapgss_name_t *output_name);

uint32_t sapgss_release_name(
	uint32_t *minor_status,
	sapgss_name_t *input_name);

uint32_t sapgss_relesae_buffer(
	uint32_t *minor_status,
	sapgss_buffer_t buffer);

uint32_t sapgss_release_oid_set(
	uint32_t *minor_status,
	sapgss_OID_set *set);

uint32_t sapgss_inquire_cred(
	uint32_t *minor_status,
	sapgss_cred_id_t cred_handle,
	sapgss_name_t *name,
	uint32_t *lifetime,
	sapgss_cred_usage_t *cred_usage,
	sapgss_OID_set *mechanisms);

uint32_t sapgss_add_cred(
	uint32_t *minor_status,
	sapgss_cred_id_t input_cred_handle,
	sapgss_name_t desired_name,
	sapgss_OID desired_mech,
	sapgss_cred_usage_t cred_usage,
	uint32_t initiator_time_req,
	uint32_t acceptor_time_req,
	sapgss_cred_id_t *output_cred_handle,
	sapgss_OID_set *actual_mechs,
	uint32_t *initiator_time_rec,
	uint32_t *acceptor_time_rec);

uint32_t sapgss_inquire_cred_by_mech(
	uint32_t *minor_status,
	sapgss_cred_id_t cred_handle,
	sapgss_OID mech_type,
	sapgss_name_t *name,
	uint32_t *initiator_lifetime,
	uint32_t *acceptor_lifetime,
	sapgss_cred_usage_t *cred_usage);

uint32_t sapgss_inquire_context(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	sapgss_name_t *src_name,
	sapgss_name_t *targ_name,
	uint32_t *lifetime_rec,
	sapgss_OID *mech_type,
	uint32_t *ctx_flags,
	int *locally_initiated,
	int *open);

uint32_t sapgss_wrap_size_limit(
	uint32_t *minor_status,
	sapgss_ctx_id_t context_handle,
	int conf_req_flag,
	sapgss_qop_t qop_req,
	uint32_t req_output_size
	uint32_t *max_input_size);

uint32_t sapgss_export_sec_context(
	uint32_t *minor_status,
	sapgss_ctx_id_t *context_handle,
	sapgss_buffer_t interprocess_token);

uint32_t sapgss_import_sec_context(
	uint32_t *minor_status,
	sapgss_buffer_t interprocess_token,
	sapgss_ctx_id_t *context_handle);

uint32_t sapgss_create_empty_oid_set(
	uint32_t *minor_status,
	sapgss_OID_set *oid_set);

uint32_t sapgss_add_oid_set_member(
	uint32_t *minor_status,
	sapgss_OID member_oid,
	sapgss_OID_set *oid_set);

uint32_t sapgss_test_oid_set_member(
	uint32_t *minor_status,
	sapgss_OID member,
	sapgss_OID_set set,
	int *present)

uint32_t sapgss_inquire_names_for_mech(
	uint32_t *minor_status,
	sapgss_OID mechanism,
	sapgss_OID_set *name_types);

uint32_t sapgss_inquire_mechs_for_name(
	uint32_t *minor_status,
	const sapgss_name_t input_name,
	sapgss_OID_set *mech_types);

uint32_t sapgss_canonicalize_name(
	uint32_t *minor_status,
	const sapgss_name_t input_name,
	const sapgss_OID mech_type,
	sapgss_name_t *output_name);

uint32_t sapgss_export_name(
	uint32_t *minor_status,
	const sapgss_name_t input_name,
	sapgss_buffer_t exported_name);

uint32_t sapgss_duplicate_name(
	uint32_t *minor_status,
	const sapgss_name_t input_name,
	sapgss_name_t *dest_name);

#endif /* SNCGSS_H */

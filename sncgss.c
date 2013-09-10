/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* sncgss.c - Implementation of the SNC shim for OS X gssapi-krb5 */
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
 * This file contains the implementation of the SNC Adapter for
 * using the system-native gssapi_krb5 library from OS X with the
 * SAP GUI.  The SAP code assumes that GSS types are laid out using
 * native alignment, but due to unfortunate historical circumstances,
 * the system's GSS-API library forces 16-bit alignment, resulting in
 * an ABI incompatibility.  We implement shim routines on top of
 * the native GSS-API library, most of which are direct pass-throughs,
 * doing the necessary translation between types where the ABI is
 * incompatible.
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <gssapi/gssapi.h>
#include "sncgss.h"

/* GSS_KRB5_NT_PRINCIPAL_NAME */
sapgss_OID_desc krb5_nt_principal_name =
    {10, "\052\206\110\206\367\022\001\002\002\001"};
/* The real one */
sapgss_OID_desc gss_mech_krb5 =
    {9, "\052\206\110\206\367\022\001\002\002"};
gss_OID_desc native_gss_mech_krb5 =
    {9, "\052\206\110\206\367\022\001\002\002"};

/* Local helper routines */
/*
 * Take an OID from the SAP ABI and generate a copy of it in the ABI
 * expected by the local GSS-API library.  The caller is responsible for
 * calling gss_OID_loc_release() to free storage allocated by this
 * routine.
 */
static void
gss_OID_sap_to_loc(sapgss_OID sap, gss_OID *loc)
{
    if (loc == NULL)
	return;
    if (sap == NULL) {
	*loc = NULL;
	return;
    }
    *loc = calloc(1, sizeof(**loc));
    (*loc)->elements = malloc(sap->length);
    memcpy((*loc)->elements, sap->elements, sap->length);
    (*loc)->length = sap->length;
    return;
}

static void
gss_OID_loc_release(gss_OID *loc)
{
    if (loc == NULL || *loc == NULL)
	return;

    free((*loc)->elements);
    free(*loc);
    *loc = NULL;
}

static void
gss_OID_loc_to_sap(gss_OID loc, sapgss_OID *sap)
{
    if (sap == NULL)
	return;
    if (loc == NULL) {
	*sap = NULL;
	return;
    }
    /* XXX memory leaks here, too. */
    *sap = calloc(1, sizeof(**sap));
    (*sap)->elements = malloc(loc->length);
    memcpy((*sap)->elements, loc->elements, loc->length);
    (*sap)->length = loc->length;
    return;
}

/*
 * The caller must free the OID set loc with gss_OID_set_loc_release() before
 * exiting the shim layer.
 */
static void
gss_OID_set_sap_to_loc(sapgss_OID_set sap, gss_OID_set *loc)
{
    sapgss_OID s;
    gss_OID e;
    size_t i;

    if (loc == NULL)
	return;
    if (sap == NULL) {
	*loc = NULL;
	return;
    }

    *loc = calloc(1, sizeof(**loc));
    (*loc)->elements = calloc(sap->count, sizeof(gss_OID_desc));
    for(i = 0; i < sap->count; ++i) {
	s = &sap->elements[i];
	e = &(*loc)->elements[i];
	e->elements = malloc(s->length);
	memcpy(e->elements, s->elements, s->length);
	e->length = s->length;
    }
    (*loc)->count = sap->count;
    return;
}

/*
 * Free the memory associated with the gss_OID_set in the local GSS-API
 * library's ABI that was allocated by the shim to call into the GSS-API
 * library.
 */
static void
gss_OID_set_loc_release(gss_OID_set *loc)
{
    gss_OID_set set;
    gss_OID e;
    size_t i;

    if (loc == NULL || *loc == NULL)
	return;

    set = *loc;
    for(i = 0; i < set->count; ++i) {
	e = &set->elements[i];
	free(e->elements);
    }
    free(set->elements);
    free(set);
    set = NULL;
}

/*
 * Translate an OID_set from the local GSS-API library's ABI into the
 * ABI which SAP expects.  This translation routine is only used within
 * this shim adapter, so it is appropriate for the this routine to release
 * the storage which was allocated by the GSS-API library (since that
 * storage will never be exposed to the application and will otherwise be
 * leaked).
 */
static void
gss_OID_set_loc_to_sap(gss_OID_set loc, sapgss_OID_set *sap)
{
    sapgss_OID s;
    gss_OID e;
    size_t i;
    uint32_t dummy;

    if (sap == NULL)
	return;
    if (loc == NULL) {
	*sap = NULL;
	return;
    }

    *sap = calloc(1, sizeof(**sap));
    (*sap)->elements = calloc(loc->count, sizeof(sapgss_OID_desc));
    for(i = 0; i < loc->count; ++i) {
	e = &loc->elements[i];
	s = &(*sap)->elements[i];
	s->elements = malloc(e->length);
	memcpy(s->elements, e->elements, e->length);
	s->length = e->length;
    }
    (*sap)->count = loc->count;
    (void)gss_release_oid_set(&dummy, &loc);
    return;
}

static void
dwrite(void *data, size_t len)
{
    int fd;
    char nul = '\0';

    fd = open("/tmp/k.log", O_WRONLY|O_CREAT|O_APPEND, 0644);
    write(fd, data, len);
    write(fd, &nul, 1);
    close(fd);
}

/* Exported library routines */
uint32_t
sapsnc_init_adapter(struct sapgss_info_s *info, size_t len, int n)
{
    if (info == NULL || len < sizeof(*info))
	return 1;
    /* else */
    memset(info, 0, len);
    info->major_rev = 1;
    info->minor_rev = 0;
    info->adapter_name = "OS X krb5 compat shim";
    info->mech_id = ID_KRB5;
    info->integ_avail = 1;
    info->conf_avail = 1;
    info->export_sec_context = 1;
    info->nt_canonical_name = &krb5_nt_principal_name;
    info->nt_private_name1 = &krb5_nt_principal_name;
    info->mech_prefix_string = "krb5";
    info->mutual_auth = 1;
    info->replay_prot = 1;
    info->mech_oid = &gss_mech_krb5;
    return 0;
}

uint32_t
sapsnc_export_cname_blob(
    uint32_t *minor_status,
    gss_name_t name,
    gss_buffer_t out,
    int dummy)
{
    *minor_status = 0;
    return GSS_S_FAILURE;
}

uint32_t
sapsnc_import_cname_blob(
    uint32_t *minor_status,
    gss_buffer_t in,
    gss_name_t name,
    int dummy)
{
    *minor_status = 0;
    return GSS_S_FAILURE;
}

uint32_t
sapgss_acquire_cred(
    uint32_t *minor_status,
    gss_name_t desired_name,
    uint32_t time_req,
    sapgss_OID_set desired_mechs,
    gss_cred_usage_t cred_usage,
    gss_cred_id_t *output_cred_handle,
    sapgss_OID_set *actual_mechs,
    uint32_t *time_rec)
{
    gss_OID_set desired_mechs_loc;
    gss_OID_set actual_mechs_loc;
    uint32_t major_status, dummy;
    
    memset(&desired_mechs_loc, 0, sizeof(desired_mechs_loc));
    memset(&actual_mechs_loc, 0, sizeof(actual_mechs_loc));
    gss_OID_set_sap_to_loc(desired_mechs, &desired_mechs_loc);
    major_status = gss_acquire_cred(minor_status, desired_name, time_req,
				    desired_mechs_loc, cred_usage,
				    output_cred_handle, &actual_mechs_loc,
				    time_rec);
    /* Meet the gss_OID_set_sap_to_loc contract and free desired_mechs_loc */
    gss_OID_set_loc_release(&desired_mechs_loc);
    /* Must inquire_cred to force resolution for the krb5 mech */
    if (major_status != 0)
	return major_status;
    (void)gss_inquire_cred(&dummy, *output_cred_handle,
				    NULL, NULL, NULL, &actual_mechs_loc);
    gss_OID_set_loc_to_sap(actual_mechs_loc, actual_mechs);
    return major_status;
}

uint32_t
sapgss_release_cred(
    uint32_t *minor_status,
    gss_cred_id_t *cred_handle)
{
    return gss_release_cred(minor_status, cred_handle);
}

uint32_t
sapgss_init_sec_context(
    uint32_t *minor_status,
    gss_cred_id_t claimant_cred_handle,
    gss_ctx_id_t *context_handle,
    gss_name_t target_name,
    sapgss_OID mech_type,
    uint32_t req_flags,
    uint32_t time_req,
    sapgss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    sapgss_OID *actual_mech_type,
    gss_buffer_t output_token,
    uint32_t *ret_flags,
    uint32_t *time_rec)
{
    gss_OID mech_type_loc, actual_mech_type_loc;
    uint32_t major_status;

    memset(&mech_type_loc, 0, sizeof(mech_type_loc));
    actual_mech_type_loc = NULL;
    /* Hope nobody uses these */
    if (input_chan_bindings != NULL)
	return GSS_S_FAILURE;
    gss_OID_sap_to_loc(mech_type, &mech_type_loc);
    major_status = gss_init_sec_context(minor_status, claimant_cred_handle,
					context_handle, target_name,
					mech_type_loc, req_flags, time_req,
					NULL, input_token,
					&actual_mech_type_loc, output_token,
	    				ret_flags, time_rec);
    /* Comply with the gss_OID_sap_to_loc contract and free mech_type_loc */
    gss_OID_loc_release(&mech_type_loc);
    gss_OID_loc_to_sap(actual_mech_type_loc, actual_mech_type);
    return major_status;
}

uint32_t
sapgss_accept_sec_context(
    uint32_t *minor_status,
    gss_ctx_id_t *context_handle,
    gss_cred_id_t acceptor_cred_handle,
    gss_buffer_t input_token_buffer,
    sapgss_channel_bindings_t input_chan_bindings,
    gss_name_t *src_name,
    sapgss_OID *mech_type,
    gss_buffer_t output_token,
    uint32_t *ret_flags,
    uint32_t *time_rec,
    gss_cred_id_t *delegated_cred_handle)
{
    gss_OID mech_type_loc;
    uint32_t major_status;

    memset(&mech_type_loc, 0, sizeof(mech_type_loc));
    if (input_chan_bindings != NULL)
	return GSS_S_FAILURE;
    major_status = gss_accept_sec_context(minor_status, context_handle,
					  acceptor_cred_handle,
					  input_token_buffer,
					  NULL, src_name, &mech_type_loc,
					  output_token, ret_flags, time_rec,
					  delegated_cred_handle);
    gss_OID_loc_to_sap(mech_type_loc, mech_type);
    return major_status;
}

uint32_t
sapgss_process_context_token(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    gss_buffer_t token_buffer)
{
    return gss_process_context_token(minor_status, context_handle,
				     token_buffer);
}

uint32_t
sapgss_delete_sec_context(
    uint32_t *minor_status,
    gss_ctx_id_t *context_handle,
    gss_buffer_t token_buffer)
{
    return gss_delete_sec_context(minor_status, context_handle, token_buffer);
}

uint32_t
sapgss_context_time(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    uint32_t *time_rec)
{
    return gss_context_time(minor_status, context_handle, time_rec);
}

uint32_t
sapgss_get_mic(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    gss_qop_t qop_req,
    gss_buffer_t message_buffer,
    gss_buffer_t message_token)
{
    return gss_get_mic(minor_status, context_handle, qop_req, message_buffer,
		       message_token);
}

uint32_t
sapgss_verify_mic(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    gss_buffer_t message_buffer,
    gss_buffer_t message_token,
    gss_qop_t *qop_state)
{
    return gss_verify_mic(minor_status, context_handle, message_buffer,
			  message_token, qop_state);
}

uint32_t
sapgss_wrap(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    int conf_req_flag,
    gss_qop_t qop_req,
    gss_buffer_t input_message_buffer,
    int *conf_state,
    gss_buffer_t output_message_buffer)
{
    return gss_wrap(minor_status, context_handle, conf_req_flag, qop_req,
		    input_message_buffer, conf_state, output_message_buffer);
}

uint32_t
sapgss_unwrap(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    gss_buffer_t input_message_buffer,
    gss_buffer_t output_message_buffer,
    int *conf_state,
    gss_qop_t *qop_state)
{
    return gss_unwrap(minor_status, context_handle, input_message_buffer,
		      output_message_buffer, conf_state, qop_state);
}

uint32_t
sapgss_display_status(
    uint32_t *minor_status,
    uint32_t status_value,
    int status_type,
    sapgss_OID mech_type,
    uint32_t *message_context,
    gss_buffer_t status_string)
{
    gss_OID mech_type_loc;
    uint32_t major_status;

    gss_OID_sap_to_loc(mech_type, &mech_type_loc);
    major_status = gss_display_status(minor_status, status_value, status_type,
				      mech_type_loc, message_context,
				      status_string);
    /* Comply with the gss_OID_sap_to_loc contract and free mech_type_loc */
    gss_OID_loc_release(&mech_type_loc);
    return major_status;
}

uint32_t
sapgss_indicate_mechs(
    uint32_t *minor_status,
    sapgss_OID_set *mech_set)
{
    gss_OID_set mech_set_loc;
    uint32_t major_status;

    memset(&mech_set_loc, 0, sizeof(mech_set_loc));
    major_status = gss_indicate_mechs(minor_status, &mech_set_loc);
    gss_OID_set_loc_to_sap(mech_set_loc, mech_set);
    return major_status;
}

uint32_t
sapgss_compare_name(
    uint32_t *minor_status,
    gss_name_t name1,
    gss_name_t name2,
    int *name_equal)
{
    return gss_compare_name(minor_status, name1, name2, name_equal);
}

uint32_t
sapgss_display_name(
    uint32_t *minor_status,
    gss_name_t input_name,
    gss_buffer_t output_name_buffer,
    sapgss_OID *output_name_type)
{
    gss_OID output_name_type_loc;
    uint32_t major_status;

    major_status = gss_display_name(minor_status, input_name,
				    output_name_buffer, &output_name_type_loc);
    gss_OID_loc_to_sap(output_name_type_loc, output_name_type);
    return major_status;
}

uint32_t
sapgss_import_name(
    uint32_t *minor_status,
    gss_buffer_t input_name_buffer,
    sapgss_OID input_name_type,
    gss_name_t *output_name)
{
    gss_OID input_name_type_loc;
    uint32_t major_status;

    gss_OID_sap_to_loc(input_name_type, &input_name_type_loc);
    major_status =  gss_import_name(minor_status, input_name_buffer,
				    input_name_type_loc, output_name);
    /* Comply with the gss_OID_sap_to_loc contract and free the OID */
    gss_OID_loc_release(&input_name_type_loc);
    return major_status == GSS_S_NAME_NOT_MN ? GSS_S_BAD_NAMETYPE :
					       major_status;
}

uint32_t
sapgss_release_name(
    uint32_t *minor_status,
    gss_name_t *input_name)
{
    return gss_release_name(minor_status, input_name);
}

uint32_t
sapgss_release_buffer(
    uint32_t *minor_status,
    gss_buffer_t buffer)
{
    return gss_release_buffer(minor_status, buffer);
}

/* This must be entirely custom, as all OIDs that are returned to SAP
 * are allocated by the shim layer, and must be freed by the shim layer. */
uint32_t
sapgss_release_oid_set(
    uint32_t *minor_status,
    sapgss_OID_set *set)
{
    size_t i;

    for(i = 0; i < (*set)->count; ++i)
	free((*set)->elements[i].elements);
    free((*set)->elements);
    free(*set);
    *set = NULL;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

uint32_t
sapgss_inquire_cred(
    uint32_t *minor_status,
    gss_cred_id_t cred_handle,
    gss_name_t *name,
    uint32_t *lifetime,
    gss_cred_usage_t *cred_usage,
    sapgss_OID_set *mechanisms)
{
    gss_OID_set mechanisms_loc;
    uint32_t major_status;

    major_status = gss_inquire_cred(minor_status, cred_handle, name, lifetime,
				    cred_usage, &mechanisms_loc);
    gss_OID_set_loc_to_sap(mechanisms_loc, mechanisms);
    return major_status;
}

uint32_t
sapgss_add_cred(
    uint32_t *minor_status,
    gss_cred_id_t input_cred_handle,
    gss_name_t desired_name,
    sapgss_OID desired_mech,
    gss_cred_usage_t cred_usage,
    uint32_t initiator_time_req,
    uint32_t acceptor_time_req,
    gss_cred_id_t *output_cred_handle,
    sapgss_OID_set *actual_mechs,
    uint32_t *initiator_time_rec,
    uint32_t *acceptor_time_rec)
{
    gss_OID desired_mech_loc;
    gss_OID_set actual_mechs_loc;
    uint32_t major_status;

    gss_OID_sap_to_loc(desired_mech, &desired_mech_loc);
    major_status = gss_add_cred(minor_status, input_cred_handle, desired_name,
				desired_mech_loc, cred_usage,
				initiator_time_req, acceptor_time_req,
				output_cred_handle, &actual_mechs_loc,
				initiator_time_rec, acceptor_time_rec);
    /* Comply with the gss_OID_sap_to_loc contract and free desired_mech_loc */
    gss_OID_loc_release(&desired_mech_loc);
    gss_OID_set_loc_to_sap(actual_mechs_loc, actual_mechs);
    return major_status;
}

uint32_t
sapgss_inquire_cred_by_mech(
    uint32_t *minor_status,
    gss_cred_id_t cred_handle,
    sapgss_OID mech_type,
    gss_name_t *name,
    uint32_t *initiator_lifetime,
    uint32_t *acceptor_lifetime,
    gss_cred_usage_t *cred_usage)
{
    gss_OID mech_type_loc;
    uint32_t major_status;

    gss_OID_sap_to_loc(mech_type, &mech_type_loc);
    major_status = gss_inquire_cred_by_mech(minor_status, cred_handle,
					    mech_type_loc, name,
					    initiator_lifetime,
					    acceptor_lifetime, cred_usage);
    /* Comply with the gss_OID_sap_to_loc contract and free mech_type_loc */
    gss_OID_loc_release(&mech_type_loc);
    return major_status;
}

uint32_t
sapgss_inquire_context(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    gss_name_t *src_name,
    gss_name_t *targ_name,
    uint32_t *lifetime_rec,
    sapgss_OID *mech_type,
    uint32_t *ctx_flags,
    int *locally_initiated,
    int *open)
{
    gss_OID mech_type_loc;
    uint32_t major_status;

    major_status = gss_inquire_context(minor_status, context_handle, src_name,
				       targ_name, lifetime_rec, &mech_type_loc,
				       ctx_flags, locally_initiated, open);
    gss_OID_loc_to_sap(mech_type_loc, mech_type);
    *mech_type = &gss_mech_krb5;
    return major_status;
}

uint32_t
sapgss_wrap_size_limit(
    uint32_t *minor_status,
    gss_ctx_id_t context_handle,
    int conf_req_flag,
    gss_qop_t qop_req,
    uint32_t req_output_size,
    uint32_t *max_input_size)
{
    *minor_status = 0;
    return gss_wrap_size_limit(minor_status, context_handle, conf_req_flag,
			       qop_req, req_output_size, max_input_size);
}

uint32_t
sapgss_export_sec_context(
    uint32_t *minor_status,
    gss_ctx_id_t *context_handle,
    gss_buffer_t interprocess_token)
{
    return gss_export_sec_context(minor_status, context_handle,
				  interprocess_token);
}

uint32_t
sapgss_import_sec_context(
    uint32_t *minor_status,
    gss_buffer_t interprocess_token,
    gss_ctx_id_t *context_handle)
{
    return gss_import_sec_context(minor_status, interprocess_token,
				  context_handle);
}

/* We must roll this ourselves */
uint32_t
sapgss_create_empty_oid_set(
    uint32_t *minor_status,
    sapgss_OID_set *oid_set)
{
    oid_set = calloc(1, sizeof(*oid_set));
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

/* Assumes [mc]alloc() never fails */
uint32_t
sapgss_add_oid_set_member(
    uint32_t *minor_status,
    sapgss_OID member_oid,
    sapgss_OID_set *oid_set)
{
    sapgss_OID list, last;
    size_t count;

    list = (*oid_set)->elements;
    count = (*oid_set)->count;
    /* calloc does overflow checking */
    (*oid_set)->elements = calloc(count, sizeof(sapgss_OID_desc));
    memcpy((*oid_set)->elements, list, count * sizeof(sapgss_OID_desc));
    last = &(*oid_set)->elements[count];
    last->elements = malloc(member_oid->length);
    memcpy(last->elements, member_oid->elements, member_oid->length);
    last->length = member_oid->length;
    (*oid_set)->count++;
    free(list);
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

uint32_t
sapgss_test_oid_set_member(
    uint32_t *minor_status,
    sapgss_OID member,
    sapgss_OID_set set,
    int *present)
{
    size_t i;

    for(i = 0; i < set->count; ++i) {
	if (set->elements[i].length == member->length &&
	    memcmp(set->elements[i].elements, member->elements,
		member->length) != 0) {
	    *present = 1;
	    *minor_status = 0;
	    return GSS_S_COMPLETE;
	}
    }
    *minor_status = 0;
    *present = 0;
    return GSS_S_COMPLETE;
}

uint32_t
sapgss_inquire_names_for_mech(
    uint32_t *minor_status,
    sapgss_OID mechanism,
    sapgss_OID_set *name_types)
{
    gss_OID mechanism_loc;
    gss_OID_set name_types_loc;
    uint32_t major_status;

    gss_OID_sap_to_loc(mechanism, &mechanism_loc);
    major_status = gss_inquire_names_for_mech(minor_status, mechanism_loc,
					      &name_types_loc);
    /* Comply with the gss_OID_sap_to_loc contract and free mechanism_loc */
    gss_OID_loc_release(&mechanism_loc);
    gss_OID_set_loc_to_sap(name_types_loc, name_types);
    return major_status;
}

uint32_t
sapgss_inquire_mechs_for_name(
    uint32_t *minor_status,
    gss_name_t input_name,
    sapgss_OID_set *mech_types)
{
    gss_OID_set mech_types_loc;
    uint32_t major_status;

    major_status = gss_inquire_mechs_for_name(minor_status, input_name,
					      &mech_types_loc);
    gss_OID_set_loc_to_sap(mech_types_loc, mech_types);
    return major_status;
}

uint32_t
sapgss_canonicalize_name(
    uint32_t *minor_status,
    gss_name_t input_name,
    sapgss_OID mech_type,
    gss_name_t *output_name)
{
    gss_OID mech_type_loc;
    uint32_t major_status;

    gss_OID_sap_to_loc(mech_type, &mech_type_loc);
    major_status = gss_canonicalize_name(minor_status, input_name,
					 mech_type_loc, output_name);
    /* Comply with the gss_OID_sap_to_loc contract and free mech_type_loc */
    gss_OID_loc_release(&mech_type_loc);
    return major_status;
}

uint32_t
sapgss_export_name(
    uint32_t *minor_status,
    gss_name_t input_name,
    gss_buffer_t exported_name)
{
    return gss_export_name(minor_status, input_name, exported_name);
}

uint32_t
sapgss_duplicate_name(
    uint32_t *minor_status,
    gss_name_t input_name,
    gss_name_t *dest_name)
{
    return gss_duplicate_name(minor_status, input_name, dest_name);
}

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

#endif /* SNCGSS_H */

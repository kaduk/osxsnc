/**********************************************************************/
/* $Id: sncgss.h,v 1.1.1.1 1999/08/24 14:36:21 d019080 Exp $
 **********************************************************************/
/*
 *  (C) Copyright 1999  SAP AG Walldorf
 *
 * SAP AG DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SAP AG BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#ifndef _SNCGSS_H
#define _SNCGSS_H  1

#ifndef UNREFERENCED_PARAMETER
#  define UNREFERENCED_PARAMETER(a)    ((a)=(a))
#endif

/**********************************************************************/
/*                                                                    */
/*  Public type definitions                                           */
/*                                                                    */
/**********************************************************************/

/**********************************************************************
 *
 * SAPGSS type definitions for use within the snc*.[ch] modules
 *
 * If these don't match with the GSS-API definitions, then
 * we might have a problem
 *
 **********************************************************************/



typedef enum sapgss_prod_id {
    SAPGSS_ID_DUMMY       = 0, /* No security         (26-jun-95) mrex   */
    SAPGSS_ID_GENERIC     = 1, /* Generic GSS-API v2 Mechanism,          */
			       /*   let GSS-API fight it out ...         */


    SAPGSS_ID_KERBEROS5   = 2, /* Kerberos 5 / MIT (26-jun-95) mrex	 */
#define SAPGSS_KERBEROS5_PREFIX   	"krb5"
#define SAPGSS_KERBEROS5_NAME	        "Kerberos 5/GSS-API v2"
#define SAPGSS_KERBEROS5_MECH_OID       {  9, "\052\206\110\206\367\022\001\002\002"     }
#define SAPGSS_KERBEROS5_CNAME_OID      { 10, "\052\206\110\206\367\022\001\002\002\001" }


    SAPGSS_ID_SECUDE      = 3, /* SecuDE 5      (21-sep-95) mrex */
#define SAPGSS_SECUDE_PREFIX		"secude"
#define SAPGSS_SECUDE_NAME	        "Secude 5 GSS-API v2"
#define SAPGSS_SECUDE_MECH_OID		{  6, "\053\044\003\001\045\001"       }
#define SAPGSS_SECUDE_CNAME_OID	        {  6, "\053\044\003\001\046\001"       }


    SAPGSS_ID_SAPNTLM     = 4, /* SAPNTLM       (08-okt-97) mrex */
#define SAPGSS_SAPNTLM_PREFIX		"sapntlm"
#define SAPGSS_SAPNTLM_NAME		"SAP's GSS-API v2 over NTLM(SSPI)"
#define SAPGSS_SAPNTLM_MECH_OID	        { 10, "\053\006\001\004\001\205\066\002\001\002"      }
#define SAPGSS_SAPNTLM_CNAME_OID        { 11, "\053\006\001\004\001\205\066\002\001\002\001"  }
  
  

    SAPGSS_ID_SPKM1       = 5, /* SPKM1         (18-aug-98) mrex */
#define SAPGSS_SPKM1_PREFIX		"spkm1"
#define SAPGSS_SPKM1_NAME	        "SPKM1 GSS-API v2 library"
#define SAPGSS_SPKM1_MECH_OID	        {  7, "\053\006\001\005\005\001\001"         }
#define SAPGSS_SPKM1_CNAME_OID	        {  9, "\053\006\001\004\001\201\172\002\001" }


    SAPGSS_ID_SPKM2       = 6, /* SPKM2         (18-aug-98) mrex */
#define SAPGSS_SPKM2_PREFIX		"spkm2"
#define SAPGSS_SPKM2_NAME	        "SPKM2 GSS-API v2 library"
#define SAPGSS_SPKM2_MECH_OID		{  7, "\053\006\001\005\005\001\002"         }
#define SAPGSS_SPKM2_CNAME_OID	        {  9, "\053\006\001\004\001\201\172\002\001" }


    SAPGSS_ID_RESERVED_1  = 7, /* reserved ID   (30-oct-96) mrex */


    SAPGSS_ID_ITSEC       = 8,
#define SAPGSS_ITSEC_PREFIX		"itsec"
#define SAPGSS_ITSEC_NAME
#define SAPGSS_ITSEC_MECH_OID
#define SAPGSS_ITSEC_CNAME_OID


    SAPGSS_ID_SDTI        = 9,
#define SAPGSS_SDTI_PREFIX		"sdti"
#define SAPGSS_SDTI_NAME	        "SDTI Connect Agent"
#define SAPGSS_SDTI_MECH_OID	        { 9, "\052\206\110\206\367\015\005\004\001" }
#define SAPGSS_SDTI_CNAME_OID		{ 9, "\052\206\110\206\367\015\005\004\002" }


    SAPGSS_ID_AMDCE	  = 10,
#define SAPGSS_AMDCE_PREFIX		"amdce"
#define SAPGSS_AMDCE_NAME	        "AccessMaster DCE"
#define SAPGSS_AMDCE_MECH_OID	        {  7, "\053\014\001\056\001\062\002"		 }
#define SAPGSS_AMDCE_CNAME_OID	        { 10, "\052\206\110\206\367\022\001\002\002\001" }

    SAPGSS_ID_INVALID
} SAPGSS_MECH_ID;

#define NUM_INTERNAL_STUBS  (SAPGSS_ID_SAPNTLM+1)


struct sapgss_info_s {
  int                major_rev;     /* major revision number of SNC-Adapter */
  int                minor_rev;     /* minor revision number of SNC-Adapter */

  char             * adapter_name;  /* SNC-Adapter identification string		     */
  SAPGSS_MECH_ID     mech_id;       /* SAP-registered gssapi mechanism identifier	     */

  char               integ_avail;   /* gssapi mechanism supports integrity protection	     */
  char               conf_avail;    /* gssapi mechanism supports confidentiality protection  */

  char		     unused1;	    /* historic -- not used  --  MUST BE 0   */

  char		     export_sec_context;
				    /* gssapi mechanism supports exporting   */
				    /* of an established security context,   */
				    /* as defined by GSS-API v2              */

  OM_uint32	     unused2;	    /* historic -- not used  --  MUST BE 0   */

  gss_OID_desc FAR * nt_canonical_name;
  gss_OID_desc FAR * nt_private_name1;
  gss_OID_desc FAR * nt_private_name2;
  gss_OID_desc FAR * nt_private_name3;
  gss_OID_desc FAR * nt_private_name4;

  char         FAR * mech_prefix_string;

  char   mutual_auth;		    /* gssapi mechanism supports mutual authentication */
  char   replay_prot;		    /* gssapi mechanism supports replay detection      */
  char   reserved1;
  char   reserved2;

  gss_OID_desc FAR * mech_oid;

};
  

#define SNCADAPT_INFO_LEN(x)  (offsetof(struct sapgss_info_s, x) + sizeof( ((struct sapgss_info_s *)0)->x ) )
#define SNCADAPT_BASIC_INFO_LEN   SNCADAPT_INFO_LEN( replay_prot )


/**********************************************************************/
/*                                                                    */
/*  Export interface                                                  */
/*    - Function list  ( Prototype definitions )                      */
/*                                                                    */
/**********************************************************************/

#define ARG3_INIT_ADAPTER				\
	struct sapgss_info_s FAR * ,			\
        size_t                     ,			\
        int 

OM_uint32 DLL_FUNC_DECO
sapsnc_init_adapter( ARG3_INIT_ADAPTER );



#define ARG4_EXPORT_CNAME_BLOB				 \
	OM_uint32   FAR * ,   	/* minor_status       */ \
	gss_name_t        ,   	/* input_name         */ \
	gss_buffer_t      ,     /* output_name_buffer */ \
        int		        /* adapter_index (snc internal use) */ 

OM_uint32 DLL_FUNC_DECO
sapsnc_export_cname_blob( ARG4_EXPORT_CNAME_BLOB );



#define ARG4_IMPORT_CNAME_BLOB				 \
	OM_uint32   FAR * ,	/* minor_status       */ \
	gss_buffer_t      ,	/* input_name_buffer  */ \
	gss_name_t  FAR * ,	/* output_name        */ \
        int                     /* adapter_index (snc internal use) */

OM_uint32 DLL_FUNC_DECO
sapsnc_import_cname_blob( ARG4_IMPORT_CNAME_BLOB );



/*
 *   GSS-API Version 1 functionality (RFC 1508 & 1509 )
 */
#define ARG8_ACQUIRE_CRED				  \
	OM_uint32     FAR * ,	/* minor_status        */ \
	gss_name_t          ,	/* desired_name        */ \
	OM_uint32           ,	/* time_req            */ \
	gss_OID_set         ,	/* desired_mechs       */ \
	gss_cred_usage_t    ,	/* cred_usage          */ \
	gss_cred_id_t FAR * ,	/* output_cred_handle  */ \
	gss_OID_set   FAR * ,	/* actual_mechs        */ \
	OM_uint32     FAR *     /* time_rec            */ 

OM_uint32 DLL_FUNC_DECO
sapgss_acquire_cred( ARG8_ACQUIRE_CRED );



#define ARG2_RELEASE_CRED					\
	OM_uint32     FAR * ,		/* minor_status */	\
	gss_cred_id_t FAR *		/* cred_handle  */

OM_uint32 DLL_FUNC_DECO
sapgss_release_cred( ARG2_RELEASE_CRED );



#define ARG13_INIT_SEC_CONTEXT					     \
	OM_uint32     FAR *    ,	/* minor_status           */ \
	gss_cred_id_t          ,	/* claimant_cred_handle   */ \
	gss_ctx_id_t  FAR *    ,	/* context_handle         */ \
	gss_name_t    	       ,	/* target_name            */ \
	gss_OID                ,	/* mech_type              */ \
	OM_uint32              ,	/* req_flags              */ \
	OM_uint32              ,	/* time_req               */ \
	gss_channel_bindings_t ,	/* input_chan_bindings    */ \
	gss_buffer_t           ,	/* input_token            */ \
	gss_OID       FAR *    ,	/* actual_mech_type       */ \
	gss_buffer_t           ,	/* output_token           */ \
	OM_uint32     FAR *    ,	/* ret_flags              */ \
	OM_uint32     FAR *             /* time_rec               */

OM_uint32 DLL_FUNC_DECO
sapgss_init_sec_context( ARG13_INIT_SEC_CONTEXT );



#define ARG11_ACCEPT_SEC_CONTEXT				    \
	OM_uint32     FAR *    ,	/* minor_status          */ \
	gss_ctx_id_t  FAR *    ,	/* context_handle        */ \
	gss_cred_id_t          ,	/* verifier_cred_handle  */ \
	gss_buffer_t           ,	/* input_token_buffer    */ \
	gss_channel_bindings_t ,	/* input_chan_bindings   */ \
	gss_name_t    FAR *    ,	/* src_name              */ \
	gss_OID       FAR *    ,	/* mech_type             */ \
	gss_buffer_t           ,	/* output_token          */ \
	OM_uint32     FAR *    ,	/* ret_flags             */ \
	OM_uint32     FAR *    ,	/* time_rec              */ \
	gss_cred_id_t FAR *		/* delegated_cred_handle */

OM_uint32 DLL_FUNC_DECO
sapgss_accept_sec_context( ARG11_ACCEPT_SEC_CONTEXT );



#define ARG3_PROCESS_CONTEXT_TOKEN \
	OM_uint32     FAR * ,		/* minor_status          */ \
	gss_ctx_id_t        ,		/* context_handle        */ \
	gss_buffer_t        		/* token_buffer          */

OM_uint32 DLL_FUNC_DECO
sapgss_process_context_token( ARG3_PROCESS_CONTEXT_TOKEN );



#define ARG3_DELETE_SEC_CONTEXT \
	OM_uint32     FAR * ,		/* minor_status         */ \
	gss_ctx_id_t  FAR * ,		/* context_handle       */ \
	gss_buffer_t        		/* output_token         */

OM_uint32 DLL_FUNC_DECO
sapgss_delete_sec_context( ARG3_DELETE_SEC_CONTEXT );



#define ARG3_CONTEXT_TIME					  \
	OM_uint32     FAR * ,		/* minor_status        */ \
	gss_ctx_id_t        ,		/* context_handle      */ \
	OM_uint32     FAR *		/* time_rec            */

OM_uint32 DLL_FUNC_DECO
sapgss_context_time( ARG3_CONTEXT_TIME );



/* v2 name for gss_sign() */
#define ARG5_GET_MIC						 \
	OM_uint32     FAR * ,		/* minor_status       */ \
	gss_ctx_id_t        ,		/* context_handle     */ \
	gss_qop_t           ,		/* qop_req            */ \
	gss_buffer_t        ,		/* message_buffer     */ \
	gss_buffer_t        		/* message_token      */

OM_uint32 DLL_FUNC_DECO
sapgss_get_mic( ARG5_GET_MIC );



/* v2 name for gss_verify() */
#define ARG5_VERIFY_MIC						 \
	OM_uint32    FAR * ,		/* minor_status       */ \
	gss_ctx_id_t       ,		/* context_handle     */ \
	gss_buffer_t       ,		/* message_buffer     */ \
	gss_buffer_t       ,		/* token_buffer       */ \
	gss_qop_t    FAR * 		/* qop_state          */
	
OM_uint32 DLL_FUNC_DECO
sapgss_verify_mic( ARG5_VERIFY_MIC );



/* v2 name for gss_seal() */
#define ARG7_WRAP						    \
	OM_uint32    FAR * ,		/* minor_status          */ \
	gss_ctx_id_t       ,		/* context_handle        */ \
	int                ,		/* conf_req_flag         */ \
	gss_qop_t          ,		/* qop_req               */ \
	gss_buffer_t       ,		/* input_message_buffer  */ \
	int          FAR * ,		/* conf_state            */ \
	gss_buffer_t       		/* output_message_buffer */

OM_uint32 DLL_FUNC_DECO
sapgss_wrap( ARG7_WRAP );



/* v2 name for gss_unseal() */
#define ARG6_UNWRAP						    \
	OM_uint32    FAR * ,		/* minor_status          */ \
	gss_ctx_id_t       ,		/* context_handle        */ \
	gss_buffer_t       ,		/* input_message_buffer  */ \
	gss_buffer_t       ,		/* output_message_buffer */ \
	int          FAR * ,		/* conf_state            */ \
	gss_qop_t    FAR * 		/* qop_state             */

OM_uint32 DLL_FUNC_DECO
sapgss_unwrap( ARG6_UNWRAP );



#define ARG6_DISPLAY_STATUS					    \
	OM_uint32    FAR * ,		/* minor_status          */ \
	OM_uint32          ,		/* status_value          */ \
	int                ,		/* status_type           */ \
	gss_OID            ,		/* mech_type             */ \
	OM_uint32    FAR * ,		/* message_context       */ \
	gss_buffer_t       		/* status_string         */

OM_uint32 DLL_FUNC_DECO
sapgss_display_status( ARG6_DISPLAY_STATUS );



#define ARG2_INDICATE_MECHS					    \
	OM_uint32    FAR * ,		/* minor_status          */ \
	gss_OID_set  FAR * 		/* mech_set              */

OM_uint32 DLL_FUNC_DECO
sapgss_indicate_mechs( ARG2_INDICATE_MECHS );



#define ARG4_COMPARE_NAME					    \
	OM_uint32    FAR * ,		/* minor_status          */ \
	gss_name_t         ,		/* name1                 */ \
	gss_name_t         ,		/* name2                 */ \
	int          FAR *		/* name_equal            */

OM_uint32 DLL_FUNC_DECO
sapgss_compare_name( ARG4_COMPARE_NAME );



#define ARG4_DISPLAY_NAME					    \
	OM_uint32    FAR * ,		/* minor_status          */ \
	gss_name_t         ,		/* input_name            */ \
	gss_buffer_t       ,		/* output_name_buffer    */ \
	gss_OID      FAR *		/* output_name_type      */

OM_uint32 DLL_FUNC_DECO
sapgss_display_name( ARG4_DISPLAY_NAME );



#define ARG4_IMPORT_NAME				        \
	OM_uint32    FAR * ,		/* minor_status      */ \
	gss_buffer_t       ,		/* input_name_buffer */ \
	gss_OID            ,		/* input_name_type   */ \
	gss_name_t   FAR * 		/* output_name       */

OM_uint32 DLL_FUNC_DECO
sapgss_import_name( ARG4_IMPORT_NAME );



#define ARG2_RELEASE_NAME				        \
	OM_uint32    FAR * ,		/* minor_status      */ \
	gss_name_t   FAR * 		/* input_name        */

OM_uint32 DLL_FUNC_DECO
sapgss_release_name( ARG2_RELEASE_NAME );



#define ARG2_RELEASE_BUFFER				        \
	OM_uint32    FAR * ,		/* minor_status      */ \
	gss_buffer_t       		/* buffer            */

OM_uint32 DLL_FUNC_DECO
sapgss_release_buffer( ARG2_RELEASE_BUFFER );



#define ARG2_RELEASE_OID_SET				        \
	OM_uint32    FAR * ,		/* minor_status      */ \
	gss_OID_set  FAR * 		/* set               */

OM_uint32 DLL_FUNC_DECO
sapgss_release_oid_set( ARG2_RELEASE_OID_SET );



#define ARG6_INQUIRE_CRED				        \
	OM_uint32         FAR * ,	/* minor_status      */ \
	gss_cred_id_t           ,	/* cred_handle       */ \
	gss_name_t        FAR * ,	/* name              */ \
	OM_uint32         FAR * ,	/* lifetime          */ \
	gss_cred_usage_t  FAR * ,	/* cred_usage        */ \
	gss_OID_set       FAR * 	/* mechanisms        */

OM_uint32 DLL_FUNC_DECO
sapgss_inquire_cred( ARG6_INQUIRE_CRED );




/*
 * New functionality of GSS-API Version 2
 */
#define ARG11_ADD_CRED						  \
	OM_uint32     FAR * ,		/* minor_status        */ \
	gss_cred_id_t       ,		/* input_cred_handle   */ \
	gss_name_t          ,		/* desired_name        */ \
	gss_OID             ,		/* desired_mech        */ \
	gss_cred_usage_t    ,		/* cred_usage          */ \
	OM_uint32           ,		/* initiator_time_req  */ \
	OM_uint32           ,		/* acceptor_time_req   */ \
	gss_cred_id_t FAR * ,		/* output_cred_handle  */ \
	gss_OID_set   FAR * ,		/* actual_mechs        */ \
	OM_uint32     FAR * ,		/* initiator_time_rec  */ \
	OM_uint32     FAR *		/* acceptor_time_rec   */

OM_uint32 DLL_FUNC_DECO
sapgss_add_cred( ARG11_ADD_CRED );



#define ARG7_INQUIRE_CRED_BY_MECH				  \
	OM_uint32        FAR * ,	/* minor_status        */ \
	gss_cred_id_t          ,	/* cred_handle         */ \
	gss_OID                ,	/* mech_type           */ \
	gss_name_t       FAR * ,	/* name                */ \
	OM_uint32        FAR * ,	/* initiator_lifetime  */ \
	OM_uint32        FAR * ,	/* acceptor_lifetime   */ \
	gss_cred_usage_t FAR *		/* cred_usage          */

OM_uint32 DLL_FUNC_DECO
sapgss_inquire_cred_by_mech( ARG7_INQUIRE_CRED_BY_MECH );



#define ARG9_INQUIRE_CONTEXT					 \
	OM_uint32    FAR * ,		/* minor_status	      */ \
	gss_ctx_id_t	   ,		/* context_handle     */ \
	gss_name_t   FAR * ,		/* initiator_name     */ \
	gss_name_t   FAR * ,		/* acceptor_name      */ \
	OM_uint32    FAR * ,		/* lifetime_rec	      */ \
	gss_OID	     FAR * ,		/* mech_type	      */ \
	OM_uint32    FAR * ,		/* ret_flags	      */ \
	int	     FAR * ,		/* locally_initiated  */ \
	int	     FAR * 		/* open		      */

OM_uint32 DLL_FUNC_DECO
sapgss_inquire_context( ARG9_INQUIRE_CONTEXT );



#define ARG6_WRAP_SIZE_LIMIT					    \
	OM_uint32    FAR * ,		/* minor_status		 */ \
	gss_ctx_id_t	   ,		/* context handle	 */ \
	int		   ,		/* conf_req_flag	 */ \
	gss_qop_t	   ,		/* qop_req		 */ \
	OM_uint32	   ,		/* requested output size */ \
	OM_uint32    FAR * 		/* maximum input size	 */

OM_uint32 DLL_FUNC_DECO
sapgss_wrap_size_limit( ARG6_WRAP_SIZE_LIMIT );



#define ARG3_EXPORT_SEC_CONTEXT					   \
	OM_uint32    FAR * ,		/* minor_status		*/ \
	gss_ctx_id_t FAR * ,		/* context_handle	*/ \
	gss_buffer_t			/* interprocess_token	*/

OM_uint32 DLL_FUNC_DECO
sapgss_export_sec_context( ARG3_EXPORT_SEC_CONTEXT );



#define ARG3_IMPORT_SEC_CONTEXT					   \
	OM_uint32    FAR * ,		/* minor_status	        */ \
	gss_buffer_t	   ,		/* interprocess_token	*/ \
	gss_ctx_id_t FAR *		/* context_handle	*/

OM_uint32 DLL_FUNC_DECO
sapgss_import_sec_context( ARG3_IMPORT_SEC_CONTEXT );



#define ARG2_CREATE_EMPTY_OID_SET				   \
	OM_uint32    FAR * ,		/* minor_status		*/ \
	gss_OID_set  FAR * 		/* oid_set		*/

OM_uint32 DLL_FUNC_DECO
sapgss_create_emtpy_oid_set( ARG2_CREATE_EMPTY_OID_SET );



#define ARG3_ADD_OID_SET_MEMBER					   \
	OM_uint32    FAR * ,		/* minor_status		*/ \
	gss_OID		   ,		/* member_oid		*/ \
	gss_OID_set  FAR *		/* oid_set		*/

OM_uint32 DLL_FUNC_DECO
sapgss_add_oid_set_member( ARG3_ADD_OID_SET_MEMBER );



#define ARG4_TEST_OID_SET_MEMBER				   \
	OM_uint32    FAR * ,		/* minor_status		*/ \
	gss_OID		   ,		/* member		*/ \
	gss_OID_set	   ,		/* set			*/ \
	int	     FAR * 		/* present		*/

OM_uint32 DLL_FUNC_DECO
sapgss_test_oid_set_member( ARG4_TEST_OID_SET_MEMBER );



#define ARG3_INQUIRE_NAMES_FOR_MECH				  \
	OM_uint32    FAR * ,		/* minor_status	       */ \
	gss_OID		   ,		/* mechanism_oid       */ \
	gss_OID_set  FAR * 		/* name_types	       */

OM_uint32 DLL_FUNC_DECO
sapgss_inquire_names_for_mech( ARG3_INQUIRE_NAMES_FOR_MECH );



#define ARG3_INQUIRE_MECHS_FOR_NAME				  \
	OM_uint32    FAR * ,		/* minor_status	       */ \
	gss_name_t	   ,		/* input_name	       */ \
	gss_OID_set  FAR * 		/* mechanism oids      */

OM_uint32 DLL_FUNC_DECO
sapgss_inquire_mechs_for_name( ARG3_INQUIRE_MECHS_FOR_NAME );



#define ARG4_CANONICALIZE_NAME					  \
	OM_uint32    FAR * ,		/* minor_status	       */ \
	gss_name_t	   ,		/* input_name	       */ \
	gss_OID		   ,		/* mechanism_type      */ \
	gss_name_t   FAR * 		/* output_name	       */

OM_uint32 DLL_FUNC_DECO
sapgss_canonicalize_name( ARG4_CANONICALIZE_NAME );



#define ARG3_EXPORT_NAME					  \
	OM_uint32    FAR * ,		/* minor_status	       */ \
	gss_name_t	   ,		/* input_name	       */ \
	gss_buffer_t	   		/* output_name_blob    */

OM_uint32 DLL_FUNC_DECO
sapgss_export_name( ARG3_EXPORT_NAME );



#define ARG3_DUPLICATE_NAME					   \
	OM_uint32    FAR * ,		/* minor_status		*/ \
	gss_name_t         ,		/* src_name		*/ \
	gss_name_t   FAR *		/* dest_name		*/

OM_uint32 DLL_FUNC_DECO
sapgss_duplicate_name( ARG3_DUPLICATE_NAME );

#endif  /* _SNCGSS_H */


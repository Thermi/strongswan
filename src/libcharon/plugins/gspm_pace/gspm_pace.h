/*
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup gspm_pace gspm_pace
 * @ingroup cplugins
 *
 * @defgroup gspm_pace_plugin gspm_pace_plugin
 * @{ @ingroup gspm_pace
 */

#ifndef GSPM_PACE_H_
#define GSPM_PACE_H_

#include <sa/ikev2/gspm/gspm_member.h>

typedef struct gspm_member_pace_t gspm_member_pace_t;

struct gspm_member_pace_t {

	/**
	 * implements gspm_member interface
	 */
	gspm_member_t gspm_member;

};


/**
 * Create an GSPM member to build signatures.
 *
 * @param ike_sa			associated ike_sa
 * @param cfg				authentication configuration
 * @param received_nonce	nonce received in IKE_SA_INIT
 * @param sent_nonce		nonce sent in IKE_SA_INIT
 * @param received_init		received IKE_SA_INIT message data
 * @param sent_init			sent IKE_SA_INIT message data
 * @param reserved			reserved bytes of the ID payload
 * @param member_id			ID of the selected GSPM member
 * @return					authenticator, NULL if not supported
 */
gspm_member_t *gspm_member_pace_create_builder(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_nonce,
									chunk_t received_init, chunk_t sent_init,
									char reserved[3]);

/**
 * Create an GSPM member to verify signatures.
 *
 * @param ike_sa			associated ike_sa
 * @param message			message containing authentication data
 * @param received_nonce	nonce received in IKE_SA_INIT
 * @param sent_nonce		nonce sent in IKE_SA_INIT
 * @param received_init		received IKE_SA_INIT message data
 * @param sent_init			sent IKE_SA_INIT message data
 * @param reserved			reserved bytes of the ID payload
 * @param member_id			ID of the selected GSPM member
 * @return					authenticator, NULL if not supported
 */
gspm_member_t *gspm_member_pace_create_verifier(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_nonce,
									chunk_t received_init, chunk_t sent_init,
									char reserved[3]);

#endif /** GSPM_PACE_PLUGIN_H_ @}*/

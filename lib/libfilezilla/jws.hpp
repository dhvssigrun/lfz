#ifndef LIBFILEZILLA_JWS_HEADER
#define LIBFILEZILLA_JWS_HEADER

/** \file
 * \brief Functions to create JSON Web Keys (JWK) and JSON Web Signatures (JWS)
 */

#include "json.hpp"

namespace fz {

/** \brief Creates a JWK pair
 *
 * Using EC key type with P-256 as algorithm.
 *
 * Returns both the private key and the public key as JSON structurs.
 */
std::pair<json, json> FZ_PUBLIC_SYMBOL create_jwk();

/** \brief Create a JWS, with optional protected data
 *
 * Only supports EC keys using P-256. Signature algorithm is ES256.
 *
 * Returns the signature in the flattened JSON JWS representation.
 *
 * Any values passed through an object in the extra_protected are included in the JWS protected headers.
 *
 * Does not use the JWS Unprotected Header.
 */
json FZ_PUBLIC_SYMBOL jws_sign_flattened(json const& priv, json const& payload, json const& extra_protected = {});
}

#endif

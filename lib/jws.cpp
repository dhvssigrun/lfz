#include "libfilezilla/encode.hpp"
#include "libfilezilla/hash.hpp"
#include "libfilezilla/jws.hpp"
#include "libfilezilla/util.hpp"
#include <nettle/ecdsa.h>
#include <nettle/ecc-curve.h>

#include <memory.h>

namespace fz {
namespace {
extern "C" void rnd(void *, size_t length, uint8_t *dst)
{
	random_bytes(length, dst);
}

std::string to_string(mpz_t n, size_t pad = 0)
{
	std::string ret;
	size_t s = nettle_mpz_sizeinbase_256_u(n);
	if (s) {
		ret.resize(std::max(s, pad));
		size_t offset{};
		if (s < pad) {
			offset = pad - s;
		}
		nettle_mpz_get_str_256(s, reinterpret_cast<unsigned char*>(ret.data() + offset), n);
	}
	return ret;
}
}

// Private and public key
std::pair<json, json> create_jwk()
{
	auto curve = nettle_get_secp_256r1();
	if (!curve) {
		return {};
	}

	ecc_scalar key;
	ecc_point pub;
	nettle_ecc_scalar_init(&key, curve);
	nettle_ecc_point_init(&pub, curve);
	nettle_ecdsa_generate_keypair(&pub, &key, nullptr, &rnd);

	mpz_t d;
	mpz_init(d);
	nettle_ecc_scalar_get(&key, d);

	json jpriv;
	jpriv["kty"] = "EC";
	jpriv["crv"] = "P-256";
	jpriv["d"] = fz::base64_encode(to_string(d), base64_type::url, false);

	mpz_clear(d);

	mpz_t x, y;
	mpz_init(x);
	mpz_init(y);
	nettle_ecc_point_get(&pub, x, y);

	json jpub;
	jpub["kty"] = "EC";
	jpub["crv"] = "P-256";
	jpub["x"] = fz::base64_encode(to_string(x), base64_type::url, false);
	jpub["y"] = fz::base64_encode(to_string(y), base64_type::url, false);

	mpz_clear(x);
	mpz_clear(y);

	nettle_ecc_scalar_clear(&key);
	nettle_ecc_point_clear(&pub);

	return {jpriv, jpub};
}

json jws_sign_flattened(json const& priv, json const& payload, json const& extra_protected)
{
	auto const ds = fz::base64_decode_s(priv["d"].string_value());
	if (priv["kty"].string_value() != "EC" || priv["crv"].string_value() != "P-256"|| ds.empty()) {
		return {};
	}

	auto curve = nettle_get_secp_256r1();
	if (!curve) {
		return {};
	}

	mpz_t d;
	mpz_init(d);
	nettle_mpz_set_str_256_u(d, ds.size(), reinterpret_cast<uint8_t const*>(ds.c_str()));

	ecc_scalar key;
	nettle_ecc_scalar_init(&key, curve);
	if (!nettle_ecc_scalar_set(&key, d)) {
		mpz_clear(d);
		nettle_ecc_scalar_clear(&key);
		return {};
	}
	mpz_clear(d);

	auto encoded_payload = fz::base64_encode(payload.to_string(), fz::base64_type::url, false);

	json prot;
	if (extra_protected.type() == json_type::object) {
		prot = extra_protected;
	}
	prot["alg"] = "ES256";

	auto encoded_prot = base64_encode(prot.to_string(), fz::base64_type::url, false);

	fz::hash_accumulator acc(fz::hash_algorithm::sha256);
	acc << encoded_prot << "." << encoded_payload;
	auto digest = acc.digest();


	struct dsa_signature sig;
	nettle_dsa_signature_init(&sig);

	nettle_ecdsa_sign(&key, nullptr, rnd, digest.size(), digest.data(), &sig);
	nettle_ecc_scalar_clear(&key);

	json ret;
	ret["protected"] = std::move(encoded_prot);
	ret["payload"] = std::move(encoded_payload);
	ret["signature"] = fz::base64_encode(to_string(sig.r, 32) + to_string(sig.s, 32), base64_type::url, false);

	nettle_dsa_signature_clear(&sig);

	return ret;
}
}

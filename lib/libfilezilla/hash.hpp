#ifndef LIBFILEZILLA_HASH_HEADER
#define LIBFILEZILLA_HASH_HEADER

/** \file
 * \brief Collection of cryptographic hash and MAC functions
 */

#include "libfilezilla.hpp"

#include <vector>
#include <string>

namespace fz {

/// List of supported hashing algorithms
enum class hash_algorithm
{
	md5, // insecure
	sha1, // insecure
	sha256,
	sha512
};

/// Accumulator for hashing large amounts of data
class FZ_PUBLIC_SYMBOL hash_accumulator final
{
public:
	/// Creates an initialized accumulator for the passed algorithm
	hash_accumulator(hash_algorithm algorithm);
	~hash_accumulator();

	hash_accumulator(hash_accumulator const&) = delete;
	hash_accumulator& operator=(hash_accumulator const&) = delete;

	void reinit();

	void update(std::string_view const& data);
	void update(std::basic_string_view<uint8_t> const& data);
	void update(std::vector<uint8_t> const& data);
	void update(uint8_t const* data, size_t size);
	void update(uint8_t in) {
		update(&in, 1);
	}

	/// Returns the raw digest and reinitializes the accumulator
	std::vector<uint8_t> digest();

	operator std::vector<uint8_t>() {
		return digest();
	}

	template<typename T>
	hash_accumulator& operator<<(T && in) {
		update(std::forward<T>(in));
		return *this;
	}

	class impl;
private:
	impl* impl_;
};

/** \brief Standard MD5
 *
 * Insecure, avoid using this
 */
std::vector<uint8_t> FZ_PUBLIC_SYMBOL md5(std::string_view const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL md5(std::vector<uint8_t> const& data);

/// \brief Standard SHA256
std::vector<uint8_t> FZ_PUBLIC_SYMBOL sha256(std::string_view const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL sha256(std::vector<uint8_t> const& data);

/** \brief Standard HMAC using SHA1
 *
 * While HMAC-SHA1 (as opposed to plain SHA1) is still considered secure in 2021, avoid using this for new things
 */
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha1(std::string_view const& key, std::string_view const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha1(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha1(std::vector<uint8_t> const& key, std::string_view const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha1(std::string_view const& key, std::vector<uint8_t> const& data);

/// \brief Standard HMAC using SHA256
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha256(std::string_view const& key, std::string_view const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha256(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha256(std::vector<uint8_t> const& key, std::string_view const& data);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL hmac_sha256(std::string_view const& key, std::vector<uint8_t> const& data);

std::vector<uint8_t> FZ_PUBLIC_SYMBOL pbkdf2_hmac_sha256(std::basic_string_view<uint8_t> const& password, std::basic_string_view<uint8_t> const& salt, size_t length, unsigned int iterations);

template <typename PasswordContainer, typename SaltContainer,
          std::enable_if_t<sizeof(typename PasswordContainer::value_type) == sizeof(uint8_t) &&
                           sizeof(typename SaltContainer::value_type) == sizeof(uint8_t)>* = nullptr>
std::vector<uint8_t> pbkdf2_hmac_sha256(PasswordContainer const& password, SaltContainer const& salt, size_t length, unsigned int iterations)
{
	return pbkdf2_hmac_sha256(std::basic_string_view<uint8_t>(reinterpret_cast<uint8_t const*>(password.data()), password.size()),
	                          std::basic_string_view<uint8_t>(reinterpret_cast<uint8_t const*>(salt.data()), salt.size()),
	                          length, iterations);
}
}

#endif

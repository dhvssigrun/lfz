#include "libfilezilla/libfilezilla.hpp"

#include "libfilezilla/hash.hpp"

#include <nettle/hmac.h>
#include <nettle/md5.h>
#include <nettle/pbkdf2.h>

// Undo Nettle's horrible namespace mangling fuckery
#ifdef pbkdf2_hmac_sha256
#undef pbkdf2_hmac_sha256
#endif

#include <nettle/sha2.h>

namespace fz {

class hash_accumulator::impl
{
public:
	virtual ~impl() = default;

	virtual void update(uint8_t const* data, size_t size) = 0;
	virtual void reinit() = 0;
	virtual std::vector<uint8_t> digest() = 0;
};

class hash_accumulator_md5 final : public hash_accumulator::impl
{
public:
	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_md5_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_md5_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(MD5_DIGEST_SIZE);
		nettle_md5_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	md5_ctx ctx_;
};

class hash_accumulator_sha1 final : public hash_accumulator::impl
{
public:
	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_sha1_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_sha1_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(SHA1_DIGEST_SIZE);
		nettle_sha1_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	sha1_ctx ctx_;
};

class hash_accumulator_sha256 final : public hash_accumulator::impl
{
public:
	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_sha256_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_sha256_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(SHA256_DIGEST_SIZE);
		nettle_sha256_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	sha256_ctx ctx_;
};

class hash_accumulator_sha512 final : public hash_accumulator::impl
{
public:
	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_sha512_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_sha512_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(SHA512_DIGEST_SIZE);
		nettle_sha512_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	sha512_ctx ctx_;
};

hash_accumulator::hash_accumulator(hash_algorithm algorithm)
{
	switch (algorithm) {
	case hash_algorithm::md5:
		impl_ = new hash_accumulator_md5;
		break;
	case hash_algorithm::sha1:
		impl_ = new hash_accumulator_sha1;
		break;
	case hash_algorithm::sha256:
		impl_ = new hash_accumulator_sha256;
		break;
	case hash_algorithm::sha512:
		impl_ = new hash_accumulator_sha512;
		break;
	}

	impl_->reinit();
}

hash_accumulator::~hash_accumulator()
{
	delete impl_;
}

void hash_accumulator::reinit()
{
	impl_->reinit();
}

void hash_accumulator::update(std::string_view const& data)
{
	if (!data.empty()) {
		impl_->update(reinterpret_cast<uint8_t const*>(data.data()), data.size());
	}
}

void hash_accumulator::update(std::basic_string_view<uint8_t> const& data)
{
	if (!data.empty()) {
		impl_->update(data.data(), data.size());
	}
}

void hash_accumulator::update(std::vector<uint8_t> const& data)
{
	if (!data.empty()) {
		impl_->update(data.data(), data.size());
	}
}

void hash_accumulator::update(uint8_t const* data, size_t size)
{
	impl_->update(data, size);
}

std::vector<uint8_t> hash_accumulator::digest()
{
	return impl_->digest();
}

namespace {
// In C++17, require ContiguousContainer
template<typename DataContainer>
std::vector<uint8_t> md5_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_md5 acc;
	acc.reinit();
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename DataContainer>
std::vector<uint8_t> sha1_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_sha1 acc;
	acc.reinit();
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename DataContainer>
std::vector<uint8_t> sha256_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_sha256 acc;
	acc.reinit();
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename DataContainer>
std::vector<uint8_t> sha512_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_sha512 acc;
	acc.reinit();
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename KeyContainer, typename DataContainer>
std::vector<uint8_t> hmac_sha1_impl(KeyContainer const& key, DataContainer const& data)
{
	static_assert(sizeof(typename KeyContainer::value_type) == 1, "Bad container type");
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	std::vector<uint8_t> ret;

	hmac_sha1_ctx ctx;
	nettle_hmac_sha1_set_key(&ctx, key.size(), key.empty() ? nullptr : reinterpret_cast<uint8_t const*>(key.data()));

	if (!data.empty()) {
		nettle_hmac_sha1_update(&ctx, data.size(), reinterpret_cast<uint8_t const*>(data.data()));
	}

	ret.resize(SHA1_DIGEST_SIZE);
	nettle_hmac_sha1_digest(&ctx, ret.size(), ret.data());

	return ret;
}

template<typename KeyContainer, typename DataContainer>
std::vector<uint8_t> hmac_sha256_impl(KeyContainer const& key, DataContainer const& data)
{
	static_assert(sizeof(typename KeyContainer::value_type) == 1, "Bad container type");
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	std::vector<uint8_t> ret;

	hmac_sha256_ctx ctx;
	nettle_hmac_sha256_set_key(&ctx, key.size(), key.empty() ? nullptr : reinterpret_cast<uint8_t const*>(key.data()));

	if (!data.empty()) {
		nettle_hmac_sha256_update(&ctx, data.size(), reinterpret_cast<uint8_t const*>(data.data()));
	}

	ret.resize(SHA256_DIGEST_SIZE);
	nettle_hmac_sha256_digest(&ctx, ret.size(), ret.data());

	return ret;
}
}

std::vector<uint8_t> md5(std::vector<uint8_t> const& data)
{
	return md5_impl(data);
}

std::vector<uint8_t> md5(std::string_view const& data)
{
	return md5_impl(data);
}

std::vector<uint8_t> sha1(std::vector<uint8_t> const& data)
{
	return sha1_impl(data);
}

std::vector<uint8_t> sha1(std::string_view const& data)
{
	return sha1_impl(data);
}

std::vector<uint8_t> sha256(std::vector<uint8_t> const& data)
{
	return sha256_impl(data);
}

std::vector<uint8_t> sha256(std::string_view const& data)
{
	return sha256_impl(data);
}

std::vector<uint8_t> sha512(std::vector<uint8_t> const& data)
{
	return sha512_impl(data);
}

std::vector<uint8_t> sha512(std::string_view const& data)
{
	return sha512_impl(data);
}

std::vector<uint8_t> hmac_sha1(std::string_view const& key, std::string_view const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha1(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha1(std::vector<uint8_t> const& key, std::string_view const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha1(std::string_view const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::string_view const& key, std::string_view const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::vector<uint8_t> const& key, std::string_view const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::string_view const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> pbkdf2_hmac_sha256(std::basic_string_view<uint8_t> const& password, std::basic_string_view<uint8_t> const& salt, size_t length, unsigned int iterations)
{
	std::vector<uint8_t> ret;

	if (!password.empty() && !salt.empty()) {
		ret.resize(length);
		nettle_pbkdf2_hmac_sha256(password.size(), password.data(), iterations, salt.size(), salt.data(), length, ret.data());
	}

	return ret;
}
}

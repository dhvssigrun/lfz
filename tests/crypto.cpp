#include "../lib/libfilezilla/encryption.hpp"
#include "../lib/libfilezilla/signature.hpp"
#include "../lib/libfilezilla/util.hpp"

#include "test_utils.hpp"

#include <string.h>

class crypto_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(crypto_test);
	CPPUNIT_TEST(test_encryption);
	CPPUNIT_TEST(test_encryption_with_password);
	CPPUNIT_TEST(test_signature);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_encryption();
	void test_encryption_with_password();
	void test_signature();
};

CPPUNIT_TEST_SUITE_REGISTRATION(crypto_test);

void crypto_test::test_encryption()
{
	auto priv = fz::private_key::generate();
	priv.generate();

	auto const pub = priv.pubkey();

	std::string const plain = "Hello world";

	auto cipher = fz::encrypt(plain, pub);
	CPPUNIT_ASSERT(fz::decrypt(cipher, priv) == std::vector<uint8_t>(plain.cbegin(), plain.cend()));
}


void crypto_test::test_encryption_with_password()
{
	auto const salt = fz::random_bytes(fz::private_key::salt_size);

	std::string const plain = "Hello world";
	std::vector<uint8_t> cipher;

	{
		auto priv = fz::private_key::from_password("super secret", salt);
		CPPUNIT_ASSERT(priv);

		auto const pub = priv.pubkey();

		cipher = fz::encrypt(plain, pub);
	}


	{
		auto priv = fz::private_key::from_password("super secret", salt);
		CPPUNIT_ASSERT(priv);

		CPPUNIT_ASSERT(fz::decrypt(cipher, priv) == std::vector<uint8_t>(plain.cbegin(), plain.cend()));
	}

}

void crypto_test::test_signature()
{
	// Test privkey generation
	auto const priv = fz::private_signing_key::generate();
	CPPUNIT_ASSERT(priv);
	CPPUNIT_ASSERT(!priv.to_base64().empty());
	CPPUNIT_ASSERT(fz::private_signing_key::from_base64(priv.to_base64()));

	// Test pubkey generation
	auto const pub = priv.pubkey();
	CPPUNIT_ASSERT(pub);
	CPPUNIT_ASSERT(!pub.to_base64().empty());
	CPPUNIT_ASSERT(fz::public_verification_key::from_base64(pub.to_base64()));

	// Test signing attached
	auto sig = fz::sign("Hello", priv);
	std::string_view sigv(reinterpret_cast<char const*>(sig.data()), sig.size());
	CPPUNIT_ASSERT(!sig.empty());

	// Test signing detached
	auto sig2 = fz::sign("Hello", priv, false);
	std::string_view sig2v(reinterpret_cast<char const*>(sig2.data()), sig2.size());
	CPPUNIT_ASSERT(!sig2.empty());

	// Test sig verification
	CPPUNIT_ASSERT(fz::verify(sig, pub));
	CPPUNIT_ASSERT(fz::verify("Hello", sig2v, pub));
	CPPUNIT_ASSERT(!fz::verify(sig2, pub));
	CPPUNIT_ASSERT(!fz::verify("Hello", sigv, pub));

	// Test verification with wrong key fails
	auto const pub2 = fz::private_signing_key::generate().pubkey();
	CPPUNIT_ASSERT(pub2);
	CPPUNIT_ASSERT(!fz::verify(sig, pub2));
	CPPUNIT_ASSERT(!fz::verify("Hello", sig2v, pub2));

	// Test verification of modified data fails
	sig[5] ^= 0x2c;
	sig2[5] ^= 0x2c;
	CPPUNIT_ASSERT(!fz::verify(sig, pub));
	CPPUNIT_ASSERT(!fz::verify("Hello", sig2v, pub));
}

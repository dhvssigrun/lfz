#include "../lib/libfilezilla/json.hpp"

#include "test_utils.hpp"

class json_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(json_test);
	CPPUNIT_TEST(test_surrogate_pair);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_surrogate_pair();
};

CPPUNIT_TEST_SUITE_REGISTRATION(json_test);

void json_test::test_surrogate_pair()
{
	auto j = fz::json::parse("\"\\ud83d\\ude01\"");
	CPPUNIT_ASSERT(j);
	auto const& v = j.string_value();
	CPPUNIT_ASSERT(v.size() == 4);
	auto u = reinterpret_cast<unsigned char const*>(v.c_str()); // as char may be signed
	CPPUNIT_ASSERT(u[0] == 0xf0);
	CPPUNIT_ASSERT(u[1] == 0x9f);
	CPPUNIT_ASSERT(u[2] == 0x98);
	CPPUNIT_ASSERT(u[3] == 0x81);
}

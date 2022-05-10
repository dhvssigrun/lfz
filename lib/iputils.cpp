#include "libfilezilla/iputils.hpp"
#include "libfilezilla/encode.hpp"

namespace fz {
template<typename String, typename Char = typename String::value_type, typename OutString = std::basic_string<Char>>
OutString do_get_ipv6_long_form(String const& short_address)
{
	size_t start = 0;
	size_t end = short_address.size();

	if (!short_address.empty() && short_address[0] == '[') {
		if (short_address.back() != ']') {
			return OutString();
		}
		++start;
		--end;
	}

	if ((end - start) < 2 || (end - start) > 39) {
		return OutString();
	}

	Char buf[39] = {
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0'
	};

	size_t left_segments{};

	// Left half, before possible ::
	while (left_segments < 8 && start < end) {
		size_t pos = short_address.find(':', start);
		if (pos == String::npos) {
			pos = end;
		}
		if (pos == start) {
			if (!left_segments) {
				if (short_address[start + 1] != ':') {
					return OutString();
				}
				start = pos + 1;
			}
			else {
				start = pos;
			}
			break;
		}

		size_t group_length = pos - start;
		if (group_length > 4) {
			return OutString();
		}

		Char* out = buf + 5 * left_segments;
		out += 4 - group_length;
		for (size_t i = start; i < pos; ++i) {
			Char const& c = short_address[i];
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				*out++ = c;
			}
			else if (c >= 'A' && c <= 'F') {
				*out++ = c + ('a' - 'A');
			}
			else {
				// Invalid character
				return OutString();
			}
		}
		++left_segments;

		start = pos + 1;
	}

	size_t right_segments{};

	// Right half, after possible ::
	while (left_segments + right_segments < 8 && start < end) {
		--end;
		size_t pos = short_address.rfind(':', end); // Cannot be npos

		size_t const group_length = end - pos;
		if (!group_length) {
			if (left_segments || right_segments) {
				/// ::: or two ::
				return OutString();
			}
			break;
		}
		else if (group_length > 4) {
			return OutString();
		}

		Char* out = buf + 5 * (8 - right_segments) - 1;
		for (size_t i = end; i > pos; --i) {
			Char const& c = short_address[i];
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				*(--out) = c;
			}
			else if (c >= 'A' && c <= 'F') {
				*(--out) = c + ('a' - 'A');
			}
			else {
				// Invalid character
				return OutString();
			}
		}
		++right_segments;

		end = pos;
	}

	if (start < end) {
		// Too many segments
		return OutString();
	}

	return OutString(buf, 39);
}

std::string get_ipv6_long_form(std::string_view const& short_address)
{
	return do_get_ipv6_long_form(short_address);
}

std::wstring get_ipv6_long_form(std::wstring_view const& short_address)
{
	return do_get_ipv6_long_form(short_address);
}

template<typename String, typename Char = typename String::value_type>
bool do_is_routable_address(String const& address)
{
	auto const type = get_address_type(address);

	if (type == address_type::ipv6) {
		auto long_address = do_get_ipv6_long_form(address);
		if (long_address.size() != 39) {
			return false;
		}
		if (long_address[0] == '0') {
			// ::/128
			if (long_address == fzS(Char, "0000:0000:0000:0000:0000:0000:0000:0000")) {
				return false;
			}
			// ::1/128
			if (long_address == fzS(Char, "0000:0000:0000:0000:0000:0000:0000:0001")) {
				return false;
			}

			if (long_address.substr(0, 30) == fzS(Char, "0000:0000:0000:0000:0000:ffff:")) {
				char const dot = '.';
				// IPv4 mapped
				std::string ipv4 =
					toString<std::string>(hex_char_to_int(long_address[30]) * 16 + hex_char_to_int(long_address[31])) + dot +
					toString<std::string>(hex_char_to_int(long_address[32]) * 16 + hex_char_to_int(long_address[33])) + dot +
					toString<std::string>(hex_char_to_int(long_address[35]) * 16 + hex_char_to_int(long_address[36])) + dot +
					toString<std::string>(hex_char_to_int(long_address[37]) * 16 + hex_char_to_int(long_address[38]));

				return do_is_routable_address(ipv4);
			}

			return true;
		}
		if (long_address[0] == 'f') {
			if (long_address[1] == 'e') {
				// fe80::/10 (link local)
				int v = hex_char_to_int(long_address[2]);
				return (v & 0xc) != 0x8;
			}
			else if (long_address[1] == 'c' || long_address[1] == 'd') {
				// fc00::/7 (site local)
				return false;
			}
		}

		return true;
	}
	else if (type == address_type::ipv4) {
		if (address.size() < 7) {
			return false;
		}

		// Assumes address is already a valid IP address
		if (address.substr(0, 3) == fzS(Char, "127") ||
			address.substr(0, 3) == fzS(Char, "10.") ||
			address.substr(0, 7) == fzS(Char, "192.168") ||
			address.substr(0, 7) == fzS(Char, "169.254"))
		{
			return false;
		}

		if (address.substr(0, 3) == fzS(Char, "172")) {
			auto middle = address.substr(4);
			auto pos = middle.find('.');
			if (pos == String::npos || pos > 3) {
				return false;
			}

			auto segment = fz::to_integral<uint8_t>(middle.substr(0, pos)); // Cannot throw as we have verified it to be a valid IPv4
			if (segment >= 16 && segment <= 31) {
				return false;
			}
		}

		return true;
	}

	return false;
}

bool is_routable_address(std::string_view const& address)
{
	return do_is_routable_address(address);
}

bool is_routable_address(std::wstring_view const& address)
{
	return do_is_routable_address(address);
}

template<typename String>
address_type do_get_address_type(String const& address)
{
	if (!do_get_ipv6_long_form(address).empty()) {
		return address_type::ipv6;
	}

	int segment = 0;
	int dotcount = 0;

	for (size_t i = 0; i < address.size(); ++i) {
		auto const c = address[i];
		if (c == '.') {
			if (i + 1 < address.size() && address[i + 1] == '.') {
				// Disallow multiple dots in a row
				return address_type::unknown;
			}

			if (segment > 255) {
				return address_type::unknown;
			}
			if (!dotcount && !segment) {
				return address_type::unknown;
			}
			++dotcount;
			segment = 0;
		}
		else if (c < '0' || c > '9') {
			return address_type::unknown;
		}
		else {
			segment = segment * 10 + c - '0';
		}
	}
	if (dotcount != 3) {
		return address_type::unknown;
	}

	if (segment > 255) {
		return address_type::unknown;
	}

	return address_type::ipv4;
}

address_type get_address_type(std::string_view const& address)
{
	return do_get_address_type(address);
}

address_type get_address_type(std::wstring_view const& address)
{
	return do_get_address_type(address);
}
}

#ifndef LIBFILEZILLA_STRING_HEADER
#define LIBFILEZILLA_STRING_HEADER

#include "libfilezilla.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

/** \file
 * \brief String types and assorted functions.
 *
 * Defines the \ref fz::native_string type and offers various functions to convert between
 * different string types.
 */

namespace fz {

/** \typedef native_string
 *
 * \brief A string in the system's native character type and encoding.\n Note: This typedef changes depending on platform!
 *
 * On Windows, the system's native encoding is UTF-16, so native_string is typedef'ed to std::wstring.
 *
 * On all other platform, native_string is a typedef for std::string.
 *
 * Always using native_string has the benefit that no conversion needs to be performed which is especially useful
 * if dealing with filenames.
 */

#ifdef FZ_WINDOWS
typedef std::wstring native_string;
typedef std::wstring_view native_string_view;
#endif
#if defined(FZ_UNIX) || defined(FZ_MAC)
typedef std::string native_string;
typedef std::string_view native_string_view;
#endif

/** \brief Converts std::string to native_string.
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
native_string FZ_PUBLIC_SYMBOL to_native(std::string_view const& in);

/** \brief Convert std::wstring to native_string.
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
native_string FZ_PUBLIC_SYMBOL to_native(std::wstring_view const& in);

/// Avoid converting native_string to native_string_view and back to native_string
template<typename T, typename std::enable_if_t<std::is_same_v<native_string, typename std::decay_t<T>>, int> = 0>
inline native_string to_native(T const& in) {
	return in;
}

/** \brief Locale-sensitive stricmp
 *
 * Like std::string::compare but case-insensitive, respecting locale.
 *
 * \note does not handle embedded null
 */
int FZ_PUBLIC_SYMBOL stricmp(std::string_view const& a, std::string_view const& b);
int FZ_PUBLIC_SYMBOL stricmp(std::wstring_view const& a, std::wstring_view const& b);

/** \brief Converts ASCII uppercase characters to lowercase as if C-locale is used.

 Under some locales there is a different case-relationship
 between the letters a-z and A-Z as one expects from ASCII under the C locale.
 In Turkish for example there are different variations of the letter i,
 namely dotted and dotless. What we see as 'i' is the lowercase dotted i and
 'I' is the  uppercase dotless i. Since std::tolower is locale-aware, I would
 become the dotless lowercase i.

 This is not always what we want. FTP commands for example are case-insensitive
 ASCII strings, LIST and list are the same.

 tolower_ascii instead converts all types of 'i's to the ASCII i as well.

 \return  A-Z becomes a-z.\n In addition dotless lowercase i and dotted uppercase i also become the standard i.

 */
template<typename Char>
Char tolower_ascii(Char c) {
	if (c >= 'A' && c <= 'Z') {
		return c + ('a' - 'A');
	}
	return c;
}

template<>
std::wstring::value_type FZ_PUBLIC_SYMBOL tolower_ascii(std::wstring::value_type c);

/// \brief Converts ASCII lowercase characters to uppercase as if C-locale is used.
template<typename Char>
Char toupper_ascii(Char c) {
	if (c >= 'a' && c <= 'z') {
		return c + ('A' - 'a');
	}
	return c;
}

template<>
std::wstring::value_type FZ_PUBLIC_SYMBOL toupper_ascii(std::wstring::value_type c);

/** \brief tr_tolower_ascii does for strings what tolower_ascii does for individual characters
 */
 // Note: For UTF-8 strings it works on individual octets!
std::string FZ_PUBLIC_SYMBOL str_tolower_ascii(std::string_view const& s);
std::wstring FZ_PUBLIC_SYMBOL str_tolower_ascii(std::wstring_view const& s);

std::string FZ_PUBLIC_SYMBOL str_toupper_ascii(std::string_view const& s);
std::wstring FZ_PUBLIC_SYMBOL str_toupper_ascii(std::wstring_view const& s);

/** \brief Comparator to be used for std::map for case-insensitive keys
 *
 * Comparison is done locale-agnostic.
 * Useful for key-value pairs in protocols, e.g. HTTP headers.
 */
struct FZ_PUBLIC_SYMBOL less_insensitive_ascii final
{
	template<typename T>
	bool operator()(T const& lhs, T const& rhs) const {
		return std::lexicographical_compare(lhs.cbegin(), lhs.cend(), rhs.cbegin(), rhs.cend(),
		    [](typename T::value_type const& a, typename T::value_type const& b) {
			    return tolower_ascii(a) < tolower_ascii(b);
		    }
		);
	}
};

/** \brief Locale-insensitive stricmp
 *
 * Equivalent to str_tolower_ascii(a).compare(str_tolower_ascii(b));
 */
inline bool equal_insensitive_ascii(std::string_view a, std::string_view b)
{
	return std::equal(a.cbegin(), a.cend(), b.cbegin(), b.cend(),
	    [](auto const& a, auto const& b) {
		    return tolower_ascii(a) == tolower_ascii(b);
	    }
	);
}
inline bool equal_insensitive_ascii(std::wstring_view a, std::wstring_view b)
{
	return std::equal(a.cbegin(), a.cend(), b.cbegin(), b.cend(),
	    [](auto const& a, auto const& b) {
		    return tolower_ascii(a) == tolower_ascii(b);
	    }
	);
}

/** \brief Converts from std::string in system encoding into std::wstring
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
std::wstring FZ_PUBLIC_SYMBOL to_wstring(std::string_view const& in);

/** \brief Returns identity, that way to_wstring can be called with native_string.
 *
 * This template deals with wide string literals, std::wstring and std::wstring_view parameters.
 */
template <typename T>
inline auto to_wstring(T && in) -> decltype(std::wstring(std::forward<T>(in)))
{
	return std::wstring(std::forward<T>(in));
}

/// Converts from arithmetic type to std::wstring
template<typename Arg>
inline typename std::enable_if<std::is_arithmetic_v<std::decay_t<Arg>>, std::wstring>::type to_wstring(Arg && arg)
{
	return std::to_wstring(std::forward<Arg>(arg));
}


/** \brief Converts from std::string in UTF-8 into std::wstring
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
std::wstring FZ_PUBLIC_SYMBOL to_wstring_from_utf8(std::string_view const& in);
std::wstring FZ_PUBLIC_SYMBOL to_wstring_from_utf8(char const* s, size_t len);

class buffer;
std::wstring FZ_PUBLIC_SYMBOL to_wstring_from_utf8(fz::buffer const& in);

/** \brief Converts from std::wstring into std::string in system encoding
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
std::string FZ_PUBLIC_SYMBOL to_string(std::wstring_view const& in);

/** \brief Returns identity, that way to_wstring can be called with native_string.
 *
 * This template deals with string literals, std::string and std::string_view parameters.
 */
template <typename T>
inline auto to_string(T && in) -> decltype(std::string(std::forward<T>(in)))
{
	return std::string(std::forward<T>(in));
}


/// Converts from arithmetic type to std::string
template<typename Arg>
inline typename std::enable_if<std::is_arithmetic_v<std::decay_t<Arg>>, std::string>::type to_string(Arg && arg)
{
	return std::to_string(std::forward<Arg>(arg));
}


/// Returns length of 0-terminated character sequence. Works with both narrow and wide-characters.
template<typename Char>
size_t strlen(Char const* str) {
	return std::char_traits<Char>::length(str);
}


/** \brief Converts from std::string in native encoding into std::string in UTF-8
 *
 * \return the converted string on success. On failure an empty string is returned.
 *
 * \note Does not handle embedded nulls
 */
std::string FZ_PUBLIC_SYMBOL to_utf8(std::string_view const& in);

/** \brief Converts from std::wstring in native encoding into std::string in UTF-8
 *
 * \return the converted string on success. On failure an empty string is returned.
 *
 * \note Does not handle embedded nulls
 */
std::string FZ_PUBLIC_SYMBOL to_utf8(std::wstring_view const& in);

/// Calls either fz::to_string or fz::to_wstring depending on the passed template argument
template<typename String, typename Arg>
inline auto toString(Arg&& arg) -> typename std::enable_if<std::is_same_v<String, std::string>, decltype(to_string(std::forward<Arg>(arg)))>::type
{
	return to_string(std::forward<Arg>(arg));
}

template<typename String, typename Arg>
inline auto toString(Arg&& arg) -> typename std::enable_if<std::is_same_v<String, std::wstring>, decltype(to_wstring(std::forward<Arg>(arg)))>::type
{
	return to_wstring(std::forward<Arg>(arg));
}

#if !defined(fzT) || defined(DOXYGEN)
#ifdef FZ_WINDOWS
/** \brief Macro for a string literal in system-native character type.\n Note: Macro definition changes depending on platform!
 *
 * Example: \c fzT("this string is wide on Windows and narrow elsewhere")
 */
#define fzT(x) L ## x
#else
/** \brief Macro for a string literal in system-native character type.\n Note: Macro definition changes depending on platform!
 *
 * Example: \c fzT("this string is wide on Windows and narrow elsewhere")
 */
#define fzT(x) x
#endif
#endif

 /// Returns the function argument of the type matching the template argument. \sa fzS
template<typename Char>
Char const* choose_string(char const* c, wchar_t const* w);

template<> inline char const* choose_string(char const* c, wchar_t const*) { return c; }
template<> inline wchar_t const* choose_string(char const*, wchar_t const* w) { return w; }

#if !defined(fzS) || defined(DOXYGEN)
/** \brief Macro to get const pointer to a string of the corresponding type
 *
 * Useful when using string literals in templates where the type of string
 * is a template argument:
 * \code
 *   template<typename String>
 *   String append_foo(String const& s) {
 *       s += fzS(String::value_type, "foo");
 *   }
 * \endcode
 */
#define fzS(Char, s) fz::choose_string<Char>(s, L ## s)
#endif

 /** \brief Returns \c in with all occurrences of \c find in the input string replaced with \c replacement
  *
  * \arg find If empty, no replacement takes place.
  */
std::string FZ_PUBLIC_SYMBOL replaced_substrings(std::string_view const& in, std::string_view const& find, std::string_view const& replacement);
std::wstring FZ_PUBLIC_SYMBOL replaced_substrings(std::wstring_view const& in, std::wstring_view const& find, std::wstring_view const& replacement);

/// Returns \c in with all occurrences of \c find in the input string replaced with \c replacement
std::string FZ_PUBLIC_SYMBOL replaced_substrings(std::string_view const& in, char find, char replacement);
std::wstring FZ_PUBLIC_SYMBOL replaced_substrings(std::wstring_view const& in, wchar_t find, wchar_t replacement);

/** \brief Modifies \c in, replacing all occurrences of \c find with \c replacement
 *
 * \arg find If empty, no replacement takes place.
 */
bool FZ_PUBLIC_SYMBOL replace_substrings(std::string& in, std::string_view const& find, std::string_view const& replacement);
bool FZ_PUBLIC_SYMBOL replace_substrings(std::wstring& in, std::wstring_view const& find, std::wstring_view const& replacement);

/// Modifies \c in, replacing all occurrences of \c find with \c replacement
bool FZ_PUBLIC_SYMBOL replace_substrings(std::string& in, char find, char replacement);
bool FZ_PUBLIC_SYMBOL replace_substrings(std::wstring& in, wchar_t find, wchar_t replacement);

/**
 * \brief Tokenizes string.
 *
 * \param delims the delimiters to look for
 * \param ignore_empty If true, empty tokens are omitted in the output
 */
std::vector<std::string> FZ_PUBLIC_SYMBOL strtok(std::string_view const& tokens, std::string_view const& delims, bool const ignore_empty = true);
std::vector<std::wstring> FZ_PUBLIC_SYMBOL strtok(std::wstring_view const& tokens, std::wstring_view const& delims, bool const ignore_empty = true);
inline auto FZ_PUBLIC_SYMBOL strtok(std::string_view const& tokens, char const delim, bool const ignore_empty = true) {
	return strtok(tokens, std::string_view(&delim, 1), ignore_empty);
}
inline auto FZ_PUBLIC_SYMBOL strtok(std::wstring_view const& tokens, wchar_t const delim, bool const ignore_empty = true) {
	return strtok(tokens, std::wstring_view(&delim, 1), ignore_empty);
}

/**
 * \brief Tokenizes string.
 *
 * \warning This function returns string_views, mind the lifetime of the string passed in tokens.
 *
 * \param delims the delimiters to look for
 * \param ignore_empty If true, empty tokens are omitted in the output
 */
std::vector<std::string_view> FZ_PUBLIC_SYMBOL strtok_view(std::string_view const& tokens, std::string_view const& delims, bool const ignore_empty = true);
std::vector<std::wstring_view> FZ_PUBLIC_SYMBOL strtok_view(std::wstring_view const& tokens, std::wstring_view const& delims, bool const ignore_empty = true);
inline auto FZ_PUBLIC_SYMBOL strtok_view(std::string_view const& tokens, char const delim, bool const ignore_empty = true) {
	return strtok_view(tokens, std::string_view(&delim, 1), ignore_empty);
}
inline auto FZ_PUBLIC_SYMBOL strtok_view(std::wstring_view const& tokens, wchar_t const delim, bool const ignore_empty = true) {
	return strtok_view(tokens, std::wstring_view(&delim, 1), ignore_empty);
}

/// \private
template<typename T, typename String>
T to_integral_impl(String const& s, T const errorval = T())
{
	if constexpr (std::is_same_v<T, bool>) {
		return static_cast<T>(to_integral_impl<unsigned int>(s, static_cast<unsigned int>(errorval))) != 0;
	}
	else if constexpr (std::is_enum_v<T>) {
		return static_cast<T>(to_integral_impl<std::underlying_type_t<T>>(s, static_cast<std::underlying_type_t<T>>(errorval)));
	}
	else {
		T ret{};
		auto it = s.cbegin();
		if (it != s.cend() && (*it == '-' || *it == '+')) {
			++it;
		}

		if (it == s.cend()) {
			return errorval;
		}

		for (; it != s.cend(); ++it) {
			auto const& c = *it;
			if (c < '0' || c > '9') {
				return errorval;
			}
			ret *= 10;
			ret += c - '0';
		}

		if (!s.empty() && s.front() == '-') {
			ret *= static_cast<T>(-1);
		}
		return ret;
	}
}

/// Converts string to integral type T. If string is not convertible, errorval is returned.
template<typename T>
T to_integral(std::string_view const& s, T const errorval = T()) {
	return to_integral_impl<T>(s, errorval);
}

template<typename T>
T to_integral(std::wstring_view const& s, T const errorval = T()) {
	return to_integral_impl<T>(s, errorval);
}

template<typename T, typename StringType>
T to_integral(std::basic_string_view<StringType> const& s, T const errorval = T()) {
	return to_integral_impl<T>(s, errorval);
}


/// \brief Returns true iff the string only has characters in the 7-bit ASCII range
template<typename String>
bool str_is_ascii(String const& s) {
	for (auto const& c : s) {
		if (static_cast<std::make_unsigned_t<typename String::value_type>>(c) > 127) {
			return false;
		}
	}

	return true;
}

/// \private
template<typename String, typename Chars>
void trim_impl(String & s, Chars const& chars, bool fromLeft, bool fromRight) {
	size_t const first = fromLeft ? s.find_first_not_of(chars) : 0;
	if (first == String::npos) {
		s = String();
		return;
	}

	size_t const last = fromRight ? s.find_last_not_of(chars) : s.size();
	if (last == String::npos) {
		s = String();
		return;
	}

	// Invariant: If first exists, then last >= first
	s = s.substr(first, last - first + 1);
}

/// \brief Return passed string with all leading and trailing whitespace removed
inline std::string FZ_PUBLIC_SYMBOL trimmed(std::string_view s, std::string_view const& chars = " \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
	return std::string(s);
}

inline std::wstring FZ_PUBLIC_SYMBOL trimmed(std::wstring_view s, std::wstring_view const& chars = L" \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
	return std::wstring(s);
}

inline std::string FZ_PUBLIC_SYMBOL ltrimmed(std::string_view s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, true, false);
	return std::string(s);
}

inline std::wstring FZ_PUBLIC_SYMBOL ltrimmed(std::wstring_view s, std::wstring_view const& chars = L" \r\n\t")
{
	trim_impl(s, chars, true, false);
	return std::wstring(s);
}

inline std::string FZ_PUBLIC_SYMBOL rtrimmed(std::string_view s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, false, true);
	return std::string(s);
}

inline std::wstring FZ_PUBLIC_SYMBOL rtrimmed(std::wstring_view s, std::wstring_view const& chars = L" \r\n\t")
{
	trim_impl(s, chars, false, true);
	return std::wstring(s);
}


/// \brief Remove all leading and trailing whitespace from string
template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, char>, int> = 0>
inline void trim(String & s, std::string_view const& chars = " \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, wchar_t>, int> = 0>
inline void trim(String & s, std::wstring_view const& chars = L" \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, char>, int> = 0>
inline void ltrim(String& s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, true, false);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, wchar_t>, int> = 0>
inline void ltrim(String& s, std::wstring_view  const& chars = L" \r\n\t")
{
	trim_impl(s, chars, true, false);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, char>, int> = 0>
inline void rtrim(String& s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, false, true);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, wchar_t>, int> = 0>
inline void rtrim(String & s, std::wstring_view const& chars = L" \r\n\t")
{
	trim_impl(s, chars, false, true);
}

/** \brief Tests whether the first string starts with the second string
 *
 * \tparam insensitive_ascii If true, comparison is case-insensitive
 */
template<bool insensitive_ascii = false, typename String>
bool starts_with(String const& s, String const& beginning)
{
	if (beginning.size() > s.size()) {
		return false;
	}
	if constexpr (insensitive_ascii) {
		return std::equal(beginning.begin(), beginning.end(), s.begin(), [](typename String::value_type const& a, typename String::value_type const& b) {
			return tolower_ascii(a) == tolower_ascii(b);
		});
	}
	else {
		return std::equal(beginning.begin(), beginning.end(), s.begin());
	}
}

/** \brief Tests whether the first string ends with the second string
 *
 * \tparam insensitive_ascii If true, comparison is case-insensitive
 */
template<bool insensitive_ascii = false, typename String>
bool ends_with(String const& s, String const& ending)
{
	if (ending.size() > s.size()) {
		return false;
	}

	if constexpr (insensitive_ascii) {
		return std::equal(ending.rbegin(), ending.rend(), s.rbegin(), [](typename String::value_type const& a, typename String::value_type const& b) {
			return tolower_ascii(a) == tolower_ascii(b);
		});
	}
	else {
		return std::equal(ending.rbegin(), ending.rend(), s.rbegin());
	}
}

/**
 * Normalizes various hyphens, dashes and minuses to just hyphen-minus.
 *
 * The narrow version assumes UTF-8 as encoding.
 */
std::string FZ_PUBLIC_SYMBOL normalize_hyphens(std::string_view const& in);
std::wstring FZ_PUBLIC_SYMBOL normalize_hyphens(std::wstring_view const& in);

}

#endif

#ifndef LIBFILEZILLA_IMPERSONATION_HEADER
#define LIBFILEZILLA_IMPERSONATION_HEADER

/** \file
* \brief Declares \ref fz::impersonation_token
*/

#include "string.hpp"

#include <memory>
#include <functional>

namespace fz {

#if !FZ_WINDOWS
enum class impersonation_flag
{
	pwless /// Impersonate as any user without checking credentials
};
#endif

class impersonation_token_impl;

/**
 * \brief Impersonation tokens for a given user can be used to spawn processes running as that user
 *
 * Under *nix, the caller needs to be root. On Linux, CAP_SETUID/CAP_SETGID is also sufficient.
 *
 * On Windows, the caller needs to have "Replace a process level token" rights, to be found
 * through secpol.msc -> Local Policies -> User Rights Assignment
 */
class FZ_PUBLIC_SYMBOL impersonation_token final
{
public:
	impersonation_token();

	impersonation_token(impersonation_token&&) noexcept;
	impersonation_token& operator=(impersonation_token&&) noexcept;

	/// Creates an impersonation token, verifying credentials in the proceess
	explicit impersonation_token(fz::native_string const& username, fz::native_string const& password);

#if !FZ_WINDOWS
	/// Doesn't verify credentials
	explicit impersonation_token(fz::native_string const& username, impersonation_flag flag, fz::native_string const& group = {});
#endif

	~impersonation_token() noexcept;

	explicit operator bool() const {
		return impl_.operator bool();
	}

	bool operator==(impersonation_token const&) const;
	bool operator<(impersonation_token const&) const;

	/// Returns the name of the impersonated user
	fz::native_string username() const;

	/// Returns home directory, may be empty.
	fz::native_string home() const;

	/// For std::hash
	std::size_t hash() const noexcept;

private:
	friend class impersonation_token_impl;
	std::unique_ptr<impersonation_token_impl> impl_;
};

#if !FZ_WINDOWS
/// Applies to the entire current process, calls setuid/setgid
bool FZ_PUBLIC_SYMBOL set_process_impersonation(impersonation_token const& token);
#endif

}

namespace std {

/// \private
template <>
struct hash<fz::impersonation_token>
{
	std::size_t operator()(fz::impersonation_token const& op) const noexcept
	{
		return op.hash();
	}
};

}

#endif

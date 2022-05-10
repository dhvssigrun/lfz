#include "libfilezilla/impersonation.hpp"

#if FZ_UNIX || FZ_MAC

#include "libfilezilla/buffer.hpp"

#include <optional>
#include <tuple>

#if FZ_UNIX
#include <crypt.h>
#include <shadow.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if FZ_MAC
#include <CoreServices/CoreServices.h>
#endif

namespace fz {
namespace {
struct passwd_holder {
	passwd_holder() = default;
	passwd_holder(passwd_holder const&) = delete;
	passwd_holder(passwd_holder &&) = default;

	passwd_holder& operator=(passwd_holder const&) = delete;
	passwd_holder& operator=(passwd_holder &&) = default;

	~passwd_holder() noexcept = default;

	struct passwd* pwd_{};

	struct passwd pwd_buffer_;
	fz::buffer buf_{};
};

passwd_holder get_passwd(fz::native_string const& username)
{
	passwd_holder ret;

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		res = getpwnam_r(username.c_str(), &ret.pwd_buffer_, reinterpret_cast<char*>(ret.buf_.get(s)), s, &ret.pwd_);
	} while (res == ERANGE);

	if (res || !ret.pwd_) {
		ret.pwd_ = nullptr;
	}

	return ret;
}

std::optional<gid_t> get_group(fz::native_string const& gname)
{
	fz::buffer buf;

	struct group g;
	struct group *pg{};

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		buf.get(s);
		res = getgrnam_r(gname.c_str(), &g, reinterpret_cast<char*>(buf.get(s)), s, &pg);
	} while (res == ERANGE);

	if (!res && pg) {
		return pg->gr_gid;
	}

	return {};
}

#if FZ_UNIX
struct shadow_holder {
	shadow_holder() = default;
	shadow_holder(shadow_holder const&) = delete;
	shadow_holder(shadow_holder &&) = default;

	shadow_holder& operator=(shadow_holder const&) = delete;
	shadow_holder& operator=(shadow_holder &&) = default;

	~shadow_holder() noexcept = default;

	struct spwd* shadow_{};

	struct spwd shadow_buffer_;
	fz::buffer buf_{};
};

shadow_holder get_shadow(fz::native_string const& username)
{
	shadow_holder ret;

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		ret.buf_.get(s);
		res = getspnam_r(username.c_str(), &ret.shadow_buffer_, reinterpret_cast<char*>(ret.buf_.get(s)), s, &ret.shadow_);
	} while (res == ERANGE);

	if (res) {
		ret.shadow_ = nullptr;
	}

	return ret;
}
#endif
}

class impersonation_token_impl final
{
public:
	static impersonation_token_impl* get(impersonation_token const& t) {
		return t.impl_.get();
	}

	fz::native_string name_;
	fz::native_string home_;
	uid_t uid_{};
	gid_t gid_{};
	std::vector<gid_t> sup_groups_;
};


impersonation_token::impersonation_token() = default;
impersonation_token::~impersonation_token() noexcept = default;


impersonation_token::impersonation_token(impersonation_token&&) noexcept = default;
impersonation_token& impersonation_token::operator=(impersonation_token&&) noexcept = default;

namespace {
std::vector<gid_t> get_supplementary(std::string const& username, gid_t primary)
{
	std::vector<gid_t> ret;

	int size = 100;
	while (true) {
		ret.resize(size);
#if FZ_MAC
		typedef int glt;
		static_assert(sizeof(gid_t) == sizeof(glt));
#else
		typedef gid_t glt;
#endif

		int res = getgrouplist(username.c_str(), primary, reinterpret_cast<glt*>(ret.data()), &size);
		if (size < 0 || (res < 0 && static_cast<size_t>(size) <= ret.size())) {
			// Something went wrong
			ret.clear();
			break;
		}

		ret.resize(size);
		if (res >= 0) {
			break;
		}
	}
	return ret;
}

bool check_auth(fz::native_string const& username, fz::native_string const& password)
{
#if FZ_UNIX
	auto shadow = get_shadow(username);
	if (shadow.shadow_) {
		struct crypt_data data{};
		char* encrypted = crypt_r(password.c_str(), shadow.shadow_->sp_pwdp, &data);
		if (encrypted && !strcmp(encrypted, shadow.shadow_->sp_pwdp)) {
			return true;
		}
	}
#elif FZ_MAC
	bool ret{};

	CFStringRef cfu = CFStringCreateWithCString(NULL, username.c_str(), kCFStringEncodingUTF8);
	if (cfu) {
		CSIdentityQueryRef q = CSIdentityQueryCreateForName(kCFAllocatorDefault, cfu, kCSIdentityQueryStringEquals, kCSIdentityClassUser, CSGetDefaultIdentityAuthority());
		if (q) {
			if (CSIdentityQueryExecute(q, kCSIdentityQueryGenerateUpdateEvents, NULL)) {
				CFArrayRef users = CSIdentityQueryCopyResults(q);
				if (users) {
					if (CFArrayGetCount(users) == 1) {
						CSIdentityRef user = (CSIdentityRef)(CFArrayGetValueAtIndex(users, 0));
						if (user) {
							CFStringRef pw = CFStringCreateWithCString(NULL, password.c_str(), kCFStringEncodingUTF8);
							if (pw) {
								ret = CSIdentityAuthenticateUsingPassword(user, pw);
								CFRelease(pw);
							}
						}
					}
					CFRelease(users);
				}
			}
			CFRelease(q);
		}
		CFRelease(cfu);
	}

	return ret;
#endif
	return false;
}
}

impersonation_token::impersonation_token(fz::native_string const& username, fz::native_string const& password)
{
	auto pwd = get_passwd(username);
	if (pwd.pwd_) {
		if (check_auth(username, password)) {
			impl_ = std::make_unique<impersonation_token_impl>();
			impl_->name_ = username;
			if (pwd.pwd_->pw_dir) {
				impl_->home_ = pwd.pwd_->pw_dir;
			}
			impl_->uid_ = pwd.pwd_->pw_uid;
			impl_->gid_ = pwd.pwd_->pw_gid;
			impl_->sup_groups_ = get_supplementary(username, pwd.pwd_->pw_gid);
		}
	}
}

impersonation_token::impersonation_token(fz::native_string const& username, impersonation_flag flag, fz::native_string const& group)
{
	if (flag == impersonation_flag::pwless) {
		auto pwd = get_passwd(username);
		if (pwd.pwd_) {
			impl_ = std::make_unique<impersonation_token_impl>();
			impl_->name_ = username;
			if (pwd.pwd_->pw_dir) {
				impl_->home_ = pwd.pwd_->pw_dir;
			}
			impl_->uid_ = pwd.pwd_->pw_uid;
			if (group.empty()) {
				impl_->gid_ = pwd.pwd_->pw_gid;
			}
			else {
				auto gid = get_group(group);
				if (!gid) {
					impl_.reset();
					return;
				}
				impl_->gid_ = *gid;
			}
			impl_->sup_groups_ = get_supplementary(username, pwd.pwd_->pw_gid);
		}
	}
}

fz::native_string impersonation_token::username() const
{
	return impl_ ? impl_->name_ : fz::native_string();
}

std::size_t impersonation_token::hash() const noexcept
{
	return impl_ ? std::hash<fz::native_string>{}(impl_->name_) : std::hash<fz::native_string>{}(fz::native_string());
}

// Note: Setuid binaries
bool set_process_impersonation(impersonation_token const& token)
{
	auto impl = impersonation_token_impl::get(token);
	if (!impl) {
		return false;
	}

	if (setgroups(impl->sup_groups_.size(), impl->sup_groups_.data()) != 0) {
		return false;
	}

	if (setgid(impl->gid_) != 0) {
		return false;
	}
	if (setuid(impl->uid_) != 0) {
		return false;
	}

	return true;
}

bool impersonation_token::operator==(impersonation_token const& op) const
{
	if (!impl_) {
		return !op.impl_;
	}
	if (!op.impl_) {
		return false;
	}

	return std::tie(impl_->name_, impl_->uid_, impl_->gid_, impl_->home_, impl_->sup_groups_) == std::tie(op.impl_->name_, op.impl_->uid_, op.impl_->gid_, op.impl_->home_, impl_->sup_groups_);
}

bool impersonation_token::operator<(impersonation_token const& op) const
{
	if (!impl_) {
		return bool(op.impl_);
	}
	if (!op.impl_) {
		return false;
	}

	return std::tie(impl_->name_, impl_->uid_, impl_->gid_, impl_->home_, impl_->sup_groups_) < std::tie(op.impl_->name_, op.impl_->uid_, op.impl_->gid_, op.impl_->home_, impl_->sup_groups_);
}

fz::native_string impersonation_token::home() const
{
	return impl_ ? impl_->home_ : fz::native_string();
}

}


#elif FZ_WINDOWS

#include "windows/dll.hpp"

#include "libfilezilla/glue/windows.hpp"
#include "windows/security_descriptor_builder.hpp"

#include <shlobj.h>

#include <tuple>

namespace fz {
class impersonation_token_impl final
{
public:
	impersonation_token_impl() = default;

	static impersonation_token_impl* get(impersonation_token const& t) {
		return t.impl_.get();
	}

	~impersonation_token_impl() {
		if (h_ != INVALID_HANDLE_VALUE) {
			CloseHandle(h_);
		}
	}

	static HANDLE get_handle(impersonation_token const& t) {
		return t.impl_ ? t.impl_->h_ : INVALID_HANDLE_VALUE;
	}

	impersonation_token_impl(impersonation_token_impl const&) = delete;
	impersonation_token_impl& operator=(impersonation_token_impl const&) = delete;

	fz::native_string name_;
	std::string sid_; // SID as string
	HANDLE h_{INVALID_HANDLE_VALUE};
};

impersonation_token::impersonation_token() = default;
impersonation_token::~impersonation_token() noexcept = default;

impersonation_token::impersonation_token(impersonation_token&&) noexcept = default;
impersonation_token& impersonation_token::operator=(impersonation_token&&) noexcept = default;


impersonation_token::impersonation_token(fz::native_string const& username, fz::native_string const& password)
{
	if (username.find_first_of(L"\"/\\[]:;|=,+*?<>") != fz::native_string::npos) {
		return;
	}

	HANDLE token{INVALID_HANDLE_VALUE};
	DWORD res = LogonUserW(username.c_str(), nullptr, password.c_str(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token);
	if (!res) {
		return;
	}

	HANDLE primary{INVALID_HANDLE_VALUE};
	res = DuplicateTokenEx(token, 0, nullptr, SecurityImpersonation, TokenPrimary, &primary);
	if (res != 0) {
		std::string sid = GetSidFromToken(primary);
		if (!sid.empty()) {
			impl_ = std::make_unique<impersonation_token_impl>();
			impl_->name_ = username;
			impl_->sid_ = std::move(sid);
			impl_->h_ = primary;
		}
		else {
			CloseHandle(primary);
		}
	}
	CloseHandle(token);
}

fz::native_string impersonation_token::username() const
{
	return impl_ ? impl_->name_ : fz::native_string();
}

std::size_t impersonation_token::hash() const noexcept
{
	return impl_ ? std::hash<fz::native_string>{}(impl_->name_) : std::hash<fz::native_string>{}(fz::native_string());
}

bool impersonation_token::operator==(impersonation_token const& op) const
{
	if (!impl_) {
		return !op.impl_;
	}
	if (!op.impl_) {
		return false;
	}

	return std::tie(impl_->name_, impl_->sid_) == std::tie(op.impl_->name_, op.impl_->sid_);
}

bool impersonation_token::operator<(impersonation_token const& op) const
{
	if (!impl_) {
		return bool(op.impl_);
	}
	if (!op.impl_) {
		return false;
	}

	return std::tie(impl_->name_, impl_->sid_) < std::tie(op.impl_->name_, op.impl_->sid_);
}

namespace {
extern "C" {
typedef HRESULT (*getknownfolderpath_t)(REFKNOWNFOLDERID, DWORD, HANDLE, wchar_t**);
typedef HRESULT (*getknownfolderpath_t)(REFKNOWNFOLDERID, DWORD, HANDLE, wchar_t**);
typedef void (*cotaskmemfree_t)(void*);
}
}

fz::native_string impersonation_token::home() const
{
	fz::native_string ret;

	if (impl_) {
		wchar_t* out{};
		// Manually define it instead of using FOLDERID_Profile as it would prevent building a DLL.
		static GUID const profile = { 0x5E6C858F, 0x0E22, 0x4760, {0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73} };

		static auto& dlls = shdlls::get();
		static getknownfolderpath_t const getknownfolderpath = dlls.shell32_ ? reinterpret_cast<getknownfolderpath_t>(GetProcAddress(dlls.shell32_.h_, "SHGetKnownFolderPath")) : nullptr;
		static cotaskmemfree_t const cotaskmemfree = dlls.ole32_ ? reinterpret_cast<cotaskmemfree_t>(GetProcAddress(dlls.ole32_.h_, "CoTaskMemFree")) : nullptr;

		if (getknownfolderpath && cotaskmemfree && getknownfolderpath(profile, 0, impl_->h_, &out) == S_OK) {
			ret = out;
			cotaskmemfree(out);
		}
	}
	return ret;
}

HANDLE get_handle(impersonation_token const& t) {
	return impersonation_token_impl::get_handle(t);
}

}

#elif 0
namespace fz {
struct impersonation_token_impl{};

impersonation_token::impersonation_token() {}
impersonation_token::impersonation_token(impersonation_token&&) noexcept {}
impersonation_token& impersonation_token::operator=(impersonation_token&&) noexcept { return *this; }

impersonation_token::impersonation_token(fz::native_string const&, fz::native_string const&) {}
impersonation_token::~impersonation_token() noexcept {}

bool impersonation_token::operator==(impersonation_token const&) const { return true; }
bool impersonation_token::operator<(impersonation_token const&) const { return false; }

fz::native_string impersonation_token::username() const { return {}; }
fz::native_string impersonation_token::home() const { return {}; }
std::size_t impersonation_token::hash() const noexcept { return {}; }

#if FZ_UNIX
impersonation_token::impersonation_token(fz::native_string const&, impersonation_flag) {}
bool set_process_impersonation(impersonation_token const&)
{
	return false;
}
#endif

}
#endif

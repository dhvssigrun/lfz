#ifndef LIBFILEZILLA_WINDOWS_SECURITY_DESCRIPTOR_BUILDER_HEADER
#define LIBFILEZILLA_WINDOWS_SECURITY_DESCRIPTOR_BUILDER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"
#include <memory>

namespace fz {
class security_descriptor_builder final
{
public:
	enum entity {
		self,
		administrators
	};

	security_descriptor_builder();
	~security_descriptor_builder();

	security_descriptor_builder(security_descriptor_builder const&) = delete;
	security_descriptor_builder& operator=(security_descriptor_builder const&) = delete;

	void add(entity e, DWORD rights = GENERIC_ALL | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL);

	ACL* get_acl();
	SECURITY_DESCRIPTOR* get_sd();

private:
	struct impl;
	std::unique_ptr<impl> impl_;
};

std::string GetSidFromToken(HANDLE h);
}

#endif
#endif

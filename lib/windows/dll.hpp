#ifndef LIBFILEZILLA_WINDOWS_DLL_HEADER
#define LIBFILEZILLA_WINDOWS_DLL_HEADER

#include "../libfilezilla/glue/windows.hpp"

namespace fz {
class dll final
{
public:
	explicit dll(wchar_t const* name, DWORD flags)
	{
		h_ = LoadLibraryExW(name, NULL, flags);
	}

	~dll() {
		if (h_) {
			FreeLibrary(h_);
		}
	}

	dll(dll const&) = delete;
	dll& operator=(dll const&) = delete;

	explicit operator bool() const {
		return h_ != nullptr;
	}

	HMODULE h_{};
};

class shdlls final
{
protected:
	shdlls();
	~shdlls();

	shdlls(shdlls const&) = delete;
	shdlls* operator=(shdlls const&) = delete;

public:
	static shdlls& get();

	dll shell32_;
	dll ole32_;
};
}

#endif


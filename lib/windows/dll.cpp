#include "dll.hpp"

#include <objbase.h>

namespace fz {
namespace {
extern "C" {
typedef HRESULT (*coinitex_t)(LPVOID, DWORD);
typedef HRESULT (*couninit_t)();
}
}

shdlls::shdlls()
	: shell32_(L"shell32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)
	, ole32_(L"ole32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)
{
	coinitex_t const coinitex = ole32_ ? reinterpret_cast<coinitex_t>(GetProcAddress(ole32_.h_, "CoInitializeEx")) : nullptr;
	if (coinitex) {
		coinitex(NULL, COINIT_MULTITHREADED);
	}
}

shdlls::~shdlls()
{
	coinitex_t const couninit = ole32_ ? reinterpret_cast<coinitex_t>(GetProcAddress(ole32_.h_, "CoUninitialize")) : nullptr;
	if (couninit) {
		couninit(NULL, COINIT_MULTITHREADED);
	}
}

shdlls& shdlls::get()
{
	static shdlls d;
	return d;
}
}

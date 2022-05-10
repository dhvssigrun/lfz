#ifndef LIBFILEZILLA_PRIVATE_VISIBILITY_HEADER
#define LIBFILEZILLA_PRIVATE_VISIBILITY_HEADER

#include "../visibility_helper.hpp"

// Symbol visibility. There are two main cases: Building libfilezilla and using it
#ifdef BUILDING_LIBFILEZILLA
  #define FZ_PUBLIC_SYMBOL FZ_EXPORT_PUBLIC
  #define FZ_PRIVATE_SYMBOL FZ_EXPORT_PRIVATE
#else
  #define FZ_PRIVATE_SYMBOL
  #if FZ_USING_DLL
    #define FZ_PUBLIC_SYMBOL FZ_IMPORT_SHARED
  #else
    #define FZ_PUBLIC_SYMBOL FZ_IMPORT_STATIC
  #endif
#endif

#endif

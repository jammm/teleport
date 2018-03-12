// +build pam,cgo

#include "_cgo_export.h"

// library_name returns the name of the library to load at runtime.
char *library_name()
{
    return "libpam.dylib";
}


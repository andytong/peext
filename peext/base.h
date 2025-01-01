#pragma once
#include <string>

BOOL multi_to_unicode(LPCSTR multi_str, std::wstring& s);
LONGLONG StrToAddress(LPCSTR str, DWORD flag);
LONGLONG StrToAddress(LPCSTR str);
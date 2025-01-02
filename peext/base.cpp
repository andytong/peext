#include "pch.h"
#include "base.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

BOOL multi_to_unicode(LPCSTR multi_str, std::wstring &s)
{
	BOOL bRet = FALSE;
	int size;
	wchar_t* unicode_str;

	size = MultiByteToWideChar(CP_ACP, 0, multi_str, -1, NULL, 0);
	unicode_str = new wchar_t[size];
	if (nullptr == unicode_str) {
		return bRet;
	}
	size = MultiByteToWideChar(CP_ACP, 0, multi_str, -1, unicode_str, size);
	if (size == 0) {
		delete[] unicode_str;
		return bRet;
	}

	s = unicode_str;
	delete[] unicode_str;
	return TRUE;
}

LONGLONG StrToAddress(LPCSTR str)
{
	return 0;
}
LONGLONG StrToAddress(LPCSTR str, DWORD flag)//STIF_SUPPORT_HEX
{
	DWORD_PTR dwAddress = 0;
	int len = static_cast<int>(strlen(str));
	LPSTR temp = new char[len + 3];
	if (NULL == temp)
		return 0;
	int copy_offset = 2;
	LPCSTR trim_char = strchr(str, '`');

	if (len < 3 || (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))) {
		copy_offset = 0;
	}
	else {
		temp[0] = '0';
		temp[1] = 'x';
	}

	if (trim_char) {
		StrCpyNA(temp + copy_offset, str, static_cast<int>(trim_char - str)+1);
		StrCatA(temp + copy_offset, trim_char + 1);
	}
	else {
		StrCpyA(temp + copy_offset, str);
	}

	//#ifdef _WIN64
	StrToInt64ExA(temp, flag, (LONGLONG*)&dwAddress);
	//#else
	//	StrToIntExA(temp, flag, (int*)&ulAddress);
	//#endif
	delete[]temp;

	return dwAddress;
}
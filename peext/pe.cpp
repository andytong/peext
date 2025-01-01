// PE.cpp : 定义 DLL 应用程序的导出函数。
//

#include "pch.h"
#include <locale.h>
#include <shellapi.h>
#include "CmdLine.h"
#include "base.h"

#define PE_OUTPUT_STRUCT(a,b)      dprintf("\t+0x%02x  %-15s  0x%x\n" , ulOffset,#b, a.b);ulOffset += sizeof(a.b);
#define PE_OUTPUT_STRUCT_2(a,b,c)  {dprintf("\t\t+0x%02x  %-30s  0x%08x  "##c"\n" , ulTemp,#b, a.b );ulTemp += sizeof(a.b);}
#define PE_OUTPUT_SECTION(a,b,c)   dprintf("\t+0x%02x  %-20s  0x%08x  "##c"\n" , ulTemp,#b, a->b );ulTemp += sizeof(a->b);

#define IMAGE_FIRST_SECTION64( ntheader ) ((PIMAGE_SECTION_HEADER)      \
  ((ULONG_PTR)ntheader +                                              \
  FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                \
  ((PIMAGE_NT_HEADERS64)(ntheader))->FileHeader.SizeOfOptionalHeader  \
  ))

#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)ntheader +                                              \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS32)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

HRESULT PE_PrintDosHeader(ULONG_PTR ulBaseAddress, BOOL bPrintDosHeard, PULONG pulNtHeaderOffset)
{
	HRESULT                      result = S_OK;
	IMAGE_DOS_HEADER             imageDosHeard = { 0 };
	ULONG                        ulReadSize = 0;
	ULONG                        ulOffset = 0;
	result = g_ExtDataSpaces->ReadVirtual(ulBaseAddress, &imageDosHeard, sizeof(IMAGE_DOS_HEADER), &ulReadSize);
	if (result != S_OK)
	{
		dprintf("***Read address %x is error.***", ulBaseAddress);
		return result;
	}
	if (ulReadSize != sizeof(IMAGE_DOS_HEADER))
	{
		dprintf("***Read DOS_HEADER buffer error.***\n");
		return S_FALSE;
	}
	if (imageDosHeard.e_magic != IMAGE_DOS_SIGNATURE)
	{
		dprintf("***Address is not PE file Image***");
		return S_FALSE;
	}
	if (bPrintDosHeard)
	{
		dprintf("Dos header: _IMAGE_DOS_HEADER\n  address: %x\n ", ulBaseAddress);
		PE_OUTPUT_STRUCT(imageDosHeard, e_magic);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cblp);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cp);
		PE_OUTPUT_STRUCT(imageDosHeard, e_crlc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cparhdr);
		PE_OUTPUT_STRUCT(imageDosHeard, e_minalloc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_maxalloc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_ss);
		PE_OUTPUT_STRUCT(imageDosHeard, e_sp);
		PE_OUTPUT_STRUCT(imageDosHeard, e_csum);
		PE_OUTPUT_STRUCT(imageDosHeard, e_ip);
		PE_OUTPUT_STRUCT(imageDosHeard, e_cs);
		PE_OUTPUT_STRUCT(imageDosHeard, e_lfarlc);
		PE_OUTPUT_STRUCT(imageDosHeard, e_ovno);
		PE_OUTPUT_STRUCT(imageDosHeard, e_res);
		PE_OUTPUT_STRUCT(imageDosHeard, e_oemid);
		PE_OUTPUT_STRUCT(imageDosHeard, e_oeminfo);
		PE_OUTPUT_STRUCT(imageDosHeard, e_res2);
		PE_OUTPUT_STRUCT(imageDosHeard, e_lfanew);
	}

	if(pulNtHeaderOffset)*pulNtHeaderOffset = imageDosHeard.e_lfanew;
	return result;
}
int Is64Image(ULONG_PTR ulAddress)
{
	WORD  wMagic = 0;
	ULONG ulReadSize = 0;
	DWORD dwMagicOffset = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	HRESULT result = g_ExtDataSpaces->ReadVirtual(ulAddress + dwMagicOffset, &wMagic, sizeof(WORD), &ulReadSize);
	if (result != S_OK)
	{
		dprintf("***Read memory address %x error.***\n", ulAddress + dwMagicOffset);
		return -1;
	}
	if (ulReadSize != sizeof(WORD))
	{
		dprintf("***Read OPTIONAL_HEADER magic error.***\n");
		return -1;
	}

	if (wMagic == 0x20b)
		return TRUE;
	else
		return FALSE;
}
HRESULT PE_PrintNtHeader64(DWORD_PTR dwBaseAddress, BOOL bPrintNtHeard, 
	PDWORD pdwSetionCount, IMAGE_DATA_DIRECTORY  DataDirectory[], 
	PDWORD_PTR pdwLoadBase, PDWORD_PTR pdwImageSize, PDWORD pdwSectionOffset)
{
	HRESULT                      result = S_OK;
	IMAGE_NT_HEADERS64             imageNtHreard = { 0 };
	ULONG                        ulReadSize = 0;
	ULONG                        ulOffset = 0;
	ULONG                        ulTemp = 0;
	char* pNote = NULL;
	result = g_ExtDataSpaces->ReadVirtual(dwBaseAddress, &imageNtHreard, sizeof(IMAGE_NT_HEADERS64), &ulReadSize);
	if (result != S_OK)
	{
		dprintf("***Read memory address %x error.***\n", dwBaseAddress);
		return result;
	}
	if (ulReadSize != sizeof(IMAGE_NT_HEADERS64))
	{
		dprintf("***Read IMAGE_NT_HEADERS size error.***\n");
		return S_FALSE;
	}
	if (imageNtHreard.Signature != IMAGE_NT_SIGNATURE)
	{
		dprintf("Address is not image\n");
		return S_FALSE;
	}
	if (bPrintNtHeard)
	{
		dprintf("NT header: _IMAGE_NT_HEADERS\n  address:%x\n ", dwBaseAddress);
		PE_OUTPUT_STRUCT(imageNtHreard, Signature);
		PE_OUTPUT_STRUCT(imageNtHreard, FileHeader);
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Machine, "Machine type");//运行平台
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSections, "section numbers");//文件的区块数目
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, TimeDateStamp, "File creation date and time");//文件创建日期和时间
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, PointerToSymbolTable, "Pointer to symbol table of COFF");//指向COFF符号表(主要用于调试)
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSymbols, "Symbol count of COFF");//COFF符号表中符号个数(同上)
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, SizeOfOptionalHeader, "size of IMAGE_OPTIONAL_HEADER");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Characteristics, "File attribute");
		PE_OUTPUT_STRUCT(imageNtHreard, OptionalHeader);
		ulTemp = 0;

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Magic, "Flag, ROM Image(0107h),Normal executable file(32:10Bh 64:20Bh)");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorLinkerVersion, "The major version number of the linker used to build the executable.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorLinkerVersion, "The minor version number of the linker used to build the executable.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfCode, "The size (in bytes) of the code section (.text) of the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfInitializedData, "The size (in bytes) of the initialized data section (.data) of the program");//所有含已初始化数据的节的总大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfUninitializedData, "The size (in bytes) of the uninitialized data section, typically referred to as .bss");//所有含未初始化数据的节的大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, AddressOfEntryPoint, " The address(RVA) of the entry point of the program");//程序执行入口RVA
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfCode, "The base address(RVA) of the code section.");//代码的区块的起始RVA
		#ifdef _X86_
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfData, "The base address of the data section.");//数据的区块的起始RVA
		#endif // DEBUG
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, ImageBase, "The preferred base address at which the executable should be loaded into memory");//程序的首选装载地址
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SectionAlignment, "The alignment (in bytes) of sections in memory.");//内存中的区块的对齐大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, FileAlignment, "The alignment (in bytes) of sections on disk.");//文件中的区块的对齐大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorOperatingSystemVersion, "The major version of the OS required to run the program.");//要求操作系统最低版本号的主版本号
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorOperatingSystemVersion, "The minor version of the OS required to run the program.");//要求操作系统最低版本号的副版本号
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorImageVersion, "The major version number of the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorImageVersion, "The minor version number of the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorSubsystemVersion, "The major version of the subsystem required by the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorSubsystemVersion, "The minor version of the subsystem required by the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Win32VersionValue, "Reserved, typically set to 0.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfImage, "The size(in bytes) of the entire image, including all sections and headers.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeaders, "The size (in bytes) of the PE header, including DOS header, PE header, file header, and optional header.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, CheckSum, "The checksum of the image, typically computed by the OS loader during the loading process.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Subsystem, " =The type of subsystem required by the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DllCharacteristics, "A set of flags that specify characteristics of the executable, typically indicating whether it's a DLL");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackReserve, "The size (in bytes) of the stack reserve for the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackCommit, "The size (in bytes) of the initial stack commit.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapReserve, "The size (in bytes) of the heap reserve for the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapCommit, "The size (in bytes) of the initial heap commit.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, LoaderFlags, "Reserved field, typically set to 0.");//For debuging
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, NumberOfRvaAndSizes, "The number of entries in the data directories, usually set to 16.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DataDirectory, "Data Directory");

		int i = 0;
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_EXPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_RESOURCE", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_EXCEPTION", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_SECURITY", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_BASERELOC", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_DEBUG", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_GLOBALPTR", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_TLS", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_IAT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n ", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n ", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
	}
	memcpy(DataDirectory, imageNtHreard.OptionalHeader.DataDirectory, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	*pdwSetionCount = imageNtHreard.FileHeader.NumberOfSections;
	//*pulBaseAddress += sizeof(IMAGE_NT_HEADERS);
	if(pdwImageSize)
		*pdwImageSize = imageNtHreard.OptionalHeader.SizeOfImage;
	if (pdwLoadBase)
		*pdwLoadBase = imageNtHreard.OptionalHeader.ImageBase;

	if (pdwSectionOffset)
		*pdwSectionOffset = FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + imageNtHreard.FileHeader.SizeOfOptionalHeader;
	return result;
}
HRESULT PE_PrintNtHeader32(DWORD_PTR dwBaseAddress, BOOL bPrintNtHeard,
	PDWORD pdwSetionCount, IMAGE_DATA_DIRECTORY  DataDirectory[],
	PDWORD_PTR pdwLoadBase, PDWORD_PTR pdwImageSize, PDWORD pdwSectionOffset)
{
	HRESULT                      result = S_OK;
	IMAGE_NT_HEADERS32           imageNtHreard = { 0 };
	DWORD                        dwReadSize = 0;
	DWORD                        ulOffset = 0;
	DWORD                        ulTemp = 0;
	char* pNote = NULL;
	result = g_ExtDataSpaces->ReadVirtual(dwBaseAddress, &imageNtHreard, sizeof(IMAGE_NT_HEADERS32), &dwReadSize);
	if (result != S_OK)
	{
		dprintf("***Read memory address %x error.***\n", dwBaseAddress);
		return result;
	}
	if (dwReadSize != sizeof(IMAGE_NT_HEADERS32))
	{
		dprintf("***Read IMAGE_NT_HEADERS size error.***\n");
		return S_FALSE;
	}
	if (imageNtHreard.Signature != IMAGE_NT_SIGNATURE)
	{
		dprintf("Address is not image\n");
		return S_FALSE;
	}
	if (bPrintNtHeard)
	{
		dprintf("NT header: _IMAGE_NT_HEADERS\n  address:%x\n ", dwBaseAddress);
		PE_OUTPUT_STRUCT(imageNtHreard, Signature);
		PE_OUTPUT_STRUCT(imageNtHreard, FileHeader);
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Machine, "Machine type");//运行平台
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSections, "section numbers");//文件的区块数目
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, TimeDateStamp, "File creation date and time");//文件创建日期和时间
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, PointerToSymbolTable, "Pointer to symbol table of COFF");//指向COFF符号表(主要用于调试)
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, NumberOfSymbols, "Symbol count of COFF");//COFF符号表中符号个数(同上)
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, SizeOfOptionalHeader, "size of IMAGE_OPTIONAL_HEADER");
		PE_OUTPUT_STRUCT_2(imageNtHreard.FileHeader, Characteristics, "File attribute");
		PE_OUTPUT_STRUCT(imageNtHreard, OptionalHeader);
		ulTemp = 0;

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Magic, "Flag, ROM Image(0107h),Normal executable file(32:10Bh 64:20Bh)");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorLinkerVersion, "The major version number of the linker used to build the executable.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorLinkerVersion, "The minor version number of the linker used to build the executable.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfCode, "The size (in bytes) of the code section (.text) of the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfInitializedData, "The size (in bytes) of the initialized data section (.data) of the program");//所有含已初始化数据的节的总大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfUninitializedData, "The size (in bytes) of the uninitialized data section, typically referred to as .bss");//所有含未初始化数据的节的大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, AddressOfEntryPoint, " The address(RVA) of the entry point of the program");//程序执行入口RVA
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfCode, "The base address(RVA) of the code section.");//代码的区块的起始RVA#ifdef _X86_
		#ifdef _X86_
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, BaseOfData, "The base address of the data section.");//数据的区块的起始RVA
		#endif

		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, ImageBase, "The preferred base address at which the executable should be loaded into memory");//程序的首选装载地址
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SectionAlignment, "The alignment (in bytes) of sections in memory.");//内存中的区块的对齐大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, FileAlignment, "The alignment (in bytes) of sections on disk.");//文件中的区块的对齐大小
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorOperatingSystemVersion, "The major version of the OS required to run the program.");//要求操作系统最低版本号的主版本号
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorOperatingSystemVersion, "The minor version of the OS required to run the program.");//要求操作系统最低版本号的副版本号
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorImageVersion, "The major version number of the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorImageVersion, "The minor version number of the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MajorSubsystemVersion, "The major version of the subsystem required by the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, MinorSubsystemVersion, "The minor version of the subsystem required by the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Win32VersionValue, "Reserved, typically set to 0.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfImage, "The size(in bytes) of the entire image, including all sections and headers.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeaders, "The size (in bytes) of the PE header, including DOS header, PE header, file header, and optional header.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, CheckSum, "The checksum of the image, typically computed by the OS loader during the loading process.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, Subsystem, " =The type of subsystem required by the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DllCharacteristics, "A set of flags that specify characteristics of the executable, typically indicating whether it's a DLL");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackReserve, "The size (in bytes) of the stack reserve for the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfStackCommit, "The size (in bytes) of the initial stack commit.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapReserve, "The size (in bytes) of the heap reserve for the program.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, SizeOfHeapCommit, "The size (in bytes) of the initial heap commit.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, LoaderFlags, "Reserved field, typically set to 0.");//For debuging
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, NumberOfRvaAndSizes, "The number of entries in the data directories, usually set to 16.");
		PE_OUTPUT_STRUCT_2(imageNtHreard.OptionalHeader, DataDirectory, "Data Directory");

		int i = 0;
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_EXPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_RESOURCE", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_EXCEPTION", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_SECURITY", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_BASERELOC", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_DEBUG", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_GLOBALPTR", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_TLS", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n", "IMAGE_DIRECTORY_ENTRY_IAT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n ", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
		dprintf("\t%-45s %02d    0x%08x \n ", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", i++, imageNtHreard.OptionalHeader.DataDirectory[i]);
	}
	memcpy(DataDirectory, imageNtHreard.OptionalHeader.DataDirectory, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	if(pdwSetionCount)
		*pdwSetionCount = imageNtHreard.FileHeader.NumberOfSections;
	if (pdwImageSize)
		*pdwImageSize = imageNtHreard.OptionalHeader.SizeOfImage;
	if (pdwLoadBase)
		*pdwLoadBase = imageNtHreard.OptionalHeader.ImageBase;
	if (pdwSectionOffset)
		*pdwSectionOffset = FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + imageNtHreard.FileHeader.SizeOfOptionalHeader;

	return result;
}

HRESULT PE_PrintNtHeader(DWORD_PTR dwBaseAddress, BOOL bPrintNtHeard,PDWORD pdwSetionCount, 
	IMAGE_DATA_DIRECTORY  DataDirectory[], PDWORD_PTR pdwLoadBase, PDWORD_PTR pdwImageSize
	, PDWORD pdwNtHeaderSize, PDWORD pdwSectionOffset)
{
	if (Is64Image(dwBaseAddress)) {
		if (pdwNtHeaderSize) *pdwNtHeaderSize = sizeof(IMAGE_NT_HEADERS64);
		return PE_PrintNtHeader64(dwBaseAddress, bPrintNtHeard, pdwSetionCount, DataDirectory, pdwLoadBase, pdwImageSize, pdwSectionOffset);
	}
	else {
		if (pdwNtHeaderSize) *pdwNtHeaderSize = sizeof(IMAGE_NT_HEADERS32);
		return PE_PrintNtHeader32(dwBaseAddress, bPrintNtHeard, pdwSetionCount, DataDirectory, pdwLoadBase, pdwImageSize, pdwSectionOffset);
	}
}
HRESULT PE_PrintSection(ULONG_PTR ulBaseAddress, ULONG ulSetionCount, BOOL bSection)
{
	HRESULT                      result = S_OK;
	PIMAGE_SECTION_HEADER        pSetion = NULL;
	ULONG                        ulReadSize = 0;
	ULONG                        ulTemp = 0;
	ULONG                        ulBufLen = 0;
	ULONG_PTR ulSectionAddress = ulBaseAddress;
	ulBufLen = sizeof(IMAGE_SECTION_HEADER) * ulSetionCount;
	pSetion = (PIMAGE_SECTION_HEADER)malloc(ulBufLen);
	if (pSetion == NULL){
		dprintf("***Alloc memory error***\n");
		return S_FALSE;
	}
	result = g_ExtDataSpaces->ReadVirtual(ulSectionAddress, pSetion, ulBufLen, &ulReadSize);
	if (result != S_OK){
		dprintf("***Read memory %x error***\n", ulSectionAddress);
		return result;
	}
	if (ulReadSize != ulBufLen){
		dprintf("***Read section error***\n");
		return S_FALSE;
	}

	if (bSection)
	{
		for (UINT i = 0; i < ulSetionCount; i++)
		{
#ifdef _X86_
			dprintf("Section%d  _IMAGE_SECTION_HEADER  addres:0x%08x \n", i + 1, ulBaseAddress);
#else
			dprintf("Section%d  _IMAGE_SECTION_HEADER  address: 0x%016x \n", i + 1, ulSectionAddress);
#endif

			dprintf("\t+0x%02x  %-20s  %s  section name\n", ulTemp, "Name", pSetion->Name); ulTemp += sizeof(pSetion->Name);
			PE_OUTPUT_SECTION(pSetion, Misc.VirtualSize, "");//真实长度，这两个值是一个联合结构，可以使用其中的任何一个，一般是取后一个
			PE_OUTPUT_SECTION(pSetion, SizeOfRawData, "");//在文件中对齐后的尺寸
			PE_OUTPUT_SECTION(pSetion, PointerToRawData, "");//在文件中的偏移量
			PE_OUTPUT_SECTION(pSetion, PointerToRelocations, "");//在OBJ文件中使用，重定位的偏移
			PE_OUTPUT_SECTION(pSetion, PointerToLinenumbers, "");//行号表的偏移（供调试使用地）
			PE_OUTPUT_SECTION(pSetion, NumberOfRelocations, "");//在OBJ文件中使用，重定位项数目
			PE_OUTPUT_SECTION(pSetion, NumberOfLinenumbers, "");//行号表中行号的数目
			PE_OUTPUT_SECTION(pSetion, Characteristics, "");//节属性如可读，可写，可执行等
			ulSectionAddress += sizeof(IMAGE_SECTION_HEADER);
			ulTemp = 0;
			pSetion++;
		}
	}
	return result;
}

HRESULT PE_PrintImport(PBYTE pBase, IMAGE_DATA_DIRECTORY DataImport, BOOL bImport)
{
	HRESULT                    result = S_OK;
	PIMAGE_IMPORT_DESCRIPTOR   pImportBlack = NULL;
	PIMAGE_THUNK_DATA   	 	   pFirstThunkData = NULL;
	PIMAGE_THUNK_DATA   	   	 pOriginalThunkData = NULL;
	PIMAGE_IMPORT_BY_NAME 		 pImageImportByName = NULL;
	pImportBlack = PIMAGE_IMPORT_DESCRIPTOR(pBase + DataImport.VirtualAddress);

	if (!pImportBlack || !DataImport.Size)
	{
		dprintf("***Empty import table***\n");
		return S_OK;
	}
	char* pDllName = NULL;
	if (bImport)
	{
		while (pImportBlack->Name != 0 /*&& pImportBlack->Characteristics != 0*/)
		{
			pFirstThunkData = (PIMAGE_THUNK_DATA)((ULONG_PTR)pBase + (ULONG)(pImportBlack->FirstThunk));
			if (pImportBlack->OriginalFirstThunk)
				pOriginalThunkData = (PIMAGE_THUNK_DATA)((ULONG_PTR)pBase + (ULONG)(pImportBlack->OriginalFirstThunk));
			else
				pOriginalThunkData = pFirstThunkData;
			pDllName = (PCHAR)((ULONG_PTR)pBase + (ULONG_PTR)pImportBlack->Name);
			dprintf("DLL  name  is  %s\n", pDllName);
			dprintf("Index    Offset    Address      Name \n");
			while (pFirstThunkData->u1.Ordinal != 0)
			{
				if (IMAGE_SNAP_BY_ORDINAL64(pOriginalThunkData->u1.Ordinal))
				{
					dprintf("%04d    0x%p    0x%p    None\n", IMAGE_ORDINAL64(pOriginalThunkData->u1.Ordinal), (ULONG_PTR)pOriginalThunkData->u1.Function, pFirstThunkData->u1.Function);
				}
				else
				{
					pImageImportByName = (PIMAGE_IMPORT_BY_NAME)((UCHAR*)pBase + pOriginalThunkData->u1.AddressOfData);
					dprintf("%04d    0x%p    0x%p(0x%p)    %s\n", pImageImportByName->Hint, (ULONG_PTR)pOriginalThunkData->u1.Function, pFirstThunkData->u1.Function, (LPBYTE)&(pFirstThunkData->u1.Function)- pBase, pImageImportByName->Name);
				}
				pOriginalThunkData++;
				pFirstThunkData++;
			}
			pImportBlack++;
		}
	}
	return result;
}


HRESULT PE_PrintExport(PBYTE pBase, IMAGE_DATA_DIRECTORY DataExport, ULONG_PTR ulBase, BOOL bExport)
{
	HRESULT                      result = S_OK;
	char* pName = NULL;
	ULONG                        Funstart = 0;
	ULONG                        FunEnd = 0;
	PIMAGE_EXPORT_DIRECTORY      pExportBlack = NULL;
	WORD* pAddressOfNameOrdinals = NULL;
	ULONG* pAddressOfNames = NULL;
	ULONG* pAddressOfFunctions = NULL;
	UINT                         j = 0;
	pExportBlack = PIMAGE_EXPORT_DIRECTORY(pBase + DataExport.VirtualAddress);

	if (!pExportBlack || !DataExport.Size)
	{
		dprintf("***Empty export table***\n");
		return S_OK;
	}
	if (!bExport)
	{
		return S_OK;
	}
	pAddressOfNameOrdinals = (PWORD)((PUCHAR)pBase + pExportBlack->AddressOfNameOrdinals);
	pAddressOfNames = (PULONG)((PUCHAR)pBase + pExportBlack->AddressOfNames);
	pAddressOfFunctions = (PULONG)((PUCHAR)pBase + pExportBlack->AddressOfFunctions);
	Funstart = DataExport.VirtualAddress;
	FunEnd = DataExport.VirtualAddress + DataExport.Size;
	pName = (PCHAR)pBase + pExportBlack->Name;
	dprintf("DLL export name is %s\n", pName);
	dprintf("Index    Offset    Address      Name \n");
	for (UINT i = 0; i < pExportBlack->NumberOfFunctions; i++)
	{
		if ((*pAddressOfFunctions > Funstart) && (*pAddressOfFunctions < FunEnd))
		{
			pName = (char*)(pBase + *pAddressOfFunctions);
			dprintf("%04d    0x%08x    0x%08x    %s\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i, ulBase + *(pAddressOfFunctions + i), (char*)(pBase + *pAddressOfFunctions));
			continue;
		}
		for (j = 0; j < pExportBlack->NumberOfNames; j++)
		{
			if (*(pAddressOfNameOrdinals + j) == i)
			{
				pName = (char*)pBase + *(pAddressOfNames + j);
				dprintf("%04d    0x%08x    0x%08x    %s\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i, ulBase + *(pAddressOfFunctions + i), (char*)pBase + *(pAddressOfNames + j));
				break;
			}
		}
		if (*(pAddressOfNameOrdinals + j) != i)
		{
			dprintf("%04d    0x%08x    0x%08x    None\n", pExportBlack->Base + i, (PULONG)((PUCHAR)ulBase + pExportBlack->AddressOfFunctions) + i, ulBase + *(pAddressOfFunctions + i));
		}
	}
	return result;
}
HRESULT PE_PrintRelocal(PBYTE pImageBase, IMAGE_DATA_DIRECTORY DataExport, ULONG ulDelta, BOOL bPrint)
{
	if (bPrint) {
		dprintf("Relocal Address\t\t Data\t\t  \n");
	}
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pImageBase + DataExport.VirtualAddress);
	for (; pReloc->VirtualAddress > 0;)
	{
		unsigned char* dest = pImageBase + pReloc->VirtualAddress;
		unsigned short* relInfo = (unsigned short*)((unsigned char*)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		for (DWORD i = 0; i < ((pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++)
		{
			DWORD* patchAddrHL;
			int type, offset;
			type = *relInfo >> 12;
			offset = *relInfo & 0xfff;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				patchAddrHL = (DWORD*)(dest + offset);
				*patchAddrHL += ulDelta;
				if (bPrint)
					dprintf("%x\t%x\n", patchAddrHL, *patchAddrHL);
				break;
			case IMAGE_REL_BASED_DIR64:
			{
				ULONGLONG* PatchAddr64 = (ULONGLONG*)(dest + offset);
				*PatchAddr64 += ulDelta;
				if (bPrint)
					dprintf("%llx\t%llx\n", PatchAddr64, *PatchAddr64);
				break;
			}
			default:
				break;
			}
		}

		pReloc = (PIMAGE_BASE_RELOCATION)(((char*)pReloc) + pReloc->SizeOfBlock);

	}
	return S_OK;
}
DWORD_PTR GetAddressFromString(PCSTR address) {
	DWORD_PTR dwAddress = 0;
	if (nullptr == address) {
		return 0;
	}

	ULONG64 ul64Address = 0;
	ULONG index = 0;
	if (0 == g_ExtSymbols->GetModuleByModuleName(address, 0, &index, &ul64Address)) {
		return (ULONG_PTR)ul64Address;
	}
	if (address[0] == '0' && (address[1] == 'n' || address[1] == 'N')) {
		dwAddress = StrToAddress(address, 0);//STIF_DEFAULT;
	}
	else {
		dwAddress = StrToAddress(address, 1);//STIF_SUPPORT_HEX
	}
	return dwAddress;
}

HRESULT ExecuteCmd(PDEBUG_CLIENT4 Client, PCSTR args) {
	DWORD_PTR    dwAddress = 0;
	DWORD_PTR    dwBase = 0;
	DWORD_PTR    dwImageSize = 0;
	HRESULT      result = S_OK;
	ULONG        ulSetionCount = 0;
	ULONG        ulNtHeaderOffset = 0;
	ULONG        ulNtHeaderSize = 0;
	ULONG        ulNtSectionOffset = 0;
	BOOL         bAllPrint = TRUE;
	BOOL         bHasDosHeader = FALSE;
	BOOL         bHasNtHeader = FALSE;
	BOOL         bHasSection = FALSE;
	BOOL         bHasImport = FALSE;
	BOOL         bHasExport = FALSE;
	BOOL         bHasReloca = FALSE;
	ULONG        ulReadSize = 0;
	DWORD        dwSectionOffset = 0;

	cmdline<char>    cmd(args);
	IMAGE_DATA_DIRECTORY  DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = { 0 };

	auto p = cmd.GetSwitchCmd("");
	if (p && !p->empty()) {
		dwAddress = GetAddressFromString(p->at(0).c_str());
	}

	dprintf("Parse module address %x\n", dwAddress);
	if (0 == dwAddress)
		return S_FALSE;
	if (cmd.IsHasSwitch("-dos"))
		bHasDosHeader = TRUE;
	if (cmd.IsHasSwitch("-nt"))
		bHasNtHeader = TRUE;
	if (cmd.IsHasSwitch("-section"))
		bHasSection = TRUE;
	if (cmd.IsHasSwitch("-import"))
		bHasImport = TRUE;
	if (cmd.IsHasSwitch("-export"))
		bHasExport = TRUE;
	if (cmd.IsHasSwitch("-relocal"))
		bHasReloca = TRUE;

	if (S_OK != PE_PrintDosHeader(dwAddress, bHasDosHeader, &ulNtHeaderOffset))
		return S_FALSE;
	if (S_OK != PE_PrintNtHeader(dwAddress + ulNtHeaderOffset, bHasNtHeader, &ulSetionCount, DataDirectory,
		&dwBase, &dwImageSize, &ulNtHeaderSize, &dwSectionOffset))
		return S_FALSE;
	if (S_OK != PE_PrintSection(dwAddress + ulNtHeaderOffset +ulNtHeaderSize, ulSetionCount, bHasSection))
		return S_FALSE;

	if(bHasImport || bHasExport || bHasReloca)
	{
		PBYTE pImage = new BYTE[dwImageSize];
		if (pImage)
		{
			DWORD dwReadBytes = 0;
			DWORD dwTotalReadBytes = 0;

			memset(pImage, 0, dwImageSize);
			for (DWORD dwOffset = 0; dwOffset < dwImageSize; )
			{
				result = g_ExtDataSpaces->ReadVirtual(dwAddress + dwOffset, pImage + dwOffset, 0x1000, &dwReadBytes);
				if (result != S_OK) {
					dprintf("***Read address %x error.***\n", dwAddress + dwOffset);
				}
				if (dwReadBytes == 0) {
					dprintf("***ImageSize error, %x, %x. .***\n", 0x1000, ulReadSize);
				}
				else {
					dwTotalReadBytes += dwReadBytes;
				}
				dwOffset += 0x1000;
			}

			if (dwTotalReadBytes == 0) {
				dprintf("***ImageSize error, %x, %x. .***\n", dwImageSize, dwTotalReadBytes);
				result = S_FALSE;
			}
			else {
				if (bHasImport) {
					result = PE_PrintImport(pImage, DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], bHasImport);
					if (result != S_OK) {
						dprintf("***Print import fail***\n");
					}
				}

				if (bHasExport) {
					result = PE_PrintExport(pImage, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT], dwBase, bHasExport);
					if (result != S_OK) {
						dprintf("***Print export fail***\n");
					}
				}

				if (bHasReloca) {
					DWORD ulDelta = (DWORD)(dwAddress - dwBase);
					result = PE_PrintRelocal(pImage, DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], ulDelta, bHasReloca);
					if (result != S_OK) {
						dprintf("***Print relocal fail***\n");
					}
				}
			}

			delete[]pImage;
		}
	}
	return result;
}
HRESULT CALLBACK pe(PDEBUG_CLIENT4 Client, PCSTR args)
{
	HRESULT result = S_FALSE;
	if (args == NULL) {
		return S_FALSE;
	}
	INIT_API();
	
	ExecuteCmd(Client, args);

	EXIT_API();
	return result;
}

HRESULT CALLBACK help(PDEBUG_CLIENT4 Client, PCSTR args)
{
	INIT_API();

	dprintf("Help for PE.dll\n"
		"  help                = Shows this help\n"
		"  !pe  [params1] [params2] ... [paramsn]  address \n"
		"  params: optional  \n"
		"    -dos      show dos header \n"
		"    -nt       show ne header \n"
		"    -section  show section table \n"
		"    -import   show import table \n"
		"    -export   show export table \n"
		"  address :\n"
		"    16\n"
		"  E.g.  :\n"
		"    !pe -dos -section  0x10000000 \n"
		"    !pe   0x10000000 \n"
	);

	EXIT_API();
	return S_OK;
}


#pragma once
#include "pch.h"

#define KDEXT_64BIT
#include "..\inc\wdbgexts.h"
 
#include "..\inc\dbgeng.h"

#pragma comment(lib ,"dbgeng.lib")
#include "..\inc\extsfns.h"

extern WINDBG_EXTENSION_APIS   ExtensionApis;

#define INIT_API()                             \
    HRESULT Status;                            \
    if ((Status = ExtQuery(Client)) != S_OK) return Status;

#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)

#define EXIT_API     ExtRelease


// Global variables initialized by query.
extern PDEBUG_CLIENT4                         g_ExtClient;
extern PDEBUG_CONTROL4                        g_ExtControl;
extern PDEBUG_SYMBOLS2                        g_ExtSymbols;
extern PDEBUG_DATA_SPACES4                    g_ExtDataSpaces;

extern BOOL  Connected;
extern ULONG TargetMachine;

HRESULT ExtQuery(PDEBUG_CLIENT4 Client);

void ExtRelease(void);

#define dprintf          (ExtensionApis.lpOutputRoutine)
#define GetExpression    (ExtensionApis.lpGetExpressionRoutine)
#define CheckControlC    (ExtensionApis.lpCheckControlCRoutine)
#define GetContext       (ExtensionApis.lpGetThreadContextRoutine)
#define SetContext       (ExtensionApis.lpSetThreadContextRoutine)
#define Ioctl            (ExtensionApis.lpIoctlRoutine)
#define Disasm           (ExtensionApis.lpDisasmRoutine)
#define GetSymbol        (ExtensionApis.lpGetSymbolRoutine)
#define ReadMemory       (ExtensionApis.lpReadProcessMemoryRoutine)
#define WriteMemory      (ExtensionApis.lpWriteProcessMemoryRoutine)
#define StackTrace       (ExtensionApis.lpStackTraceRoutine)


#define FormatPrint    "     "
#define LineEnd        "\n"
#pragma once
#include <string>

class DbgOutputCallbackImpl : public IDebugOutputCallbacks
{
public:
    DbgOutputCallbackImpl();
    ~DbgOutputCallbackImpl();
    STDMETHOD(QueryInterface)(
        IN REFIID InterfaceId,
        OUT PVOID* Interface
        );
    STDMETHOD_(ULONG, AddRef)(
        );
    STDMETHOD_(ULONG, Release)(
        );
    // IDebugOutputCallbacks.
    STDMETHOD(Output)(
        IN ULONG Mask,
        IN PCSTR Text
        );

    void InitOutPutBuffer();
    LPCSTR GetOutputBuffer();
    void ClearOutPutBuffer();
private:
    std::string buffer_;
};
extern DbgOutputCallbackImpl g_OutputCb;


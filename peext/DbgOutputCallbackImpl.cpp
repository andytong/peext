#include "pch.h"
#include "DbgOutputCallbackImpl.h"

DbgOutputCallbackImpl g_OutputCb;

DbgOutputCallbackImpl::DbgOutputCallbackImpl() {
}
DbgOutputCallbackImpl::~DbgOutputCallbackImpl() {

}
STDMETHODIMP
DbgOutputCallbackImpl::QueryInterface(
	IN REFIID InterfaceId,
	OUT PVOID* Interface
) {
	*Interface = NULL;
	if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
		IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks))) {
		*Interface = (IDebugOutputCallbacks*)this;
		AddRef();
		return S_OK;
	}
	else {
		return E_NOINTERFACE;
	}
}
STDMETHODIMP_(ULONG)
DbgOutputCallbackImpl::AddRef() {
	return 1;
}
STDMETHODIMP_(ULONG)
DbgOutputCallbackImpl::Release() {
	return 0;
}
// IDebugOutputCallbacks.
STDMETHODIMP
DbgOutputCallbackImpl::Output(IN ULONG Mask, IN PCSTR Text) {
	UNREFERENCED_PARAMETER(Mask);
	buffer_ += Text;
	return S_OK;
}
void DbgOutputCallbackImpl::InitOutPutBuffer() {
	buffer_.clear();
}
LPCSTR DbgOutputCallbackImpl::GetOutputBuffer() {
	return buffer_.c_str();
}
void DbgOutputCallbackImpl::ClearOutPutBuffer() {
	buffer_.clear();
}

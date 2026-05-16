#pragma once

#include <Windows.h>

namespace DarkenedSkyeBridge
{
	void MaybeInstall();
	void OnDd7to9DrawPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, const void* Caller);
	void OnDd7to9DrawIndexedPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, DWORD IndexCount, const void* Caller);
}

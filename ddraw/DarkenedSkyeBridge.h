#pragma once

#include <Windows.h>

namespace DarkenedSkyeBridge
{
	struct CameraState
	{
		DWORD serial = 0;
		DWORD site = 0;
		DWORD kind = 0;
		float camera[3] = {};
		float view[16] = {};
	};

	void MaybeInstall();
	bool GetLatestCameraState(CameraState* state);
	bool CaptureDrawPrimitiveReplayPositions(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, const void* Caller, float* PositionsXyz, DWORD MaxVertices, DWORD* OutVertexCount);
	void OnDd7to9DrawPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, const void* Caller);
	void OnDd7to9DrawIndexedPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, DWORD IndexCount, const void* Caller);
}

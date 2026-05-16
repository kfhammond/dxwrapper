/**
* Darkened Skye-specific Dd7to9 diagnostics for RTX Remix bring-up.
*
* This module is intentionally gated by DdrawDarkenedSkyeBridge and verifies
* the exact retail Skye.exe instruction bytes before installing any hook.
*/

#include "DarkenedSkyeBridge.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "External\Hooking\Hook.h"
#include "Logging\Logging.h"
#include "Settings\Settings.h"

namespace
{
	constexpr DWORD kImageBase = 0x00400000;

	constexpr DWORD kSubmitFunctionPointerVa = 0x0054C9C4;
	constexpr DWORD kSourceVertexPointerVa = 0x0052AF0C;
	constexpr DWORD kCurrentSourceVertexPointerVa = 0x0050476C;
	constexpr DWORD kSharedTlVertexBufferVa = 0x0052B4EC;
	constexpr DWORD kTlVertexCursorVa = 0x0054D150;
	constexpr DWORD kSourceVertexCountVa = 0x004FDC74;
	constexpr DWORD kSourceVertexBufferVa = 0x004FEDA0;
	constexpr DWORD kCameraXVa = 0x00506EC8;
	constexpr DWORD kCameraYVa = 0x00506ECC;
	constexpr DWORD kCameraZVa = 0x00506ED0;
	constexpr DWORD kMatrixBaseVa = 0x00506F14;

	constexpr DWORD kFvfPositionMask = 0x00E;
	constexpr DWORD kFvfXyzRhw = 0x004;

	enum SourceKind : DWORD
	{
		SourceKindNone = 0,
		SourceKindScratchInPlace = 1,
		SourceKindIndexedEdiEdx = 2,
		SourceKindIndexedEbpEsi = 3
	};

	struct PushadFrame
	{
		DWORD edi;
		DWORD esi;
		DWORD ebp;
		DWORD esp;
		DWORD ebx;
		DWORD edx;
		DWORD ecx;
		DWORD eax;
	};

	struct RawVertexSample
	{
		DWORD sample = 0;
		DWORD index = 0xFFFFFFFF;
		DWORD address = 0;
		DWORD x = 0;
		DWORD y = 0;
		DWORD z = 0;
		bool readable = false;
	};

	struct TransformSnapshot
	{
		volatile LONG valid = 0;
		DWORD serial = 0;
		DWORD threadId = 0;
		DWORD site = 0;
		DWORD kind = SourceKindNone;
		DWORD tick = 0;

		PushadFrame regs = {};

		DWORD camera[3] = {};
		DWORD matrix[16] = {};
		DWORD submitFunction = 0;
		DWORD sourceVertexPointer = 0;
		DWORD currentSourceVertexPointer = 0;
		DWORD sharedTlVertexBuffer = 0;
		DWORD tlVertexCursor = 0;
		DWORD sourceVertexCount = 0;

		DWORD sourceBase = 0;
		DWORD sourceCurrent = 0;
		DWORD indexBase = 0;
		DWORD sourceStride = 0;
		DWORD indexStride = 0;
		RawVertexSample samples[4] = {};
		DWORD sampleCount = 0;
	};

	struct PreSubmitSnapshot
	{
		volatile LONG valid = 0;
		DWORD serial = 0;
		DWORD threadId = 0;
		DWORD site = 0;
		DWORD tick = 0;
		PushadFrame regs = {};
		TransformSnapshot transform = {};
	};

	LONG g_installState = 0;
	LONG g_nextSerial = 0;
	DWORD g_exeBase = 0;
	DWORD g_exeSize = 0;

	TransformSnapshot g_latestTransform = {};
	PreSubmitSnapshot g_latestPreSubmit = {};

	DWORD VaToRuntime(DWORD va)
	{
		if (!g_exeBase || va < kImageBase)
		{
			return va;
		}

		return g_exeBase + (va - kImageBase);
	}

	template <typename T>
	bool TryRead(DWORD address, T* out)
	{
		if (!address || !out)
		{
			return false;
		}

		__try
		{
			*out = *reinterpret_cast<const T*>(address);
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	bool TryReadBytes(DWORD address, void* out, size_t size)
	{
		if (!address || !out || !size)
		{
			return false;
		}

		__try
		{
			std::memcpy(out, reinterpret_cast<const void*>(address), size);
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	float BitsToFloat(DWORD value)
	{
		float result = 0.0f;
		std::memcpy(&result, &value, sizeof(result));
		return result;
	}

	const char* KindName(DWORD kind)
	{
		switch (kind)
		{
		case SourceKindScratchInPlace:
			return "scratchInPlace";
		case SourceKindIndexedEdiEdx:
			return "indexedWorldEdiEdx";
		case SourceKindIndexedEbpEsi:
			return "indexedWorldEbpEsi";
		default:
			return "none";
		}
	}

	std::string FormatSkyeAddress(DWORD runtimeAddress)
	{
		std::ostringstream os;
		if (g_exeBase && g_exeSize && runtimeAddress >= g_exeBase && runtimeAddress < g_exeBase + g_exeSize)
		{
			os << "Skye+0x" << std::hex << (runtimeAddress - g_exeBase);
		}
		else if (runtimeAddress)
		{
			os << "0x" << std::hex << runtimeAddress;
		}
		else
		{
			os << "0x0";
		}
		return os.str();
	}

	std::string FormatFloat3(const DWORD values[3])
	{
		std::ostringstream os;
		os << '(' << BitsToFloat(values[0]) << ',' << BitsToFloat(values[1]) << ',' << BitsToFloat(values[2]) << ')';
		return os.str();
	}

	std::string FormatSamples(const TransformSnapshot& snapshot)
	{
		std::ostringstream os;
		os << '[';
		for (DWORD i = 0; i < snapshot.sampleCount && i < ARRAYSIZE(snapshot.samples); ++i)
		{
			const RawVertexSample& sample = snapshot.samples[i];
			if (i)
			{
				os << ';';
			}

			os << "s" << sample.sample;
			if (sample.index != 0xFFFFFFFF)
			{
				os << "/i" << sample.index;
			}
			os << '@' << FormatSkyeAddress(sample.address);
			if (sample.readable)
			{
				const DWORD xyz[3] = { sample.x, sample.y, sample.z };
				os << '=' << FormatFloat3(xyz);
			}
			else
			{
				os << "=unreadable";
			}
		}
		os << ']';
		return os.str();
	}

	bool IsSkyeProcess()
	{
		char path[MAX_PATH] = {};
		if (!GetModuleFileNameA(nullptr, path, ARRAYSIZE(path)))
		{
			return false;
		}

		const char* slash = std::strrchr(path, '\\');
		const char* forwardSlash = std::strrchr(path, '/');
		const char* name = (forwardSlash && (!slash || forwardSlash > slash)) ? forwardSlash : slash;
		name = name ? name + 1 : path;
		return _stricmp(name, "Skye.exe") == 0;
	}

	bool InitExeImage()
	{
		const auto exeBase = reinterpret_cast<BYTE*>(GetModuleHandleA(nullptr));
		if (!exeBase)
		{
			return false;
		}

		__try
		{
			const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(exeBase);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return false;
			}

			const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(exeBase + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
			{
				return false;
			}

			g_exeBase = reinterpret_cast<DWORD>(exeBase);
			g_exeSize = nt->OptionalHeader.SizeOfImage;
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	bool VerifyBytes(DWORD va, const BYTE* expected, size_t expectedSize)
	{
		BYTE actual[16] = {};
		if (expectedSize > sizeof(actual))
		{
			return false;
		}

		const DWORD runtimeAddress = VaToRuntime(va);
		return TryReadBytes(runtimeAddress, actual, expectedSize) &&
			std::memcmp(actual, expected, expectedSize) == 0;
	}

	void SnapshotGlobals(TransformSnapshot* snapshot)
	{
		if (!snapshot)
		{
			return;
		}

		TryRead(VaToRuntime(kCameraXVa), &snapshot->camera[0]);
		TryRead(VaToRuntime(kCameraYVa), &snapshot->camera[1]);
		TryRead(VaToRuntime(kCameraZVa), &snapshot->camera[2]);
		for (DWORD i = 0; i < ARRAYSIZE(snapshot->matrix); ++i)
		{
			TryRead(VaToRuntime(kMatrixBaseVa + (i * sizeof(DWORD))), &snapshot->matrix[i]);
		}

		TryRead(VaToRuntime(kSubmitFunctionPointerVa), &snapshot->submitFunction);
		TryRead(VaToRuntime(kSourceVertexPointerVa), &snapshot->sourceVertexPointer);
		TryRead(VaToRuntime(kCurrentSourceVertexPointerVa), &snapshot->currentSourceVertexPointer);
		TryRead(VaToRuntime(kSharedTlVertexBufferVa), &snapshot->sharedTlVertexBuffer);
		TryRead(VaToRuntime(kTlVertexCursorVa), &snapshot->tlVertexCursor);
		TryRead(VaToRuntime(kSourceVertexCountVa), &snapshot->sourceVertexCount);
	}

	void CaptureSampleFromAddress(TransformSnapshot* snapshot, DWORD sampleSlot, DWORD index, DWORD vertexAddress)
	{
		if (!snapshot || sampleSlot >= ARRAYSIZE(snapshot->samples))
		{
			return;
		}

		RawVertexSample& sample = snapshot->samples[sampleSlot];
		sample.sample = sampleSlot;
		sample.index = index;
		sample.address = vertexAddress;
		sample.readable =
			TryRead(vertexAddress, &sample.x) &&
			TryRead(vertexAddress + 4, &sample.y) &&
			TryRead(vertexAddress + 8, &sample.z);
	}

	void CaptureScratchSamples(TransformSnapshot* snapshot)
	{
		if (!snapshot)
		{
			return;
		}

		snapshot->sourceBase = snapshot->sourceVertexPointer;
		snapshot->sourceCurrent = snapshot->sourceVertexPointer + snapshot->regs.eax;
		snapshot->sourceStride = 0x34;
		snapshot->sampleCount = 2;

		for (DWORD i = 0; i < snapshot->sampleCount; ++i)
		{
			CaptureSampleFromAddress(snapshot, i, 0xFFFFFFFF, snapshot->sourceCurrent + (i * snapshot->sourceStride));
		}
	}

	void CaptureIndexedSamples(TransformSnapshot* snapshot, DWORD vertexBase, DWORD indexBase)
	{
		if (!snapshot)
		{
			return;
		}

		snapshot->sourceBase = vertexBase;
		snapshot->sourceCurrent = vertexBase;
		snapshot->indexBase = indexBase;
		snapshot->sourceStride = 12;
		snapshot->indexStride = 2;
		snapshot->sampleCount = 4;

		for (DWORD i = 0; i < snapshot->sampleCount; ++i)
		{
			WORD index = 0;
			const DWORD indexAddress = indexBase + (i * snapshot->indexStride);
			if (!TryRead(indexAddress, &index))
			{
				snapshot->sampleCount = i;
				break;
			}

			CaptureSampleFromAddress(snapshot, i, index, vertexBase + (static_cast<DWORD>(index) * snapshot->sourceStride));
		}
	}

	SourceKind KindForSite(DWORD site)
	{
		switch (site)
		{
		case 0x0042A25F:
		case 0x0042AF0C:
			return SourceKindScratchInPlace;
		case 0x0042B445:
		case 0x0042B66B:
			return SourceKindIndexedEdiEdx;
		case 0x0044E6DA:
			return SourceKindIndexedEbpEsi;
		default:
			return SourceKindNone;
		}
	}

	void StoreTransformSnapshot(DWORD site, const PushadFrame* frame)
	{
		if (!frame)
		{
			return;
		}

		TransformSnapshot snapshot = {};
		snapshot.threadId = GetCurrentThreadId();
		snapshot.site = site;
		snapshot.kind = KindForSite(site);
		snapshot.tick = GetTickCount();
		snapshot.regs = *frame;
		SnapshotGlobals(&snapshot);

		switch (snapshot.kind)
		{
		case SourceKindScratchInPlace:
			if (snapshot.regs.eax == 0)
			{
				CaptureScratchSamples(&snapshot);
			}
			else
			{
				return;
			}
			break;
		case SourceKindIndexedEdiEdx:
			CaptureIndexedSamples(&snapshot, snapshot.regs.edi, snapshot.regs.edx);
			break;
		case SourceKindIndexedEbpEsi:
			CaptureIndexedSamples(&snapshot, snapshot.regs.ebp, snapshot.regs.esi);
			break;
		default:
			return;
		}

		snapshot.serial = static_cast<DWORD>(InterlockedIncrement(&g_nextSerial));
		snapshot.valid = 1;
		g_latestTransform = snapshot;
	}

	void StorePreSubmitSnapshot(DWORD site, const PushadFrame* frame)
	{
		if (!frame)
		{
			return;
		}

		PreSubmitSnapshot snapshot = {};
		snapshot.threadId = GetCurrentThreadId();
		snapshot.site = site;
		snapshot.tick = GetTickCount();
		snapshot.regs = *frame;

		if (g_latestTransform.valid && g_latestTransform.threadId == snapshot.threadId)
		{
			snapshot.transform = g_latestTransform;
		}

		snapshot.serial = static_cast<DWORD>(InterlockedIncrement(&g_nextSerial));
		snapshot.valid = 1;
		g_latestPreSubmit = snapshot;
	}

	void* InstallHook(DWORD va, const char* name, void* hookProc, void** trampoline, const BYTE* expected, size_t expectedSize)
	{
		if (!VerifyBytes(va, expected, expectedSize))
		{
			LOG_LIMIT(20, "[DarkenedSkye-Bridge] skip hook byte-mismatch"
				" site=" << FormatSkyeAddress(VaToRuntime(va)) <<
				" name=" << name);
			return nullptr;
		}

		void* result = Hook::HotPatch(reinterpret_cast<void*>(VaToRuntime(va)), name, hookProc);
		*trampoline = result;
		if (result)
		{
			LOG_LIMIT(20, "[DarkenedSkye-Bridge] installed hook"
				" site=" << FormatSkyeAddress(VaToRuntime(va)) <<
				" name=" << name <<
				" trampoline=" << result);
		}
		else
		{
			LOG_LIMIT(20, "[DarkenedSkye-Bridge] failed hook"
				" site=" << FormatSkyeAddress(VaToRuntime(va)) <<
				" name=" << name);
		}
		return result;
	}

	void LogDrawPair(const char* functionName, DWORD primitiveType, DWORD fvf, DWORD startVertex, DWORD vertexCount, DWORD indexCount, const void* caller)
	{
		if ((fvf & kFvfPositionMask) != kFvfXyzRhw)
		{
			return;
		}

		const DWORD threadId = GetCurrentThreadId();
		PreSubmitSnapshot preSubmit = {};
		if (g_latestPreSubmit.valid && g_latestPreSubmit.threadId == threadId)
		{
			preSubmit = g_latestPreSubmit;
			g_latestPreSubmit.valid = 0;
		}
		else if (g_latestTransform.valid && g_latestTransform.threadId == threadId)
		{
			preSubmit.threadId = threadId;
			preSubmit.transform = g_latestTransform;
			preSubmit.valid = 1;
		}

		if (!preSubmit.valid || !preSubmit.transform.valid)
		{
			LOG_LIMIT(120, "[DarkenedSkye-Bridge] draw-missing-capture"
				" function=" << functionName <<
				" primitive=" << primitiveType <<
				" fvf=" << Logging::hex(fvf) <<
				" vertices=" << vertexCount <<
				" indices=" << indexCount <<
				" caller=" << FormatSkyeAddress(reinterpret_cast<DWORD>(caller)));
			return;
		}

		const TransformSnapshot& transform = preSubmit.transform;
		LOG_LIMIT(300, "[DarkenedSkye-Bridge] draw-pair"
			" function=" << functionName <<
			" primitive=" << primitiveType <<
			" fvf=" << Logging::hex(fvf) <<
			" start=" << startVertex <<
			" vertices=" << vertexCount <<
			" indices=" << indexCount <<
			" drawCaller=" << FormatSkyeAddress(reinterpret_cast<DWORD>(caller)) <<
			" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
			" transform=" << FormatSkyeAddress(VaToRuntime(transform.site)) <<
			" kind=" << KindName(transform.kind) <<
			" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
			" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
			" sourceCount=" << transform.sourceVertexCount <<
			" tlCursor=" << transform.tlVertexCursor <<
			" tlVB=" << FormatSkyeAddress(transform.sharedTlVertexBuffer) <<
			" camera=" << FormatFloat3(transform.camera) <<
			" matrix0_3=(" << BitsToFloat(transform.matrix[0]) << ',' << BitsToFloat(transform.matrix[1]) << ',' << BitsToFloat(transform.matrix[2]) << ',' << BitsToFloat(transform.matrix[3]) << ')' <<
			" samples=" << FormatSamples(transform));
	}
}

#if defined(_M_IX86)
extern "C" void* g_SkyeBridgeTrampoline42A25F = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42AF0C = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B445 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B66B = nullptr;
extern "C" void* g_SkyeBridgeTrampoline44E6DA = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42A395 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B042 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B626 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline439BFF = nullptr;
extern "C" void* g_SkyeBridgeTrampoline44E7E7 = nullptr;

extern "C" void __cdecl SkyeBridge_CaptureTransform(DWORD site, const PushadFrame* frame)
{
	StoreTransformSnapshot(site, frame);
}

extern "C" void __cdecl SkyeBridge_CapturePreSubmit(DWORD site, const PushadFrame* frame)
{
	StorePreSubmitSnapshot(site, frame);
}

#define SKYE_TRANSFORM_HOOK(functionName, site, trampolineName) \
	extern "C" __declspec(naked) void functionName() \
	{ \
		__asm pushfd \
		__asm pushad \
		__asm mov eax, esp \
		__asm push eax \
		__asm push site \
		__asm call SkyeBridge_CaptureTransform \
		__asm add esp, 8 \
		__asm popad \
		__asm popfd \
		__asm jmp dword ptr [trampolineName] \
	}

#define SKYE_PRESUBMIT_HOOK(functionName, site, trampolineName) \
	extern "C" __declspec(naked) void functionName() \
	{ \
		__asm pushfd \
		__asm pushad \
		__asm mov eax, esp \
		__asm push eax \
		__asm push site \
		__asm call SkyeBridge_CapturePreSubmit \
		__asm add esp, 8 \
		__asm popad \
		__asm popfd \
		__asm jmp dword ptr [trampolineName] \
	}

SKYE_TRANSFORM_HOOK(SkyeBridge_Hook42A25F, 0042A25Fh, g_SkyeBridgeTrampoline42A25F)
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook42AF0C, 0042AF0Ch, g_SkyeBridgeTrampoline42AF0C)
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook42B445, 0042B445h, g_SkyeBridgeTrampoline42B445)
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook42B66B, 0042B66Bh, g_SkyeBridgeTrampoline42B66B)
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook44E6DA, 0044E6DAh, g_SkyeBridgeTrampoline44E6DA)

SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42A395, 0042A395h, g_SkyeBridgeTrampoline42A395)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42B042, 0042B042h, g_SkyeBridgeTrampoline42B042)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42B626, 0042B626h, g_SkyeBridgeTrampoline42B626)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook439BFF, 00439BFFh, g_SkyeBridgeTrampoline439BFF)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook44E7E7, 0044E7E7h, g_SkyeBridgeTrampoline44E7E7)
#endif

void DarkenedSkyeBridge::MaybeInstall()
{
	if (!Config.DdrawDarkenedSkyeBridge)
	{
		return;
	}

	if (InterlockedCompareExchange(&g_installState, 1, 0) != 0)
	{
		return;
	}

#if !defined(_M_IX86)
	LOG_LIMIT(1, "[DarkenedSkye-Bridge] disabled: bridge hooks require x86");
	g_installState = 3;
	return;
#else
	if (!IsSkyeProcess())
	{
		LOG_LIMIT(1, "[DarkenedSkye-Bridge] disabled: process is not Skye.exe");
		g_installState = 3;
		return;
	}

	if (!InitExeImage())
	{
		LOG_LIMIT(1, "[DarkenedSkye-Bridge] disabled: unable to inspect Skye.exe image");
		g_installState = 3;
		return;
	}

	static const BYTE k42A25F[] = { 0x8B, 0x0D, 0x0C, 0xAF, 0x52, 0x00 };
	static const BYTE k42AF0C[] = { 0x8B, 0x0D, 0x0C, 0xAF, 0x52, 0x00 };
	static const BYTE k42B445[] = { 0x33, 0xC0, 0x66, 0x8B, 0x02 };
	static const BYTE k42B66B[] = { 0x33, 0xC0, 0x66, 0x8B, 0x02 };
	static const BYTE k44E6DA[] = { 0x8B, 0xD6, 0xB9, 0xA8, 0xED, 0x4F, 0x00 };
	static const BYTE kPreSubmit[] = { 0xFF, 0x15, 0xC4, 0xC9, 0x54, 0x00 };

	DWORD installed = 0;
	installed += InstallHook(0x0042A25F, "SkyeTransform42A25F", SkyeBridge_Hook42A25F, &g_SkyeBridgeTrampoline42A25F, k42A25F, sizeof(k42A25F)) ? 1 : 0;
	installed += InstallHook(0x0042AF0C, "SkyeTransform42AF0C", SkyeBridge_Hook42AF0C, &g_SkyeBridgeTrampoline42AF0C, k42AF0C, sizeof(k42AF0C)) ? 1 : 0;
	installed += InstallHook(0x0042B445, "SkyeTransform42B445", SkyeBridge_Hook42B445, &g_SkyeBridgeTrampoline42B445, k42B445, sizeof(k42B445)) ? 1 : 0;
	installed += InstallHook(0x0042B66B, "SkyeTransform42B66B", SkyeBridge_Hook42B66B, &g_SkyeBridgeTrampoline42B66B, k42B66B, sizeof(k42B66B)) ? 1 : 0;
	installed += InstallHook(0x0044E6DA, "SkyeTransform44E6DA", SkyeBridge_Hook44E6DA, &g_SkyeBridgeTrampoline44E6DA, k44E6DA, sizeof(k44E6DA)) ? 1 : 0;

	installed += InstallHook(0x0042A395, "SkyePreSubmit42A395", SkyeBridge_Hook42A395, &g_SkyeBridgeTrampoline42A395, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0042B042, "SkyePreSubmit42B042", SkyeBridge_Hook42B042, &g_SkyeBridgeTrampoline42B042, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0042B626, "SkyePreSubmit42B626", SkyeBridge_Hook42B626, &g_SkyeBridgeTrampoline42B626, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x00439BFF, "SkyePreSubmit439BFF", SkyeBridge_Hook439BFF, &g_SkyeBridgeTrampoline439BFF, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0044E7E7, "SkyePreSubmit44E7E7", SkyeBridge_Hook44E7E7, &g_SkyeBridgeTrampoline44E7E7, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;

	g_installState = installed ? 2 : 3;
	LOG_LIMIT(1, "[DarkenedSkye-Bridge] hook install complete"
		" installed=" << installed <<
		" exeBase=" << reinterpret_cast<void*>(g_exeBase) <<
		" exeSize=" << g_exeSize);
#endif
}

void DarkenedSkyeBridge::OnDd7to9DrawPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, const void* Caller)
{
	MaybeInstall();
	LogDrawPair("DrawPrimitiveVB", PrimitiveType, FVF, StartVertex, VertexCount, 0, Caller);
}

void DarkenedSkyeBridge::OnDd7to9DrawIndexedPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, DWORD IndexCount, const void* Caller)
{
	MaybeInstall();
	LogDrawPair("DrawIndexedPrimitiveVB", PrimitiveType, FVF, StartVertex, VertexCount, IndexCount, Caller);
}

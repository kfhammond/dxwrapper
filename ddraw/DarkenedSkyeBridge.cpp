/**
* Darkened Skye-specific Dd7to9 diagnostics for RTX Remix bring-up.
*
* This module is intentionally gated by DdrawDarkenedSkyeBridge and verifies
* the exact retail Skye.exe instruction bytes before installing any hook.
*/

#include "DarkenedSkyeBridge.h"

#include <algorithm>
#include <cmath>
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
	constexpr DWORD kScratchSegmentOffset = 0x2680;
	constexpr DWORD kCameraXVa = 0x00506EC8;
	constexpr DWORD kCameraYVa = 0x00506ECC;
	constexpr DWORD kCameraZVa = 0x00506ED0;
	constexpr DWORD kMatrixBaseVa = 0x00506F14;
	constexpr DWORD kMatrixFloatCount = 12;
	constexpr DWORD kProjectionScaleVa = 0x004FFAE8;
	constexpr DWORD kProjectionCenterXVa = 0x004FFB44;
	constexpr DWORD kProjectionCenterYVa = 0x0052C94C;
	constexpr DWORD kProjectionNearVa = 0x004FFB90;

	constexpr DWORD kFvfPositionMask = 0x00E;
	constexpr DWORD kFvfXyzRhw = 0x004;
	constexpr bool kEnableScratchInPlaceReplay = true;
	constexpr bool kEnableScratchReplayStitch = true;
	constexpr bool kEnableRawIndexedReplay = false;
	constexpr bool kEnableIndexedPartialReplay = false;
	constexpr bool kEnableIndexedScratchFallback = false;
	constexpr bool kEnableIndexedCursorBaseReplay = false;
	constexpr bool kEnableIndexedOutputScratchReplay = false;
	constexpr DWORD kScratchBatchVertexCount = 3;
	constexpr DWORD kMaxAccumulatedScratchReplayVertices = 4096;
	constexpr float kMaxReplayTriangleEdgeLength = 4096.0f;
	constexpr LONG kIndexedDiagSummaryInterval = 1024;
	constexpr DWORD kMaxIndexedDiagBuckets = 24;

	enum SourceKind : DWORD
	{
		SourceKindNone = 0,
		SourceKindScratchInPlace = 1,
		SourceKindIndexedEdiEdx = 2,
		SourceKindIndexedEbpEsi = 3,
		SourceKindIndexedEbpEdx = 4
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
		DWORD projectionScale = 0;
		DWORD projectionCenterX = 0;
		DWORD projectionCenterY = 0;
		DWORD projectionNear = 0;
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
		DWORD batchVertexCount = 0;
		RawVertexSample samples[4] = {};
		DWORD sampleCount = 0;
	};

	struct Vec3
	{
		float x = 0.0f;
		float y = 0.0f;
		float z = 0.0f;
	};

	struct ReplayGeometryStats
	{
		Vec3 min = {};
		Vec3 max = {};
		Vec3 center = {};
		bool valid = false;
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
		DWORD indexedReplayValidAtSubmit = 0;
		DWORD indexedReplayVertexCountAtSubmit = 0;
		DWORD indexedReplayCursorBaseAtSubmit = 0;
		DWORD indexedReplayLastTransformSerialAtSubmit = 0;
		DWORD indexedReplayLastPreSubmitSiteAtSubmit = 0;
		DWORD indexedReplayLastTickAtSubmit = 0;
		DWORD indexedReplayLatestTransformSiteAtSubmit = 0;
		DWORD indexedReplayLatestTransformKindAtSubmit = SourceKindNone;
	};

	struct ReplayAccumulator
	{
		volatile LONG valid = 0;
		DWORD threadId = 0;
		DWORD vertexCount = 0;
		DWORD cursorBase = 0;
		DWORD lastTransformSerial = 0;
		DWORD lastPreSubmitSite = 0;
		DWORD lastTick = 0;
		TransformSnapshot latestTransform = {};
		float positions[kMaxAccumulatedScratchReplayVertices * 3] = {};
	};

	enum IndexedDiagEventType : DWORD
	{
		IndexedDiagAppendAccepted = 0,
		IndexedDiagAppendReject,
		IndexedDiagAppendGap,
		IndexedDiagAppendOverflow,
		IndexedDiagAppendReset,
		IndexedDiagConsumeOk,
		IndexedDiagConsumeUnavailable,
		IndexedDiagConsumeSiteMismatch,
		IndexedDiagConsumeZeroCamera,
		IndexedDiagConsumeCountMismatch,
		IndexedDiagReplaySkip
	};

	struct IndexedDiagBucket
	{
		bool inUse = false;
		DWORD preSubmitSite = 0;
		DWORD transformSite = 0;
		DWORD kind = SourceKindNone;
		volatile LONG appendAccepted = 0;
		volatile LONG appendReject = 0;
		volatile LONG appendGap = 0;
		volatile LONG appendOverflow = 0;
		volatile LONG appendReset = 0;
		volatile LONG consumeOk = 0;
		volatile LONG consumeUnavailable = 0;
		volatile LONG consumeSiteMismatch = 0;
		volatile LONG consumeZeroCamera = 0;
		volatile LONG consumeCountMismatch = 0;
		volatile LONG replaySkip = 0;
	};

	LONG g_installState = 0;
	LONG g_nextSerial = 0;
	DWORD g_exeBase = 0;
	DWORD g_exeSize = 0;

	TransformSnapshot g_latestTransform = {};
	TransformSnapshot g_latestIndexedTransform = {};
	TransformSnapshot g_latestScratchTransform = {};
	TransformSnapshot g_latestIndexedEdiEdxTransform = {};
	TransformSnapshot g_latestIndexedEbpEsiTransform = {};
	TransformSnapshot g_latestIndexedEbpEdxTransform = {};
	PreSubmitSnapshot g_latestPreSubmit = {};
	PreSubmitSnapshot g_lastConsumedPreSubmit = {};
	ReplayAccumulator g_scratchReplay = {};
	ReplayAccumulator g_indexedReplay = {};
	IndexedDiagBucket g_indexedDiagBuckets[kMaxIndexedDiagBuckets] = {};
	volatile LONG g_indexedDiagEventSerial = 0;

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

	DWORD FloatToBits(float value)
	{
		DWORD result = 0;
		std::memcpy(&result, &value, sizeof(result));
		return result;
	}

	bool IsUsableFloat(float value)
	{
		return std::isfinite(value) && std::fabs(value) < 1.0e20f;
	}

	float MaxAbs3(float x, float y, float z)
	{
		const float ax = std::fabs(x);
		const float ay = std::fabs(y);
		const float az = std::fabs(z);
		return ax > ay ? (ax > az ? ax : az) : (ay > az ? ay : az);
	}

	bool IsNearlyZero(float value)
	{
		return std::fabs(value) < 1.0e-5f;
	}

	float Dot(const Vec3& a, const Vec3& b)
	{
		return (a.x * b.x) + (a.y * b.y) + (a.z * b.z);
	}

	float LengthSq(const Vec3& value)
	{
		return Dot(value, value);
	}

	float DistanceSq(const float* a, const float* b)
	{
		const float dx = a[0] - b[0];
		const float dy = a[1] - b[1];
		const float dz = a[2] - b[2];
		return (dx * dx) + (dy * dy) + (dz * dz);
	}

	bool Normalize(Vec3& value)
	{
		const float lengthSq = LengthSq(value);
		if (lengthSq < 1.0e-8f || !IsUsableFloat(lengthSq))
		{
			return false;
		}

		const float invLength = 1.0f / std::sqrt(lengthSq);
		value.x *= invLength;
		value.y *= invLength;
		value.z *= invLength;
		return IsUsableFloat(value.x) && IsUsableFloat(value.y) && IsUsableFloat(value.z);
	}

	bool IsUsableVec3(const Vec3& value)
	{
		return IsUsableFloat(value.x) && IsUsableFloat(value.y) && IsUsableFloat(value.z);
	}

	bool BuildViewFromNativeMatrix(const float native[kMatrixFloatCount], const float camera[3], bool anyCamera, float view[16])
	{
		Vec3 right = { native[0], native[1], native[2] };
		Vec3 up = { native[3], native[4], native[5] };
		Vec3 forward = { native[6], native[7], native[8] };
		Vec3 translation = { native[9], native[10], native[11] };

		if (!IsUsableVec3(right) || !IsUsableVec3(up) || !IsUsableVec3(forward) ||
			!Normalize(right) || !Normalize(up) || !Normalize(forward))
		{
			return false;
		}

		if (std::fabs(Dot(right, up)) > 0.02f ||
			std::fabs(Dot(right, forward)) > 0.02f ||
			std::fabs(Dot(up, forward)) > 0.02f)
		{
			return false;
		}

		if (!IsUsableVec3(translation) && anyCamera)
		{
			const Vec3 eye = { camera[0], camera[1], camera[2] };
			if (!IsUsableVec3(eye))
			{
				return false;
			}

			translation.x = -Dot(right, eye);
			translation.y = -Dot(up, eye);
			translation.z = -Dot(forward, eye);
		}

		if (!IsUsableVec3(translation))
		{
			return false;
		}

		std::fill(view, view + 16, 0.0f);
		view[0] = right.x;
		view[1] = up.x;
		view[2] = forward.x;
		view[4] = right.y;
		view[5] = up.y;
		view[6] = forward.y;
		view[8] = right.z;
		view[9] = up.z;
		view[10] = forward.z;
		view[12] = translation.x;
		view[13] = translation.y;
		view[14] = translation.z;
		view[15] = 1.0f;
		return true;
	}

	bool TryBuildNativeBasisAndEye(const TransformSnapshot& snapshot, Vec3* right, Vec3* up, Vec3* forward, Vec3* eye)
	{
		if (!right || !up || !forward || !eye)
		{
			return false;
		}

		*right = { BitsToFloat(snapshot.matrix[0]), BitsToFloat(snapshot.matrix[1]), BitsToFloat(snapshot.matrix[2]) };
		*up = { BitsToFloat(snapshot.matrix[3]), BitsToFloat(snapshot.matrix[4]), BitsToFloat(snapshot.matrix[5]) };
		*forward = { BitsToFloat(snapshot.matrix[6]), BitsToFloat(snapshot.matrix[7]), BitsToFloat(snapshot.matrix[8]) };
		*eye = { BitsToFloat(snapshot.camera[0]), BitsToFloat(snapshot.camera[1]), BitsToFloat(snapshot.camera[2]) };

		if (!IsUsableVec3(*right) || !IsUsableVec3(*up) || !IsUsableVec3(*forward) || !IsUsableVec3(*eye) ||
			!Normalize(*right) || !Normalize(*up) || !Normalize(*forward))
		{
			return false;
		}

		if (IsNearlyZero(eye->x) && IsNearlyZero(eye->y) && IsNearlyZero(eye->z))
		{
			return false;
		}

		return std::fabs(Dot(*right, *up)) <= 0.02f &&
			std::fabs(Dot(*right, *forward)) <= 0.02f &&
			std::fabs(Dot(*up, *forward)) <= 0.02f;
	}

	bool ViewToWorldPosition(const Vec3& right, const Vec3& up, const Vec3& forward, const Vec3& eye, const float view[3], float world[3])
	{
		if (!view || !world ||
			!IsUsableFloat(view[0]) || !IsUsableFloat(view[1]) || !IsUsableFloat(view[2]))
		{
			return false;
		}

		world[0] = eye.x + (right.x * view[0]) + (up.x * view[1]) + (forward.x * view[2]);
		world[1] = eye.y + (right.y * view[0]) + (up.y * view[1]) + (forward.y * view[2]);
		world[2] = eye.z + (right.z * view[0]) + (up.z * view[1]) + (forward.z * view[2]);
		return IsUsableFloat(world[0]) && IsUsableFloat(world[1]) && IsUsableFloat(world[2]);
	}

	bool IsIndexedKind(DWORD kind)
	{
		return kind == SourceKindIndexedEdiEdx ||
			kind == SourceKindIndexedEbpEsi ||
			kind == SourceKindIndexedEbpEdx;
	}

	DWORD BatchVertexCountForSite(DWORD site)
	{
		switch (site)
		{
		case 0x0042B66B:
			return 4;
		case 0x0042A25F:
		case 0x0042AF0C:
		case 0x0042B445:
		case 0x0044E5DC:
		case 0x0044E689:
		case 0x0044E6DA:
			return kScratchBatchVertexCount;
		default:
			return 0;
		}
	}

	bool ShouldPreferIndexedForPreSubmit(const TransformSnapshot& selected, const TransformSnapshot& indexed, DWORD threadId)
	{
		if (!selected.valid || !indexed.valid)
		{
			return false;
		}

		if (selected.kind != SourceKindScratchInPlace || !IsIndexedKind(indexed.kind))
		{
			return false;
		}

		if (selected.threadId != threadId || indexed.threadId != threadId)
		{
			return false;
		}

		if (indexed.serial > selected.serial)
		{
			return false;
		}

		const DWORD serialDelta = selected.serial - indexed.serial;
		if (serialDelta > 64)
		{
			return false;
		}

		if (indexed.tick > selected.tick)
		{
			return false;
		}

		const DWORD tickDelta = selected.tick - indexed.tick;
		if (tickDelta > 8)
		{
			return false;
		}

		return true;
	}

	DWORD ExpectedKindForPreSubmitSite(DWORD site)
	{
		switch (site)
		{
		case 0x0042A395:
		case 0x0042B042:
			return SourceKindScratchInPlace;
		case 0x0042B626:
		case 0x0042B84C:
			return SourceKindIndexedEdiEdx;
		case 0x00439BFF:
		case 0x0044E7E7:
			return SourceKindIndexedEbpEsi;
		case 0x0044E69C:
			return SourceKindIndexedEbpEdx;
		default:
			return SourceKindNone;
		}
	}

	TransformSnapshot* LatestTransformCacheForKindMutable(DWORD kind)
	{
		switch (kind)
		{
		case SourceKindScratchInPlace:
			return &g_latestScratchTransform;
		case SourceKindIndexedEdiEdx:
			return &g_latestIndexedEdiEdxTransform;
		case SourceKindIndexedEbpEsi:
			return &g_latestIndexedEbpEsiTransform;
		case SourceKindIndexedEbpEdx:
			return &g_latestIndexedEbpEdxTransform;
		default:
			return nullptr;
		}
	}

	const TransformSnapshot* LatestTransformCacheForKind(DWORD kind)
	{
		switch (kind)
		{
		case SourceKindScratchInPlace:
			return &g_latestScratchTransform;
		case SourceKindIndexedEdiEdx:
			return &g_latestIndexedEdiEdxTransform;
		case SourceKindIndexedEbpEsi:
			return &g_latestIndexedEbpEsiTransform;
		case SourceKindIndexedEbpEdx:
			return &g_latestIndexedEbpEdxTransform;
		default:
			return nullptr;
		}
	}

	bool TrySelectExpectedKindForPreSubmit(DWORD preSubmitSite, DWORD threadId, const TransformSnapshot& selected, TransformSnapshot* out)
	{
		if (!out)
		{
			return false;
		}

		const DWORD expectedKind = ExpectedKindForPreSubmitSite(preSubmitSite);
		if (expectedKind == SourceKindNone || selected.kind == expectedKind)
		{
			return false;
		}

		const TransformSnapshot* candidate = LatestTransformCacheForKind(expectedKind);
		if (!candidate || !candidate->valid || candidate->threadId != threadId)
		{
			return false;
		}

		if (selected.serial < candidate->serial || selected.tick < candidate->tick)
		{
			return false;
		}

		const DWORD serialDelta = selected.serial - candidate->serial;
		const DWORD tickDelta = selected.tick - candidate->tick;
		if (serialDelta > 64 || tickDelta > 8)
		{
			return false;
		}

		*out = *candidate;
		return true;
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
		case SourceKindIndexedEbpEdx:
			return "indexedWorldEbpEdx";
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

	std::string FormatVec3(const Vec3& value)
	{
		std::ostringstream os;
		os << '(' << value.x << ',' << value.y << ',' << value.z << ')';
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

	IndexedDiagBucket* AcquireIndexedDiagBucket(DWORD preSubmitSite, DWORD transformSite, DWORD kind)
	{
		IndexedDiagBucket* freeBucket = nullptr;
		for (DWORD i = 0; i < ARRAYSIZE(g_indexedDiagBuckets); ++i)
		{
			IndexedDiagBucket& bucket = g_indexedDiagBuckets[i];
			if (!bucket.inUse)
			{
				if (!freeBucket)
				{
					freeBucket = &bucket;
				}
				continue;
			}

			if (bucket.preSubmitSite == preSubmitSite &&
				bucket.transformSite == transformSite &&
				bucket.kind == kind)
			{
				return &bucket;
			}
		}

		if (!freeBucket)
		{
			return nullptr;
		}

		freeBucket->inUse = true;
		freeBucket->preSubmitSite = preSubmitSite;
		freeBucket->transformSite = transformSite;
		freeBucket->kind = kind;
		return freeBucket;
	}

	void LogIndexedDiagSummary(const char* trigger, LONG eventSerial)
	{
		for (DWORD i = 0; i < ARRAYSIZE(g_indexedDiagBuckets); ++i)
		{
			const IndexedDiagBucket& bucket = g_indexedDiagBuckets[i];
			if (!bucket.inUse)
			{
				continue;
			}

			const LONG failures =
				bucket.appendReject +
				bucket.appendGap +
				bucket.appendOverflow +
				bucket.appendReset +
				bucket.consumeUnavailable +
				bucket.consumeSiteMismatch +
				bucket.consumeZeroCamera +
				bucket.consumeCountMismatch +
				bucket.replaySkip;
			if (!failures && !bucket.appendAccepted && !bucket.consumeOk)
			{
				continue;
			}

			LOG_LIMIT(300, "[DarkenedSkye-Bridge] indexed-diag-summary"
				" trigger=" << trigger <<
				" eventSerial=" << eventSerial <<
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(bucket.preSubmitSite)) <<
				" transform=" << FormatSkyeAddress(VaToRuntime(bucket.transformSite)) <<
				" kind=" << KindName(bucket.kind) <<
				" appendAccepted=" << bucket.appendAccepted <<
				" appendReject=" << bucket.appendReject <<
				" appendGap=" << bucket.appendGap <<
				" appendOverflow=" << bucket.appendOverflow <<
				" appendReset=" << bucket.appendReset <<
				" consumeOk=" << bucket.consumeOk <<
				" consumeUnavailable=" << bucket.consumeUnavailable <<
				" consumeSiteMismatch=" << bucket.consumeSiteMismatch <<
				" consumeZeroCamera=" << bucket.consumeZeroCamera <<
				" consumeCountMismatch=" << bucket.consumeCountMismatch <<
				" replaySkip=" << bucket.replaySkip);
		}
	}

	void NoteIndexedDiagEvent(IndexedDiagEventType eventType, DWORD preSubmitSite, DWORD transformSite, DWORD kind)
	{
		if (!IsIndexedKind(kind))
		{
			return;
		}

		IndexedDiagBucket* bucket = AcquireIndexedDiagBucket(preSubmitSite, transformSite, kind);
		if (!bucket)
		{
			return;
		}

		volatile LONG* counter = nullptr;
		switch (eventType)
		{
		case IndexedDiagAppendAccepted:
			counter = &bucket->appendAccepted;
			break;
		case IndexedDiagAppendReject:
			counter = &bucket->appendReject;
			break;
		case IndexedDiagAppendGap:
			counter = &bucket->appendGap;
			break;
		case IndexedDiagAppendOverflow:
			counter = &bucket->appendOverflow;
			break;
		case IndexedDiagAppendReset:
			counter = &bucket->appendReset;
			break;
		case IndexedDiagConsumeOk:
			counter = &bucket->consumeOk;
			break;
		case IndexedDiagConsumeUnavailable:
			counter = &bucket->consumeUnavailable;
			break;
		case IndexedDiagConsumeSiteMismatch:
			counter = &bucket->consumeSiteMismatch;
			break;
		case IndexedDiagConsumeZeroCamera:
			counter = &bucket->consumeZeroCamera;
			break;
		case IndexedDiagConsumeCountMismatch:
			counter = &bucket->consumeCountMismatch;
			break;
		case IndexedDiagReplaySkip:
			counter = &bucket->replaySkip;
			break;
		default:
			break;
		}

		if (!counter)
		{
			return;
		}

		InterlockedIncrement(counter);
		const LONG eventSerial = InterlockedIncrement(&g_indexedDiagEventSerial);
		if (eventSerial % kIndexedDiagSummaryInterval == 0)
		{
			// Periodic rollups keep family trends visible when per-event logs hit caps.
			LogIndexedDiagSummary("periodic", eventSerial);
		}
	}

	void ResetScratchReplayAccumulator(DWORD threadId)
	{
		g_scratchReplay.valid = 0;
		g_scratchReplay.threadId = threadId;
		g_scratchReplay.vertexCount = 0;
		g_scratchReplay.cursorBase = 0;
		g_scratchReplay.lastTransformSerial = 0;
		g_scratchReplay.lastPreSubmitSite = 0;
		g_scratchReplay.lastTick = 0;
		g_scratchReplay.latestTransform = {};
	}

	void ResetIndexedReplayAccumulator(DWORD threadId)
	{
		g_indexedReplay.valid = 0;
		g_indexedReplay.threadId = threadId;
		g_indexedReplay.vertexCount = 0;
		g_indexedReplay.cursorBase = 0;
		g_indexedReplay.lastTransformSerial = 0;
		g_indexedReplay.lastPreSubmitSite = 0;
		g_indexedReplay.lastTick = 0;
		g_indexedReplay.latestTransform = {};
	}

	void CaptureIndexedReplayStateAtSubmit(PreSubmitSnapshot* snapshot)
	{
		if (!snapshot)
		{
			return;
		}

		snapshot->indexedReplayValidAtSubmit = g_indexedReplay.valid ? 1 : 0;
		snapshot->indexedReplayVertexCountAtSubmit = g_indexedReplay.vertexCount;
		snapshot->indexedReplayCursorBaseAtSubmit = g_indexedReplay.cursorBase;
		snapshot->indexedReplayLastTransformSerialAtSubmit = g_indexedReplay.lastTransformSerial;
		snapshot->indexedReplayLastPreSubmitSiteAtSubmit = g_indexedReplay.lastPreSubmitSite;
		snapshot->indexedReplayLastTickAtSubmit = g_indexedReplay.lastTick;
		snapshot->indexedReplayLatestTransformSiteAtSubmit = g_indexedReplay.latestTransform.site;
		snapshot->indexedReplayLatestTransformKindAtSubmit = g_indexedReplay.latestTransform.kind;
	}

	bool ScratchSamplesUsable(const TransformSnapshot& transform)
	{
		if (transform.kind != SourceKindScratchInPlace ||
			transform.sampleCount < kScratchBatchVertexCount)
		{
			return false;
		}

		for (DWORD i = 0; i < kScratchBatchVertexCount; ++i)
		{
			const RawVertexSample& sample = transform.samples[i];
			if (!sample.readable ||
				!IsUsableFloat(BitsToFloat(sample.x)) ||
				!IsUsableFloat(BitsToFloat(sample.y)) ||
				!IsUsableFloat(BitsToFloat(sample.z)))
			{
				return false;
			}
		}

		return true;
	}

	void AppendScratchReplayBatch(DWORD preSubmitSite, const TransformSnapshot& transform)
	{
		if (!ScratchSamplesUsable(transform))
		{
			return;
		}

		if (transform.serial == g_scratchReplay.lastTransformSerial &&
			g_scratchReplay.threadId == transform.threadId)
		{
			return;
		}

		const DWORD expectedCursor = transform.tlVertexCursor;
		if (!g_scratchReplay.valid ||
			g_scratchReplay.threadId != transform.threadId ||
			expectedCursor == 0 ||
			expectedCursor < g_scratchReplay.vertexCount)
		{
			ResetScratchReplayAccumulator(transform.threadId);
			g_scratchReplay.valid = 1;
		}

		if (g_scratchReplay.vertexCount != expectedCursor)
		{
			LOG_LIMIT(240, "[DarkenedSkye-Bridge] scratch-accum-gap"
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmitSite)) <<
				" transform=" << FormatSkyeAddress(VaToRuntime(transform.site)) <<
				" expectedCursor=" << expectedCursor <<
				" haveVertices=" << g_scratchReplay.vertexCount <<
				" serial=" << transform.serial);
			g_scratchReplay.lastTransformSerial = transform.serial;
			g_scratchReplay.lastPreSubmitSite = preSubmitSite;
			g_scratchReplay.lastTick = transform.tick;
			g_scratchReplay.latestTransform = transform;
			return;
		}

		if (g_scratchReplay.vertexCount + kScratchBatchVertexCount > kMaxAccumulatedScratchReplayVertices)
		{
			LOG_LIMIT(40, "[DarkenedSkye-Bridge] scratch-accum-overflow"
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmitSite)) <<
				" haveVertices=" << g_scratchReplay.vertexCount <<
				" capacity=" << kMaxAccumulatedScratchReplayVertices);
			ResetScratchReplayAccumulator(transform.threadId);
			return;
		}

		for (DWORD i = 0; i < kScratchBatchVertexCount; ++i)
		{
			const RawVertexSample& sample = transform.samples[i];
			const DWORD dstVertex = g_scratchReplay.vertexCount + i;
			float* dst = &g_scratchReplay.positions[dstVertex * 3];
			dst[0] = BitsToFloat(sample.x);
			dst[1] = BitsToFloat(sample.y);
			dst[2] = BitsToFloat(sample.z);
		}

		g_scratchReplay.vertexCount += kScratchBatchVertexCount;
		g_scratchReplay.lastTransformSerial = transform.serial;
		g_scratchReplay.lastPreSubmitSite = preSubmitSite;
		g_scratchReplay.lastTick = transform.tick;
		g_scratchReplay.latestTransform = transform;
		g_scratchReplay.valid = 1;
	}

	const char* GetIndexedSamplesRejectReason(const TransformSnapshot& transform)
	{
		const DWORD batchVertexCount = transform.batchVertexCount ? transform.batchVertexCount : kScratchBatchVertexCount;
		if (!IsIndexedKind(transform.kind))
		{
			return "not-indexed";
		}

		if (transform.sampleCount < batchVertexCount)
		{
			return "sample-count";
		}

		for (DWORD i = 0; i < batchVertexCount; ++i)
		{
			const RawVertexSample& sample = transform.samples[i];
			if (!sample.readable)
			{
				return "sample-unreadable";
			}

			const float x = BitsToFloat(sample.x);
			const float y = BitsToFloat(sample.y);
			const float z = BitsToFloat(sample.z);
			if (!IsUsableFloat(x) || !IsUsableFloat(y) || !IsUsableFloat(z))
			{
				return "sample-invalid-float";
			}

			if (MaxAbs3(x, y, z) < 4.0f)
			{
				return "sample-vector-like";
			}
		}

		return nullptr;
	}

	void AppendIndexedReplayBatch(DWORD preSubmitSite, const TransformSnapshot& transform)
	{
		const char* rejectReason = GetIndexedSamplesRejectReason(transform);
		if (rejectReason)
		{
			LOG_LIMIT(240, "[DarkenedSkye-Bridge] indexed-accum-reject"
				" reason=" << rejectReason <<
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmitSite)) <<
				" transform=" << FormatSkyeAddress(VaToRuntime(transform.site)) <<
				" expectedCursor=" << transform.tlVertexCursor <<
				" haveVertices=" << g_indexedReplay.vertexCount <<
				" kind=" << KindName(transform.kind) <<
				" batchVertices=" << transform.batchVertexCount <<
				" sampleCount=" << transform.sampleCount <<
				" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
				" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
				" serial=" << transform.serial <<
				" samples=" << FormatSamples(transform));
			NoteIndexedDiagEvent(IndexedDiagAppendReject, preSubmitSite, transform.site, transform.kind);
			return;
		}

		if (transform.serial == g_indexedReplay.lastTransformSerial &&
			g_indexedReplay.threadId == transform.threadId)
		{
			if (preSubmitSite && !g_indexedReplay.lastPreSubmitSite)
			{
				g_indexedReplay.lastPreSubmitSite = preSubmitSite;
			}
			return;
		}

		const DWORD expectedCursor = transform.tlVertexCursor;
		const DWORD batchVertexCount = transform.batchVertexCount ? transform.batchVertexCount : kScratchBatchVertexCount;
		if (!g_indexedReplay.valid ||
			g_indexedReplay.threadId != transform.threadId ||
			g_indexedReplay.latestTransform.kind != transform.kind ||
			expectedCursor == 0 ||
			expectedCursor < g_indexedReplay.vertexCount)
		{
			ResetIndexedReplayAccumulator(transform.threadId);
			g_indexedReplay.valid = 1;
			NoteIndexedDiagEvent(IndexedDiagAppendReset, preSubmitSite, transform.site, transform.kind);
		}

		DWORD expectedRelativeCursor = expectedCursor;
		if (g_indexedReplay.cursorBase && expectedCursor >= g_indexedReplay.cursorBase)
		{
			expectedRelativeCursor = expectedCursor - g_indexedReplay.cursorBase;
		}

		if (g_indexedReplay.vertexCount && expectedRelativeCursor < g_indexedReplay.vertexCount)
		{
			ResetIndexedReplayAccumulator(transform.threadId);
			g_indexedReplay.valid = 1;
			expectedRelativeCursor = expectedCursor;
			NoteIndexedDiagEvent(IndexedDiagAppendReset, preSubmitSite, transform.site, transform.kind);
		}

		bool cursorMatchesPreBatch = (g_indexedReplay.vertexCount == expectedRelativeCursor);
		bool cursorMatchesPostBatch = false;
		if (batchVertexCount && expectedRelativeCursor >= batchVertexCount)
		{
			cursorMatchesPostBatch = (g_indexedReplay.vertexCount == (expectedRelativeCursor - batchVertexCount));
		}

		if (!cursorMatchesPreBatch && !cursorMatchesPostBatch && g_indexedReplay.vertexCount == 0)
		{
			g_indexedReplay.cursorBase = expectedCursor;
			expectedRelativeCursor = 0;
			cursorMatchesPreBatch = true;
		}
		const char* cursorMode = cursorMatchesPreBatch ? "pre" : (cursorMatchesPostBatch ? "post" : "none");

		if (!cursorMatchesPreBatch && !cursorMatchesPostBatch)
		{
			LOG_LIMIT(240, "[DarkenedSkye-Bridge] indexed-accum-gap"
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmitSite)) <<
				" transform=" << FormatSkyeAddress(VaToRuntime(transform.site)) <<
				" expectedCursor=" << expectedCursor <<
				" expectedRelative=" << expectedRelativeCursor <<
				" haveVertices=" << g_indexedReplay.vertexCount <<
				" kind=" << KindName(transform.kind) <<
				" batchVertices=" << batchVertexCount <<
				" cursorBase=" << g_indexedReplay.cursorBase <<
				" cursorMode=" << cursorMode <<
				" serial=" << transform.serial);
			g_indexedReplay.lastTransformSerial = transform.serial;
			g_indexedReplay.lastPreSubmitSite = preSubmitSite;
			g_indexedReplay.lastTick = transform.tick;
			g_indexedReplay.latestTransform = transform;
			NoteIndexedDiagEvent(IndexedDiagAppendGap, preSubmitSite, transform.site, transform.kind);
			return;
		}

		if (g_indexedReplay.vertexCount + batchVertexCount > kMaxAccumulatedScratchReplayVertices)
		{
			LOG_LIMIT(40, "[DarkenedSkye-Bridge] indexed-accum-overflow"
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmitSite)) <<
				" haveVertices=" << g_indexedReplay.vertexCount <<
				" capacity=" << kMaxAccumulatedScratchReplayVertices);
			NoteIndexedDiagEvent(IndexedDiagAppendOverflow, preSubmitSite, transform.site, transform.kind);
			ResetIndexedReplayAccumulator(transform.threadId);
			return;
		}

		for (DWORD i = 0; i < batchVertexCount; ++i)
		{
			const RawVertexSample& sample = transform.samples[i];
			const DWORD dstVertex = g_indexedReplay.vertexCount + i;
			float* dst = &g_indexedReplay.positions[dstVertex * 3];
			dst[0] = BitsToFloat(sample.x);
			dst[1] = BitsToFloat(sample.y);
			dst[2] = BitsToFloat(sample.z);
		}

		g_indexedReplay.vertexCount += batchVertexCount;
		g_indexedReplay.lastTransformSerial = transform.serial;
		g_indexedReplay.lastPreSubmitSite = preSubmitSite;
		g_indexedReplay.lastTick = transform.tick;
		g_indexedReplay.latestTransform = transform;
		g_indexedReplay.valid = 1;
		NoteIndexedDiagEvent(IndexedDiagAppendAccepted, preSubmitSite, transform.site, transform.kind);
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
		TryRead(VaToRuntime(kProjectionScaleVa), &snapshot->projectionScale);
		TryRead(VaToRuntime(kProjectionCenterXVa), &snapshot->projectionCenterX);
		TryRead(VaToRuntime(kProjectionCenterYVa), &snapshot->projectionCenterY);
		TryRead(VaToRuntime(kProjectionNearVa), &snapshot->projectionNear);
		for (DWORD i = 0; i < kMatrixFloatCount; ++i)
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
		// At the hooked site EAX is an inner-loop offset (0, 0x34, 0x68) for a
		// 3-vertex transform pass, not the start of the full replay stream.
		// Starting at base+EAX misaligns triangle-list reconstruction.
		snapshot->sourceCurrent = snapshot->sourceVertexPointer;
		snapshot->sourceStride = 0x34;
		snapshot->sampleCount = kScratchBatchVertexCount;

		for (DWORD i = 0; i < snapshot->sampleCount; ++i)
		{
			CaptureSampleFromAddress(snapshot, i, 0xFFFFFFFF, snapshot->sourceCurrent + (i * snapshot->sourceStride));
		}

		// Some draws stage transformed vertices at currentSourceVertexPointer.
		// If sourceCurrent is unreadable, fall back to that cursor so replay
		// extraction stays aligned with the active draw stream.
		if (!snapshot->samples[0].readable && snapshot->currentSourceVertexPointer)
		{
			snapshot->sourceBase = snapshot->currentSourceVertexPointer;
			snapshot->sourceCurrent = snapshot->currentSourceVertexPointer;
			for (DWORD i = 0; i < snapshot->sampleCount; ++i)
			{
				CaptureSampleFromAddress(snapshot, i, 0xFFFFFFFF, snapshot->sourceCurrent + (i * snapshot->sourceStride));
			}
		}
	}

	void CaptureIndexedSamples(TransformSnapshot* snapshot, DWORD vertexBase, DWORD indexBase, DWORD sampleCount)
	{
		if (!snapshot)
		{
			return;
		}

		const DWORD clampedSampleCount = std::min<DWORD>(sampleCount, ARRAYSIZE(snapshot->samples));
		snapshot->sourceBase = vertexBase;
		snapshot->sourceCurrent = vertexBase;
		snapshot->indexBase = indexBase;
		snapshot->sourceStride = 12;
		snapshot->indexStride = 2;
		snapshot->sampleCount = clampedSampleCount;

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

	void CaptureOutputScratchSamples(TransformSnapshot* snapshot)
	{
		if (!snapshot)
		{
			return;
		}

		const DWORD scratchBase = VaToRuntime(kSourceVertexBufferVa);
		snapshot->sourceBase = scratchBase;
		snapshot->sourceCurrent = scratchBase;
		snapshot->indexBase = snapshot->regs.edx;
		snapshot->sourceStride = 0x34;
		snapshot->indexStride = 0;
		snapshot->sourceVertexCount = kScratchBatchVertexCount;
		snapshot->sampleCount = kScratchBatchVertexCount;

		Vec3 right = {};
		Vec3 up = {};
		Vec3 forward = {};
		Vec3 eye = {};
		const bool canConvertViewToWorld = TryBuildNativeBasisAndEye(*snapshot, &right, &up, &forward, &eye);

		for (DWORD i = 0; i < snapshot->sampleCount; ++i)
		{
			const DWORD vertexAddress = snapshot->sourceCurrent + (i * snapshot->sourceStride);
			RawVertexSample& sample = snapshot->samples[i];
			sample.sample = i;
			sample.index = 0xFFFFFFFF;
			sample.address = vertexAddress;

			DWORD viewBits[3] = {};
			if (!canConvertViewToWorld ||
				!TryRead(vertexAddress, &viewBits[0]) ||
				!TryRead(vertexAddress + 4, &viewBits[1]) ||
				!TryRead(vertexAddress + 8, &viewBits[2]))
			{
				sample.readable = false;
				continue;
			}

			const float view[3] = { BitsToFloat(viewBits[0]), BitsToFloat(viewBits[1]), BitsToFloat(viewBits[2]) };
			float world[3] = {};
			if (!ViewToWorldPosition(right, up, forward, eye, view, world))
			{
				sample.readable = false;
				continue;
			}

			sample.x = FloatToBits(world[0]);
			sample.y = FloatToBits(world[1]);
			sample.z = FloatToBits(world[2]);
			sample.readable = true;
		}
	}

	bool ShouldAppendIndexedAtTransformSite(DWORD site)
	{
		// 44E689 runs before the clip/visibility helper. Append only if the
		// matching pre-submit hook proves the helper accepted this triangle.
		return site != 0x0044E689;
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
		case 0x0044E689:
			return SourceKindIndexedEbpEdx;
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
		snapshot.batchVertexCount = BatchVertexCountForSite(site);
		SnapshotGlobals(&snapshot);

		switch (snapshot.kind)
		{
		case SourceKindScratchInPlace:
			CaptureScratchSamples(&snapshot);
			if (snapshot.regs.eax != 0)
			{
				return;
			}
			if (snapshot.sampleCount < kScratchBatchVertexCount ||
				!snapshot.samples[0].readable ||
				!snapshot.samples[1].readable ||
				!snapshot.samples[2].readable)
			{
				return;
			}
			break;
		case SourceKindIndexedEdiEdx:
			CaptureIndexedSamples(&snapshot, snapshot.regs.edi, snapshot.regs.edx, snapshot.batchVertexCount);
			break;
		case SourceKindIndexedEbpEsi:
			CaptureIndexedSamples(&snapshot, snapshot.regs.ebp, snapshot.regs.esi, snapshot.batchVertexCount);
			break;
		case SourceKindIndexedEbpEdx:
			if (site == 0x0044E689)
			{
				CaptureOutputScratchSamples(&snapshot);
			}
			else
			{
				CaptureIndexedSamples(&snapshot, snapshot.regs.ebp, snapshot.regs.edx, snapshot.batchVertexCount);
			}
			break;
		default:
			return;
		}

		snapshot.serial = static_cast<DWORD>(InterlockedIncrement(&g_nextSerial));
		snapshot.valid = 1;
		g_latestTransform = snapshot;
		if (TransformSnapshot* latestForKind = LatestTransformCacheForKindMutable(snapshot.kind))
		{
			*latestForKind = snapshot;
		}
		if (g_lastConsumedPreSubmit.valid && g_lastConsumedPreSubmit.threadId == snapshot.threadId)
		{
			g_lastConsumedPreSubmit.valid = 0;
		}
		if (IsIndexedKind(snapshot.kind))
		{
			g_latestIndexedTransform = snapshot;
			if (ShouldAppendIndexedAtTransformSite(site))
			{
				AppendIndexedReplayBatch(0, snapshot);
			}
		}
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

			if (ShouldPreferIndexedForPreSubmit(snapshot.transform, g_latestIndexedTransform, snapshot.threadId))
			{
				ResetScratchReplayAccumulator(snapshot.threadId);
				snapshot.transform = g_latestIndexedTransform;
				LOG_LIMIT(400, "[DarkenedSkye-Bridge] pre-submit-transform-override"
					" preSubmit=" << FormatSkyeAddress(VaToRuntime(site)) <<
					" selected=scratch" <<
					" replacement=" << KindName(snapshot.transform.kind) <<
					" transform=" << FormatSkyeAddress(VaToRuntime(snapshot.transform.site)) <<
					" serialDelta=" << (g_latestTransform.serial - snapshot.transform.serial) <<
					" tickDelta=" << (g_latestTransform.tick - snapshot.transform.tick));
			}

			const TransformSnapshot selectedTransform = snapshot.transform;
			TransformSnapshot expectedKindTransform = {};
			if (TrySelectExpectedKindForPreSubmit(site, snapshot.threadId, selectedTransform, &expectedKindTransform))
			{
				snapshot.transform = expectedKindTransform;
				LOG_LIMIT(400, "[DarkenedSkye-Bridge] pre-submit-kind-correction"
					" preSubmit=" << FormatSkyeAddress(VaToRuntime(site)) <<
					" selected=" << KindName(selectedTransform.kind) <<
					" replacement=" << KindName(snapshot.transform.kind) <<
					" transform=" << FormatSkyeAddress(VaToRuntime(snapshot.transform.site)) <<
					" serialDelta=" << (selectedTransform.serial - snapshot.transform.serial) <<
					" tickDelta=" << (selectedTransform.tick - snapshot.transform.tick));
			}

			if (snapshot.transform.kind == SourceKindScratchInPlace)
			{
				AppendScratchReplayBatch(site, snapshot.transform);
			}
			else if (IsIndexedKind(snapshot.transform.kind))
			{
				ResetScratchReplayAccumulator(snapshot.threadId);
				AppendIndexedReplayBatch(site, snapshot.transform);
				CaptureIndexedReplayStateAtSubmit(&snapshot);
			}
			else
			{
				ResetScratchReplayAccumulator(snapshot.threadId);
				ResetIndexedReplayAccumulator(snapshot.threadId);
			}
		}

		snapshot.serial = static_cast<DWORD>(InterlockedIncrement(&g_nextSerial));
		snapshot.valid = 1;
		g_latestPreSubmit = snapshot;
		if (g_lastConsumedPreSubmit.valid && g_lastConsumedPreSubmit.threadId == snapshot.threadId)
		{
			g_lastConsumedPreSubmit.valid = 0;
		}
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

	bool TryReuseConsumedPreSubmit(DWORD threadId, PreSubmitSnapshot* out)
	{
		if (!g_lastConsumedPreSubmit.valid ||
			g_lastConsumedPreSubmit.threadId != threadId ||
			!g_lastConsumedPreSubmit.site ||
			!g_lastConsumedPreSubmit.transform.valid)
		{
			return false;
		}

		if (g_latestTransform.valid &&
			g_latestTransform.threadId == threadId &&
			g_latestTransform.serial != g_lastConsumedPreSubmit.transform.serial)
		{
			return false;
		}

		const DWORD tickDelta = GetTickCount() - g_lastConsumedPreSubmit.tick;
		if (tickDelta > 250)
		{
			return false;
		}

		if (out)
		{
			*out = g_lastConsumedPreSubmit;
		}
		return true;
	}

	bool ConsumePairedSnapshot(const char* functionName, DWORD primitiveType, DWORD fvf, DWORD vertexCount, DWORD indexCount, const void* caller, PreSubmitSnapshot* out)
	{
		if ((fvf & kFvfPositionMask) != kFvfXyzRhw)
		{
			return false;
		}

		const DWORD threadId = GetCurrentThreadId();
		PreSubmitSnapshot preSubmit = {};
		if (g_latestPreSubmit.valid && g_latestPreSubmit.threadId == threadId)
		{
			preSubmit = g_latestPreSubmit;
			g_latestPreSubmit.valid = 0;
			g_lastConsumedPreSubmit = preSubmit;
		}
		else if (TryReuseConsumedPreSubmit(threadId, &preSubmit))
		{
			LOG_LIMIT(600, "[DarkenedSkye-Bridge] pre-submit-reuse"
				" function=" << functionName <<
				" primitive=" << primitiveType <<
				" vertices=" << vertexCount <<
				" indices=" << indexCount <<
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
				" transform=" << FormatSkyeAddress(VaToRuntime(preSubmit.transform.site)) <<
				" kind=" << KindName(preSubmit.transform.kind) <<
				" tickDelta=" << (GetTickCount() - preSubmit.tick) <<
				" caller=" << FormatSkyeAddress(reinterpret_cast<DWORD>(caller)));
		}
		else if (g_latestTransform.valid && g_latestTransform.threadId == threadId)
		{
			preSubmit.threadId = threadId;
			preSubmit.transform = g_latestTransform;
			preSubmit.valid = 1;
		}

		if (!preSubmit.valid || !preSubmit.transform.valid)
		{
			LOG_LIMIT(500, "[DarkenedSkye-Bridge] draw-missing-capture"
				" function=" << functionName <<
				" primitive=" << primitiveType <<
				" fvf=" << Logging::hex(fvf) <<
				" vertices=" << vertexCount <<
				" indices=" << indexCount <<
				" caller=" << FormatSkyeAddress(reinterpret_cast<DWORD>(caller)));
			return false;
		}

		if (out)
		{
			*out = preSubmit;
		}
		return true;
	}

	void LogDrawPair(const char* functionName, DWORD primitiveType, DWORD fvf, DWORD startVertex, DWORD vertexCount, DWORD indexCount, const void* caller, const PreSubmitSnapshot& preSubmit)
	{
		const TransformSnapshot& transform = preSubmit.transform;
		LOG_LIMIT(10000, "[DarkenedSkye-Bridge] draw-pair"
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
			" batchVertices=" << transform.batchVertexCount <<
			" tlCursor=" << transform.tlVertexCursor <<
			" tlVB=" << FormatSkyeAddress(transform.sharedTlVertexBuffer) <<
			" camera=" << FormatFloat3(transform.camera) <<
			" matrix0_3=(" << BitsToFloat(transform.matrix[0]) << ',' << BitsToFloat(transform.matrix[1]) << ',' << BitsToFloat(transform.matrix[2]) << ',' << BitsToFloat(transform.matrix[3]) << ')' <<
			" matrix9_11=(" << BitsToFloat(transform.matrix[9]) << ',' << BitsToFloat(transform.matrix[10]) << ',' << BitsToFloat(transform.matrix[11]) << ')' <<
			" projection=(scale=" << BitsToFloat(transform.projectionScale) <<
			",center=" << BitsToFloat(transform.projectionCenterX) << ',' << BitsToFloat(transform.projectionCenterY) <<
			",near=" << BitsToFloat(transform.projectionNear) << ')' <<
			" samples=" << FormatSamples(transform));
	}

	bool HasNonZeroCamera(const TransformSnapshot& transform)
	{
		for (DWORD i = 0; i < ARRAYSIZE(transform.camera); ++i)
		{
			const float value = BitsToFloat(transform.camera[i]);
			if (!IsUsableFloat(value))
			{
				return false;
			}

			if (!IsNearlyZero(value))
			{
				return true;
			}
		}

		return false;
	}

	bool ReadReplayPosition(DWORD address, float* outXyz)
	{
		if (!address || !outXyz)
		{
			return false;
		}

		DWORD xyz[3] = {};
		if (!TryRead(address, &xyz[0]) ||
			!TryRead(address + 4, &xyz[1]) ||
			!TryRead(address + 8, &xyz[2]))
		{
			return false;
		}

		const float x = BitsToFloat(xyz[0]);
		const float y = BitsToFloat(xyz[1]);
		const float z = BitsToFloat(xyz[2]);
		if (!IsUsableFloat(x) || !IsUsableFloat(y) || !IsUsableFloat(z))
		{
			return false;
		}

		outXyz[0] = x;
		outXyz[1] = y;
		outXyz[2] = z;
		return true;
	}

	bool ReadReplayPositionsFromAddress(DWORD sourceCurrent, DWORD sourceStride, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount)
	{
		if (!positionsXyz || !outVertexCount || !sourceCurrent || sourceStride < 12)
		{
			return false;
		}

		DWORD count = 0;
		for (; count < maxVertices; ++count)
		{
			const DWORD vertexAddress = sourceCurrent + (count * sourceStride);
			if (!ReadReplayPosition(vertexAddress, &positionsXyz[count * 3]))
			{
				break;
			}
		}

		*outVertexCount = count;
		return count == maxVertices;
	}

	DWORD AppendReplayPositionsFromAddress(DWORD sourceCurrent, DWORD sourceStride, float* positionsXyz, DWORD startVertex, DWORD maxVertices)
	{
		if (!positionsXyz || !sourceCurrent || sourceStride < 12 || startVertex >= maxVertices)
		{
			return startVertex;
		}

		DWORD count = startVertex;
		for (; count < maxVertices; ++count)
		{
			const DWORD vertexAddress = sourceCurrent + ((count - startVertex) * sourceStride);
			if (!ReadReplayPosition(vertexAddress, &positionsXyz[count * 3]))
			{
				break;
			}
		}

		return count;
	}

	bool ReadSegmentedScratchReplayPositions(const TransformSnapshot& /*transform*/, DWORD primarySource, DWORD sourceStride, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, bool* outUsedStitch)
	{
		if (outUsedStitch)
		{
			*outUsedStitch = false;
		}

		if (!positionsXyz || !outVertexCount || !primarySource || sourceStride < 12)
		{
			return false;
		}

		if (ReadReplayPositionsFromAddress(primarySource, sourceStride, positionsXyz, maxVertices, outVertexCount))
		{
			return true;
		}

		if (!*outVertexCount)
		{
			return false;
		}

		if (!kEnableScratchReplayStitch)
		{
			return false;
		}

		const DWORD scratchBase = VaToRuntime(kSourceVertexBufferVa);
		const DWORD scratchSplit = scratchBase ? (scratchBase + kScratchSegmentOffset) : 0;
		if (!scratchBase || !scratchSplit)
		{
			return false;
		}

		DWORD stitchSource = 0;
		if (primarySource < scratchSplit)
		{
			stitchSource = scratchSplit;
		}
		else
		{
			stitchSource = scratchBase;
		}

		if (!stitchSource || stitchSource == primarySource)
		{
			return false;
		}

		const DWORD baseCount = *outVertexCount;
		const DWORD stitchedCount = AppendReplayPositionsFromAddress(stitchSource, sourceStride, positionsXyz, baseCount, maxVertices);

		if (outUsedStitch && stitchedCount > baseCount)
		{
			*outUsedStitch = true;
		}

		*outVertexCount = stitchedCount;
		return stitchedCount == maxVertices;
	}

	bool ReadScratchReplayPositions(const TransformSnapshot& transform, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, bool* outUsedStitch)
	{
		if (transform.kind != SourceKindScratchInPlace)
		{
			return false;
		}

		return ReadSegmentedScratchReplayPositions(transform, transform.sourceCurrent, transform.sourceStride, positionsXyz, maxVertices, outVertexCount, outUsedStitch);
	}

	bool ReadIndexedScratchReplayPositions(const TransformSnapshot& transform, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		if (!transform.sourceVertexPointer)
		{
			if (outReason)
			{
				*outReason = "indexed-scratch-unavailable";
			}
			return false;
		}

		bool usedStitch = false;
		if (!ReadSegmentedScratchReplayPositions(transform, transform.sourceVertexPointer, 0x34, positionsXyz, maxVertices, outVertexCount, &usedStitch))
		{
			if (outReason)
			{
				*outReason = *outVertexCount ? "indexed-scratch-position-read-failed" : "indexed-scratch-unavailable";
			}
			return false;
		}

		if (outReason)
		{
			*outReason = nullptr;
		}
		return true;
	}

	bool ReadIndexedOutputScratchReplayPositions(const TransformSnapshot& transform, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		if (transform.kind != SourceKindIndexedEbpEdx)
		{
			if (outReason)
			{
				*outReason = "indexed-output-scratch-unsupported";
			}
			return false;
		}

		const DWORD scratchBase = VaToRuntime(kSourceVertexBufferVa);
		if (!scratchBase)
		{
			if (outReason)
			{
				*outReason = "indexed-output-scratch-unavailable";
			}
			return false;
		}

		DWORD replayBase = scratchBase;
		const DWORD batchVertexCount = transform.batchVertexCount ? transform.batchVertexCount : kScratchBatchVertexCount;
		const DWORD cursorEnd = transform.tlVertexCursor + batchVertexCount;
		if (transform.tlVertexCursor && maxVertices && cursorEnd >= maxVertices)
		{
			replayBase = scratchBase + ((cursorEnd - maxVertices) * 0x34);
		}

		bool usedStitch = false;
		if (!ReadSegmentedScratchReplayPositions(transform, replayBase, 0x34, positionsXyz, maxVertices, outVertexCount, &usedStitch))
		{
			if (outReason)
			{
				*outReason = *outVertexCount ? "indexed-output-scratch-position-read-failed" : "indexed-output-scratch-unavailable";
			}
			return false;
		}

		if (outReason)
		{
			*outReason = nullptr;
		}
		return true;
	}

	bool ReadIndexedReplayPositionsFromIndexBase(const TransformSnapshot& transform, DWORD indexBase, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		if (!positionsXyz || !outVertexCount ||
			!IsIndexedKind(transform.kind) ||
			!transform.sourceBase ||
			!indexBase ||
			transform.sourceStride < 12 ||
			transform.indexStride != 2)
		{
			if (outReason)
			{
				*outReason = "indexed-source-unavailable";
			}
			return false;
		}

		DWORD count = 0;
		for (; count < maxVertices; ++count)
		{
			WORD index = 0;
			const DWORD indexAddress = indexBase + (count * transform.indexStride);
			if (!TryRead(indexAddress, &index))
			{
				if (outReason)
				{
					*outReason = "index-read-failed";
				}
				break;
			}

			float* xyz = &positionsXyz[count * 3];
			const DWORD vertexAddress = transform.sourceBase + (static_cast<DWORD>(index) * transform.sourceStride);
			if (!ReadReplayPosition(vertexAddress, xyz))
			{
				if (outReason)
				{
					*outReason = "position-read-failed";
				}
				break;
			}

			// Guard against adjacent unit-vector streams being mistaken for world positions.
			if (MaxAbs3(xyz[0], xyz[1], xyz[2]) < 4.0f)
			{
				if (outReason)
				{
					*outReason = "indexed-vector-reject";
				}
				break;
			}
		}

		*outVertexCount = count;
		const bool success = count == maxVertices;
		if (success && outReason)
		{
			*outReason = nullptr;
		}
		return success;
	}

	bool ReadIndexedReplayPositions(const TransformSnapshot& transform, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		return ReadIndexedReplayPositionsFromIndexBase(transform, transform.indexBase, positionsXyz, maxVertices, outVertexCount, outReason);
	}

	bool ReadIndexedCursorBaseReplayPositions(const TransformSnapshot& transform, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		if (!transform.tlVertexCursor ||
			!transform.indexBase ||
			transform.indexStride != 2)
		{
			if (outReason)
			{
				*outReason = "indexed-cursor-base-unavailable";
			}
			return false;
		}

		const DWORD cursorBytes = transform.tlVertexCursor * transform.indexStride;
		if (transform.indexBase < cursorBytes)
		{
			if (outReason)
			{
				*outReason = "indexed-cursor-base-underflow";
			}
			return false;
		}

		const DWORD indexBase = transform.indexBase - cursorBytes;
		return ReadIndexedReplayPositionsFromIndexBase(transform, indexBase, positionsXyz, maxVertices, outVertexCount, outReason);
	}

	bool ReadReplayPositions(const TransformSnapshot& transform, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason, const char** outReplaySource, const char** outFallbackReason)
	{
		if (outVertexCount)
		{
			*outVertexCount = 0;
		}
		if (outReason)
		{
			*outReason = nullptr;
		}
		if (outReplaySource)
		{
			*outReplaySource = nullptr;
		}
		if (outFallbackReason)
		{
			*outFallbackReason = nullptr;
		}

		if (!HasNonZeroCamera(transform))
		{
			if (outReason)
			{
				*outReason = "zero-camera";
			}
			return false;
		}

		if (transform.kind == SourceKindScratchInPlace)
		{
			if (!kEnableScratchInPlaceReplay)
			{
				if (outReason)
				{
					*outReason = "scratch-replay-disabled";
				}
				return false;
			}

			bool usedScratchStitch = false;
			if (ReadScratchReplayPositions(transform, positionsXyz, maxVertices, outVertexCount, &usedScratchStitch))
			{
				if (usedScratchStitch && !kEnableScratchReplayStitch)
				{
					if (outReason)
					{
						*outReason = "scratch-stitched-disabled";
					}
					if (outVertexCount)
					{
						*outVertexCount = 0;
					}
					return false;
				}

				if (outReplaySource)
				{
					*outReplaySource = usedScratchStitch ? "scratchStitched" : "scratch";
				}
				return true;
			}

			if (outReason)
			{
				*outReason = *outVertexCount ? "position-read-failed" : "scratch-source-unavailable";
			}
			return false;
		}

		if (IsIndexedKind(transform.kind))
		{
			const char* indexedReason = nullptr;
			const char* indexedScratchReason = nullptr;
			if (kEnableRawIndexedReplay &&
				ReadIndexedReplayPositions(transform, positionsXyz, maxVertices, outVertexCount, &indexedReason))
			{
				if (outReplaySource)
				{
					*outReplaySource = "indexed";
				}
				return true;
			}
			else if (!kEnableRawIndexedReplay)
			{
				indexedReason = "indexed-raw-disabled";
			}

			if (kEnableIndexedOutputScratchReplay &&
				transform.kind == SourceKindIndexedEbpEdx)
			{
				const char* outputScratchReason = nullptr;
				if (ReadIndexedOutputScratchReplayPositions(transform, positionsXyz, maxVertices, outVertexCount, &outputScratchReason))
				{
					if (outReplaySource)
					{
						*outReplaySource = "indexedOutputScratch";
					}
					return true;
				}
				if (outputScratchReason)
				{
					indexedReason = outputScratchReason;
				}
			}

			if (kEnableIndexedCursorBaseReplay &&
				transform.kind == SourceKindIndexedEbpEdx)
			{
				const char* cursorBaseReason = nullptr;
				if (ReadIndexedCursorBaseReplayPositions(transform, positionsXyz, maxVertices, outVertexCount, &cursorBaseReason))
				{
					if (outReplaySource)
					{
						*outReplaySource = "indexedCursorBase";
					}
					return true;
				}
				if (cursorBaseReason)
				{
					indexedReason = cursorBaseReason;
				}
			}

			if (kEnableIndexedScratchFallback &&
				ReadIndexedScratchReplayPositions(transform, positionsXyz, maxVertices, outVertexCount, &indexedScratchReason))
			{
				if (outReplaySource)
				{
					*outReplaySource = "indexedScratch";
				}
				return true;
			}
			else if (!kEnableIndexedScratchFallback)
			{
				indexedScratchReason = "indexed-scratch-disabled";
			}

			if (outReason)
			{
				*outReason = indexedReason ? indexedReason : "indexed-source-unavailable";
			}
			if (outFallbackReason)
			{
				*outFallbackReason = indexedScratchReason;
			}
			return false;
		}

		if (outReason)
		{
			*outReason = "unsupported-kind";
		}
		return false;
	}

	DWORD AlignReplayVertexCountForPrimitive(DWORD primitiveType, DWORD vertexCount)
	{
		switch (primitiveType)
		{
		case 1: // D3DPT_POINTLIST
			return vertexCount;
		case 2: // D3DPT_LINELIST
			return (vertexCount / 2) * 2;
		case 3: // D3DPT_LINESTRIP
			return vertexCount >= 2 ? vertexCount : 0;
		case 4: // D3DPT_TRIANGLELIST
			return (vertexCount / 3) * 3;
		case 5: // D3DPT_TRIANGLESTRIP
		case 6: // D3DPT_TRIANGLEFAN
			return vertexCount >= 3 ? vertexCount : 0;
		default:
			return vertexCount;
		}
	}

	bool ComputeReplayGeometryStats(const float* positionsXyz, DWORD vertexCount, ReplayGeometryStats* outStats)
	{
		if (!positionsXyz || !vertexCount || !outStats)
		{
			return false;
		}

		ReplayGeometryStats stats = {};
		stats.min = { positionsXyz[0], positionsXyz[1], positionsXyz[2] };
		stats.max = stats.min;
		Vec3 sum = {};

		for (DWORD i = 0; i < vertexCount; ++i)
		{
			const float* xyz = &positionsXyz[i * 3];
			if (!IsUsableFloat(xyz[0]) || !IsUsableFloat(xyz[1]) || !IsUsableFloat(xyz[2]))
			{
				return false;
			}

			if (xyz[0] < stats.min.x) stats.min.x = xyz[0];
			if (xyz[1] < stats.min.y) stats.min.y = xyz[1];
			if (xyz[2] < stats.min.z) stats.min.z = xyz[2];
			if (xyz[0] > stats.max.x) stats.max.x = xyz[0];
			if (xyz[1] > stats.max.y) stats.max.y = xyz[1];
			if (xyz[2] > stats.max.z) stats.max.z = xyz[2];
			sum.x += xyz[0];
			sum.y += xyz[1];
			sum.z += xyz[2];
		}

		const float invCount = 1.0f / static_cast<float>(vertexCount);
		stats.center = { sum.x * invCount, sum.y * invCount, sum.z * invCount };
		stats.valid = true;
		*outStats = stats;
		return true;
	}

	bool ValidateReplayGeometry(DWORD primitiveType, const float* positionsXyz, DWORD vertexCount, const char** outReason, float* outMaxEdge)
	{
		if (outReason)
		{
			*outReason = nullptr;
		}
		if (outMaxEdge)
		{
			*outMaxEdge = 0.0f;
		}

		if (!positionsXyz || !vertexCount)
		{
			if (outReason)
			{
				*outReason = "replay-empty";
			}
			return false;
		}

		for (DWORD i = 0; i < vertexCount; ++i)
		{
			const float* xyz = &positionsXyz[i * 3];
			if (!IsUsableFloat(xyz[0]) || !IsUsableFloat(xyz[1]) || !IsUsableFloat(xyz[2]))
			{
				if (outReason)
				{
					*outReason = "replay-invalid-float";
				}
				return false;
			}
		}

		if (primitiveType != 4)
		{
			return true;
		}

		const float maxEdgeSq = kMaxReplayTriangleEdgeLength * kMaxReplayTriangleEdgeLength;
		float largestEdgeSq = 0.0f;
		for (DWORD i = 0; i + 2 < vertexCount; i += 3)
		{
			const float* v0 = &positionsXyz[(i + 0) * 3];
			const float* v1 = &positionsXyz[(i + 1) * 3];
			const float* v2 = &positionsXyz[(i + 2) * 3];
			const float e01 = DistanceSq(v0, v1);
			const float e12 = DistanceSq(v1, v2);
			const float e20 = DistanceSq(v2, v0);
			float triangleMax = e01 > e12 ? e01 : e12;
			triangleMax = triangleMax > e20 ? triangleMax : e20;
			largestEdgeSq = largestEdgeSq > triangleMax ? largestEdgeSq : triangleMax;
			if (!IsUsableFloat(triangleMax) || triangleMax > maxEdgeSq)
			{
				if (outMaxEdge)
				{
					*outMaxEdge = std::sqrt(triangleMax);
				}
				if (outReason)
				{
					*outReason = "triangle-edge-too-large";
				}
				return false;
			}
		}

		if (outMaxEdge)
		{
			*outMaxEdge = std::sqrt(largestEdgeSq);
		}
		return true;
	}

	bool TryConsumeAccumulatedScratchReplay(const PreSubmitSnapshot& preSubmit, DWORD vertexCount, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		if (outVertexCount)
		{
			*outVertexCount = 0;
		}
		if (outReason)
		{
			*outReason = nullptr;
		}

		if (!positionsXyz || !outVertexCount || !vertexCount || maxVertices < vertexCount)
		{
			if (outReason)
			{
				*outReason = "scratch-accum-invalid-args";
			}
			return false;
		}

		if (!g_scratchReplay.valid || g_scratchReplay.threadId != preSubmit.threadId)
		{
			if (outReason)
			{
				*outReason = "scratch-accum-unavailable";
			}
			return false;
		}

		if (preSubmit.site && g_scratchReplay.lastPreSubmitSite && preSubmit.site != g_scratchReplay.lastPreSubmitSite)
		{
			if (outReason)
			{
				*outReason = "scratch-accum-site-mismatch";
			}
			return false;
		}

		if (!HasNonZeroCamera(g_scratchReplay.latestTransform))
		{
			if (outReason)
			{
				*outReason = "zero-camera";
			}
			ResetScratchReplayAccumulator(preSubmit.threadId);
			return false;
		}

		if (g_scratchReplay.vertexCount != vertexCount)
		{
			*outVertexCount = g_scratchReplay.vertexCount;
			if (outReason)
			{
				*outReason = "scratch-accum-count-mismatch";
			}
			LOG_LIMIT(400, "[DarkenedSkye-Bridge] scratch-accum-mismatch"
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
				" requestedVertices=" << vertexCount <<
				" haveVertices=" << g_scratchReplay.vertexCount <<
				" lastPreSubmit=" << FormatSkyeAddress(VaToRuntime(g_scratchReplay.lastPreSubmitSite)) <<
				" lastTransform=" << FormatSkyeAddress(VaToRuntime(g_scratchReplay.latestTransform.site)));
			ResetScratchReplayAccumulator(preSubmit.threadId);
			return false;
		}

		std::memcpy(positionsXyz, g_scratchReplay.positions, static_cast<size_t>(vertexCount) * 3 * sizeof(float));
		*outVertexCount = vertexCount;
		LOG_LIMIT(800, "[DarkenedSkye-Bridge] scratch-accum-consume"
			" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
			" vertices=" << vertexCount <<
			" lastTransform=" << FormatSkyeAddress(VaToRuntime(g_scratchReplay.latestTransform.site)) <<
			" lastSerial=" << g_scratchReplay.lastTransformSerial <<
			" lastTick=" << g_scratchReplay.lastTick);
		ResetScratchReplayAccumulator(preSubmit.threadId);
		return true;
	}

	bool TryConsumeAccumulatedIndexedReplay(const PreSubmitSnapshot& preSubmit, DWORD vertexCount, float* positionsXyz, DWORD maxVertices, DWORD* outVertexCount, const char** outReason)
	{
		if (outVertexCount)
		{
			*outVertexCount = 0;
		}
		if (outReason)
		{
			*outReason = nullptr;
		}

		if (!positionsXyz || !outVertexCount || !vertexCount || maxVertices < vertexCount)
		{
			if (outReason)
			{
				*outReason = "indexed-accum-invalid-args";
			}
			return false;
		}

		if (!g_indexedReplay.valid || g_indexedReplay.threadId != preSubmit.threadId)
		{
			if (outReason)
			{
				*outReason = "indexed-accum-unavailable";
			}
			NoteIndexedDiagEvent(IndexedDiagConsumeUnavailable, preSubmit.site, preSubmit.transform.site, preSubmit.transform.kind);
			return false;
		}

		if (preSubmit.site && g_indexedReplay.lastPreSubmitSite && preSubmit.site != g_indexedReplay.lastPreSubmitSite)
		{
			if (outReason)
			{
				*outReason = "indexed-accum-site-mismatch";
			}
			NoteIndexedDiagEvent(IndexedDiagConsumeSiteMismatch, preSubmit.site, g_indexedReplay.latestTransform.site, g_indexedReplay.latestTransform.kind);
			return false;
		}

		if (!HasNonZeroCamera(g_indexedReplay.latestTransform))
		{
			if (outReason)
			{
				*outReason = "zero-camera";
			}
			NoteIndexedDiagEvent(IndexedDiagConsumeZeroCamera, preSubmit.site, g_indexedReplay.latestTransform.site, g_indexedReplay.latestTransform.kind);
			ResetIndexedReplayAccumulator(preSubmit.threadId);
			return false;
		}

		if (g_indexedReplay.vertexCount != vertexCount)
		{
			*outVertexCount = g_indexedReplay.vertexCount;
			if (outReason)
			{
				*outReason = "indexed-accum-count-mismatch";
			}
			LOG_LIMIT(400, "[DarkenedSkye-Bridge] indexed-accum-mismatch"
				" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
				" requestedVertices=" << vertexCount <<
				" haveVertices=" << g_indexedReplay.vertexCount <<
				" lastPreSubmit=" << FormatSkyeAddress(VaToRuntime(g_indexedReplay.lastPreSubmitSite)) <<
				" lastTransform=" << FormatSkyeAddress(VaToRuntime(g_indexedReplay.latestTransform.site)) <<
				" kind=" << KindName(g_indexedReplay.latestTransform.kind));
			if (preSubmit.site == 0x0044E69C ||
				preSubmit.transform.kind == SourceKindIndexedEbpEdx ||
				g_indexedReplay.latestTransform.kind == SourceKindIndexedEbpEdx)
			{
				LOG_LIMIT(400, "[DarkenedSkye-Bridge] indexed-accum-mismatch-detail"
					" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
					" requestedVertices=" << vertexCount <<
					" currentValid=" << g_indexedReplay.valid <<
					" currentVertices=" << g_indexedReplay.vertexCount <<
					" currentCursorBase=" << g_indexedReplay.cursorBase <<
					" currentLastPreSubmit=" << FormatSkyeAddress(VaToRuntime(g_indexedReplay.lastPreSubmitSite)) <<
					" currentLastTransform=" << FormatSkyeAddress(VaToRuntime(g_indexedReplay.latestTransform.site)) <<
					" currentKind=" << KindName(g_indexedReplay.latestTransform.kind) <<
					" currentLastSerial=" << g_indexedReplay.lastTransformSerial <<
					" currentLastTick=" << g_indexedReplay.lastTick <<
					" submitReplayValid=" << preSubmit.indexedReplayValidAtSubmit <<
					" submitReplayVertices=" << preSubmit.indexedReplayVertexCountAtSubmit <<
					" submitReplayCursorBase=" << preSubmit.indexedReplayCursorBaseAtSubmit <<
					" submitReplayLastPreSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.indexedReplayLastPreSubmitSiteAtSubmit)) <<
					" submitReplayLastTransform=" << FormatSkyeAddress(VaToRuntime(preSubmit.indexedReplayLatestTransformSiteAtSubmit)) <<
					" submitReplayKind=" << KindName(preSubmit.indexedReplayLatestTransformKindAtSubmit) <<
					" submitReplayLastSerial=" << preSubmit.indexedReplayLastTransformSerialAtSubmit <<
					" submitReplayLastTick=" << preSubmit.indexedReplayLastTickAtSubmit <<
					" selectedTransform=" << FormatSkyeAddress(VaToRuntime(preSubmit.transform.site)) <<
					" selectedKind=" << KindName(preSubmit.transform.kind) <<
					" selectedSerial=" << preSubmit.transform.serial <<
					" selectedCursor=" << preSubmit.transform.tlVertexCursor <<
					" selectedSource=" << FormatSkyeAddress(preSubmit.transform.sourceBase) <<
					" selectedIndex=" << FormatSkyeAddress(preSubmit.transform.indexBase) <<
					" selectedSourceCount=" << preSubmit.transform.sourceVertexCount <<
					" selectedBatch=" << preSubmit.transform.batchVertexCount);
			}
			NoteIndexedDiagEvent(IndexedDiagConsumeCountMismatch, preSubmit.site, g_indexedReplay.latestTransform.site, g_indexedReplay.latestTransform.kind);
			return false;
		}

		std::memcpy(positionsXyz, g_indexedReplay.positions, static_cast<size_t>(vertexCount) * 3 * sizeof(float));
		*outVertexCount = vertexCount;
		LOG_LIMIT(800, "[DarkenedSkye-Bridge] indexed-accum-consume"
			" preSubmit=" << FormatSkyeAddress(VaToRuntime(preSubmit.site)) <<
			" vertices=" << vertexCount <<
			" lastTransform=" << FormatSkyeAddress(VaToRuntime(g_indexedReplay.latestTransform.site)) <<
			" kind=" << KindName(g_indexedReplay.latestTransform.kind) <<
			" lastSerial=" << g_indexedReplay.lastTransformSerial <<
			" lastTick=" << g_indexedReplay.lastTick);
		NoteIndexedDiagEvent(IndexedDiagConsumeOk, preSubmit.site, g_indexedReplay.latestTransform.site, g_indexedReplay.latestTransform.kind);
		ResetIndexedReplayAccumulator(preSubmit.threadId);
		return true;
	}
}

bool DarkenedSkyeBridge::GetLatestCameraState(CameraState* state)
{
	if (!state || !g_latestTransform.valid)
	{
		return false;
	}

	TransformSnapshot snapshot = g_latestTransform;
	if (!snapshot.valid)
	{
		return false;
	}

	CameraState result = {};
	result.serial = snapshot.serial;
	result.site = snapshot.site;
	result.kind = snapshot.kind;

	bool anyCamera = false;
	for (DWORD i = 0; i < ARRAYSIZE(result.camera); ++i)
	{
		result.camera[i] = BitsToFloat(snapshot.camera[i]);
		anyCamera = anyCamera || !IsNearlyZero(result.camera[i]);
		if (!IsUsableFloat(result.camera[i]))
		{
			return false;
		}
	}

	float nativeMatrix[kMatrixFloatCount] = {};
	bool anyMatrix = false;
	for (DWORD i = 0; i < ARRAYSIZE(nativeMatrix); ++i)
	{
		nativeMatrix[i] = BitsToFloat(snapshot.matrix[i]);
		anyMatrix = anyMatrix || !IsNearlyZero(nativeMatrix[i]);
		if (!IsUsableFloat(nativeMatrix[i]))
		{
			return false;
		}
	}

	if (!anyMatrix || !BuildViewFromNativeMatrix(nativeMatrix, result.camera, anyCamera, result.view))
	{
		return false;
	}

	result.projectionScale = BitsToFloat(snapshot.projectionScale);
	result.projectionCenterX = BitsToFloat(snapshot.projectionCenterX);
	result.projectionCenterY = BitsToFloat(snapshot.projectionCenterY);
	result.projectionNear = BitsToFloat(snapshot.projectionNear);
	if (!IsUsableFloat(result.projectionScale) ||
		!IsUsableFloat(result.projectionCenterX) ||
		!IsUsableFloat(result.projectionCenterY) ||
		!IsUsableFloat(result.projectionNear))
	{
		return false;
	}

	*state = result;
	return true;
}

bool DarkenedSkyeBridge::CaptureDrawPrimitiveReplayPositions(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, const void* Caller, float* PositionsXyz, DWORD MaxVertices, DWORD* OutVertexCount)
{
	MaybeInstall();

	if (OutVertexCount)
	{
		*OutVertexCount = 0;
	}

	PreSubmitSnapshot preSubmit = {};
	if (!ConsumePairedSnapshot("DrawPrimitiveVB", PrimitiveType, FVF, VertexCount, 0, Caller, &preSubmit))
	{
		return false;
	}

	LogDrawPair("DrawPrimitiveVB", PrimitiveType, FVF, StartVertex, VertexCount, 0, Caller, preSubmit);

	if (!PositionsXyz || !OutVertexCount || !VertexCount || MaxVertices < VertexCount)
	{
		return false;
	}

	const TransformSnapshot& transform = preSubmit.transform;
	const char* replaySkipReason = nullptr;
	const char* replaySource = nullptr;
	const char* replayFallbackSkipReason = nullptr;
	bool replayReadSucceeded = false;
	if (transform.kind == SourceKindScratchInPlace &&
		Config.DdrawDarkenedSkyeReplayDisableScratch)
	{
		replaySkipReason = "scratch-replay-disabled-by-config";
		ResetScratchReplayAccumulator(preSubmit.threadId);
	}
	else if (transform.kind == SourceKindScratchInPlace &&
		Config.DdrawDarkenedSkyeReplayMaxScratchVertices &&
		VertexCount > Config.DdrawDarkenedSkyeReplayMaxScratchVertices)
	{
		replaySkipReason = "scratch-accum-over-max-vertices";
		ResetScratchReplayAccumulator(preSubmit.threadId);
	}
	else if (transform.kind == SourceKindScratchInPlace &&
		g_scratchReplay.valid &&
		g_scratchReplay.threadId == preSubmit.threadId &&
		(!preSubmit.site || !g_scratchReplay.lastPreSubmitSite || preSubmit.site == g_scratchReplay.lastPreSubmitSite))
	{
		replayReadSucceeded = TryConsumeAccumulatedScratchReplay(preSubmit, VertexCount, PositionsXyz, MaxVertices, OutVertexCount, &replaySkipReason);
		if (replayReadSucceeded)
		{
			replaySource = "scratchAccumulated";
		}
	}
	else if (IsIndexedKind(transform.kind) &&
		(Config.DdrawDarkenedSkyeReplayDisableIndexed ||
			(Config.DdrawDarkenedSkyeReplayDisableIndexedEbpEdx && transform.kind == SourceKindIndexedEbpEdx)))
	{
		replaySkipReason = Config.DdrawDarkenedSkyeReplayDisableIndexed ? "indexed-replay-disabled-by-config" : "indexed-ebpedx-disabled-by-config";
		ResetIndexedReplayAccumulator(preSubmit.threadId);
	}
	else if (transform.kind != SourceKindScratchInPlace)
	{
		if (g_scratchReplay.valid && g_scratchReplay.threadId == preSubmit.threadId)
		{
			ResetScratchReplayAccumulator(preSubmit.threadId);
		}
		if (IsIndexedKind(transform.kind) &&
			g_indexedReplay.valid &&
			g_indexedReplay.threadId == preSubmit.threadId)
		{
			replayReadSucceeded = TryConsumeAccumulatedIndexedReplay(preSubmit, VertexCount, PositionsXyz, MaxVertices, OutVertexCount, &replaySkipReason);
			if (replayReadSucceeded)
			{
				replaySource = "indexedAccumulated";
			}
		}

		if (!replayReadSucceeded)
		{
			replayReadSucceeded = ReadReplayPositions(transform, PositionsXyz, VertexCount, OutVertexCount, &replaySkipReason, &replaySource, &replayFallbackSkipReason);
		}
	}
	else
	{
		replaySkipReason = "scratch-accum-unavailable";
	}

	if (!replayReadSucceeded)
	{
		bool allowPartialReplay = false;
		const bool partialAllowedForKind = IsIndexedKind(transform.kind);
		if (partialAllowedForKind && replaySkipReason && std::strcmp(replaySkipReason, "position-read-failed") == 0 && *OutVertexCount)
		{
			const DWORD alignedVertexCount = AlignReplayVertexCountForPrimitive(PrimitiveType, *OutVertexCount);
			const bool hasMinimumGeometry = alignedVertexCount >= 96;
			const bool hasUsefulCoverage = (alignedVertexCount * 100) >= (VertexCount * 35);
			if (alignedVertexCount && alignedVertexCount < VertexCount && hasMinimumGeometry && hasUsefulCoverage)
			{
				allowPartialReplay = true;
				*OutVertexCount = alignedVertexCount;
				replaySource = "partial";

				LOG_LIMIT(400, "[DarkenedSkye-Bridge] replay-partial"
					" reason=" << replaySkipReason <<
					" fallbackReason=" << (replayFallbackSkipReason ? replayFallbackSkipReason : "none") <<
					" primitive=" << PrimitiveType <<
					" fvf=" << Logging::hex(FVF) <<
					" requestedVertices=" << VertexCount <<
					" replayVertices=" << *OutVertexCount <<
					" kind=" << KindName(transform.kind) <<
					" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
					" sourceCurrent=" << FormatSkyeAddress(transform.sourceCurrent) <<
					" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
					" sourceStride=" << transform.sourceStride <<
					" indexStride=" << transform.indexStride);
			}
		}

		if (allowPartialReplay)
		{
			if (!kEnableIndexedPartialReplay)
			{
				allowPartialReplay = false;
				replaySkipReason = "partial-replay-disabled";
			}
		}

		if (allowPartialReplay)
		{
			LOG_LIMIT(1000, "[DarkenedSkye-Bridge] replay-positions"
				" primitive=" << PrimitiveType <<
				" fvf=" << Logging::hex(FVF) <<
				" vertices=" << VertexCount <<
				" kind=" << KindName(transform.kind) <<
				" replaySource=" << (replaySource ? replaySource : "unknown") <<
				" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
				" sourceCurrent=" << FormatSkyeAddress(transform.sourceCurrent) <<
				" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
				" sourceStride=" << transform.sourceStride <<
				" indexStride=" << transform.indexStride <<
				" readVertices=" << *OutVertexCount);
			return true;
		}

		if (replaySkipReason && std::strcmp(replaySkipReason, "zero-camera") == 0)
		{
			LOG_LIMIT(80, "[DarkenedSkye-Bridge] replay-skip"
				" reason=" << replaySkipReason <<
				" fallbackReason=" << (replayFallbackSkipReason ? replayFallbackSkipReason : "none") <<
				" primitive=" << PrimitiveType <<
				" fvf=" << Logging::hex(FVF) <<
				" vertices=" << VertexCount <<
				" kind=" << KindName(transform.kind) <<
				" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
				" sourceCurrent=" << FormatSkyeAddress(transform.sourceCurrent) <<
				" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
				" sourceStride=" << transform.sourceStride <<
				" indexStride=" << transform.indexStride <<
				" readVertices=" << *OutVertexCount);
		}
		else
		{
			LOG_LIMIT(1000, "[DarkenedSkye-Bridge] replay-skip"
				" reason=" << (replaySkipReason ? replaySkipReason : "source-unavailable") <<
				" fallbackReason=" << (replayFallbackSkipReason ? replayFallbackSkipReason : "none") <<
				" primitive=" << PrimitiveType <<
				" fvf=" << Logging::hex(FVF) <<
				" vertices=" << VertexCount <<
				" kind=" << KindName(transform.kind) <<
				" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
				" sourceCurrent=" << FormatSkyeAddress(transform.sourceCurrent) <<
				" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
				" sourceStride=" << transform.sourceStride <<
				" indexStride=" << transform.indexStride <<
				" readVertices=" << *OutVertexCount);
		}
		if (IsIndexedKind(transform.kind))
		{
			NoteIndexedDiagEvent(IndexedDiagReplaySkip, preSubmit.site, transform.site, transform.kind);
		}
		return false;
	}

	const char* validationReason = nullptr;
	float maxReplayEdge = 0.0f;
	if (!ValidateReplayGeometry(PrimitiveType, PositionsXyz, *OutVertexCount, &validationReason, &maxReplayEdge))
	{
		LOG_LIMIT(1000, "[DarkenedSkye-Bridge] replay-skip"
			" reason=" << (validationReason ? validationReason : "replay-validation-failed") <<
			" fallbackReason=none"
			" primitive=" << PrimitiveType <<
			" fvf=" << Logging::hex(FVF) <<
			" vertices=" << VertexCount <<
			" kind=" << KindName(transform.kind) <<
			" replaySource=" << (replaySource ? replaySource : "unknown") <<
			" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
			" sourceCurrent=" << FormatSkyeAddress(transform.sourceCurrent) <<
			" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
			" sourceStride=" << transform.sourceStride <<
			" indexStride=" << transform.indexStride <<
			" readVertices=" << *OutVertexCount <<
			" maxEdge=" << maxReplayEdge);
		if (IsIndexedKind(transform.kind))
		{
			NoteIndexedDiagEvent(IndexedDiagReplaySkip, preSubmit.site, transform.site, transform.kind);
		}
		*OutVertexCount = 0;
		return false;
	}

	ReplayGeometryStats replayStats = {};
	ComputeReplayGeometryStats(PositionsXyz, *OutVertexCount, &replayStats);
	LOG_LIMIT(1000, "[DarkenedSkye-Bridge] replay-positions"
		" primitive=" << PrimitiveType <<
		" fvf=" << Logging::hex(FVF) <<
		" vertices=" << VertexCount <<
		" kind=" << KindName(transform.kind) <<
		" replaySource=" << (replaySource ? replaySource : "unknown") <<
		" sourceBase=" << FormatSkyeAddress(transform.sourceBase) <<
		" sourceCurrent=" << FormatSkyeAddress(transform.sourceCurrent) <<
		" indexBase=" << FormatSkyeAddress(transform.indexBase) <<
		" sourceStride=" << transform.sourceStride <<
		" indexStride=" << transform.indexStride <<
		" readVertices=" << *OutVertexCount <<
		" boundsMin=" << (replayStats.valid ? FormatVec3(replayStats.min) : "(invalid)") <<
		" boundsMax=" << (replayStats.valid ? FormatVec3(replayStats.max) : "(invalid)") <<
		" boundsCenter=" << (replayStats.valid ? FormatVec3(replayStats.center) : "(invalid)") <<
		" maxEdge=" << maxReplayEdge);
	return true;
}

#if defined(_M_IX86)
extern "C" void* g_SkyeBridgeTrampoline42A25F = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42AF0C = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B445 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B66B = nullptr;
extern "C" void* g_SkyeBridgeTrampoline44E5DC = nullptr;
extern "C" void* g_SkyeBridgeTrampoline44E689 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline44E6DA = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42A395 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B042 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B626 = nullptr;
extern "C" void* g_SkyeBridgeTrampoline42B84C = nullptr;
extern "C" void* g_SkyeBridgeTrampoline439BFF = nullptr;
extern "C" void* g_SkyeBridgeTrampoline44E69C = nullptr;
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
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook44E5DC, 0044E5DCh, g_SkyeBridgeTrampoline44E5DC)
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook44E689, 0044E689h, g_SkyeBridgeTrampoline44E689)
SKYE_TRANSFORM_HOOK(SkyeBridge_Hook44E6DA, 0044E6DAh, g_SkyeBridgeTrampoline44E6DA)

SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42A395, 0042A395h, g_SkyeBridgeTrampoline42A395)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42B042, 0042B042h, g_SkyeBridgeTrampoline42B042)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42B626, 0042B626h, g_SkyeBridgeTrampoline42B626)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook42B84C, 0042B84Ch, g_SkyeBridgeTrampoline42B84C)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook439BFF, 00439BFFh, g_SkyeBridgeTrampoline439BFF)
SKYE_PRESUBMIT_HOOK(SkyeBridge_Hook44E69C, 0044E69Ch, g_SkyeBridgeTrampoline44E69C)
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
	static const BYTE k44E689[] = { 0xC7, 0x05, 0x74, 0xDC, 0x4F, 0x00, 0x03, 0x00, 0x00, 0x00 };
	static const BYTE k44E6DA[] = { 0x8B, 0xD6, 0xB9, 0xA8, 0xED, 0x4F, 0x00 };
	static const BYTE kPreSubmit[] = { 0xFF, 0x15, 0xC4, 0xC9, 0x54, 0x00 };

	DWORD installed = 0;
	installed += InstallHook(0x0042A25F, "SkyeTransform42A25F", SkyeBridge_Hook42A25F, &g_SkyeBridgeTrampoline42A25F, k42A25F, sizeof(k42A25F)) ? 1 : 0;
	installed += InstallHook(0x0042AF0C, "SkyeTransform42AF0C", SkyeBridge_Hook42AF0C, &g_SkyeBridgeTrampoline42AF0C, k42AF0C, sizeof(k42AF0C)) ? 1 : 0;
	installed += InstallHook(0x0042B445, "SkyeTransform42B445", SkyeBridge_Hook42B445, &g_SkyeBridgeTrampoline42B445, k42B445, sizeof(k42B445)) ? 1 : 0;
	installed += InstallHook(0x0042B66B, "SkyeTransform42B66B", SkyeBridge_Hook42B66B, &g_SkyeBridgeTrampoline42B66B, k42B66B, sizeof(k42B66B)) ? 1 : 0;
	installed += InstallHook(0x0044E689, "SkyeTransform44E689", SkyeBridge_Hook44E689, &g_SkyeBridgeTrampoline44E689, k44E689, sizeof(k44E689)) ? 1 : 0;
	installed += InstallHook(0x0044E6DA, "SkyeTransform44E6DA", SkyeBridge_Hook44E6DA, &g_SkyeBridgeTrampoline44E6DA, k44E6DA, sizeof(k44E6DA)) ? 1 : 0;

	installed += InstallHook(0x0042A395, "SkyePreSubmit42A395", SkyeBridge_Hook42A395, &g_SkyeBridgeTrampoline42A395, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0042B042, "SkyePreSubmit42B042", SkyeBridge_Hook42B042, &g_SkyeBridgeTrampoline42B042, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0042B626, "SkyePreSubmit42B626", SkyeBridge_Hook42B626, &g_SkyeBridgeTrampoline42B626, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0042B84C, "SkyePreSubmit42B84C", SkyeBridge_Hook42B84C, &g_SkyeBridgeTrampoline42B84C, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x00439BFF, "SkyePreSubmit439BFF", SkyeBridge_Hook439BFF, &g_SkyeBridgeTrampoline439BFF, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
	installed += InstallHook(0x0044E69C, "SkyePreSubmit44E69C", SkyeBridge_Hook44E69C, &g_SkyeBridgeTrampoline44E69C, kPreSubmit, sizeof(kPreSubmit)) ? 1 : 0;
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
	PreSubmitSnapshot preSubmit = {};
	if (ConsumePairedSnapshot("DrawPrimitiveVB", PrimitiveType, FVF, VertexCount, 0, Caller, &preSubmit))
	{
		LogDrawPair("DrawPrimitiveVB", PrimitiveType, FVF, StartVertex, VertexCount, 0, Caller, preSubmit);
	}
}

void DarkenedSkyeBridge::OnDd7to9DrawIndexedPrimitiveVB(DWORD PrimitiveType, DWORD FVF, DWORD StartVertex, DWORD VertexCount, DWORD IndexCount, const void* Caller)
{
	MaybeInstall();
	PreSubmitSnapshot preSubmit = {};
	if (ConsumePairedSnapshot("DrawIndexedPrimitiveVB", PrimitiveType, FVF, VertexCount, IndexCount, Caller, &preSubmit))
	{
		LogDrawPair("DrawIndexedPrimitiveVB", PrimitiveType, FVF, StartVertex, VertexCount, IndexCount, Caller, preSubmit);
	}
}

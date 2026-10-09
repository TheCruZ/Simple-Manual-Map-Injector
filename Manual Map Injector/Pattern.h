#pragma once

/*
* Author: TheCruZ
* Usage:
* Pattern::ScanPatternInExecutableSection(module, "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
* Pattern::ScanPatternInSection(module, ".text", "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
* Pattern::Scan(Start, memLength, "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
*
* Variable-width wildcard: token "[N-M]" (no spaces inside the brackets)
* matches between N and M arbitrary bytes. Example:
*   "44 8D ? 09 [5-24] B2 01 48 8B ? 30 E8"
* The matcher tries lengths N, N+1, ..., M in order and takes the first
* that lets the rest of the pattern match (greedy from the low end).
*
* Backward scan: Pattern::ScanBackward* mirror the forward variants but
* return the HIGHEST address <= End that matches. Useful to walk back
* from a known VA to a function boundary (e.g. CC CC CC int3 padding).
*/

#ifndef PATTERNSC_H
#define PATTERNSC_H

#ifndef _KERNEL_MODE
#include <Windows.h>
#include <vector>
#include <sstream>
#include <string>
#else
#include <ntdef.h>
#include <ntimage.h>
#endif

//comment this line to remove memory checking (usefull if you don't want to call VirtualQueryEx)
#define CHECK_VALID_MEMORY

struct Pattern
{

	// Compiled pattern token: either a literal/wildcard byte, or a
	// variable-width wildcard range of [minSkip, maxSkip] bytes.
	struct sTok
	{
		enum Kind : unsigned char { Byte = 0, Range = 1 };

		Kind          kind;
		bool          wildcard; // only valid when kind == Byte
		unsigned char data;     // only valid when kind == Byte
		unsigned int  minSkip;  // only valid when kind == Range
		unsigned int  maxSkip;  // only valid when kind == Range

		sTok() : kind(Byte), wildcard(true), data(0), minSkip(0), maxSkip(0) {}

		static sTok MakeByte(unsigned char b) {
			sTok t;
			t.kind = Byte; t.wildcard = false; t.data = b;
			return t;
		}
		static sTok MakeWildcard() {
			sTok t;
			t.kind = Byte; t.wildcard = true; t.data = 0;
			return t;
		}
		static sTok MakeRange(unsigned int lo, unsigned int hi) {
			sTok t;
			t.kind = Range; t.minSkip = lo; t.maxSkip = hi;
			return t;
		}
	};

#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY

	struct ValidationResult {
		bool valid;
		DWORD64 endOfThisSection;
	};

	static ValidationResult isMemoryValid(void* ptr, size_t size) {

		MEMORY_BASIC_INFORMATION meminfo = { 0 };
		auto ret = VirtualQueryEx(GetCurrentProcess(), ptr, &meminfo, sizeof(meminfo));

		auto regionEnd = ((DWORD64)meminfo.BaseAddress) + meminfo.RegionSize;
		auto checkRangeEnd = ((DWORD64)ptr) + size;

		if (ret <= 0)
			return { false, regionEnd };

		if ((meminfo.State & MEM_COMMIT) == 0)
			return { false, regionEnd };

		if ((meminfo.AllocationProtect & PAGE_GUARD) != 0)
			return { false, regionEnd };

		if ((meminfo.Protect & PAGE_GUARD) != 0)
			return { false, regionEnd };

		if ((meminfo.Protect & PAGE_EXECUTE_READ) == 0 && //VALID PAGES
			(meminfo.Protect & PAGE_EXECUTE_READWRITE) == 0 &&
			(meminfo.Protect & PAGE_READONLY) == 0 &&
			(meminfo.Protect & PAGE_READWRITE) == 0 &&
			(meminfo.Protect & PAGE_EXECUTE_WRITECOPY) == 0 &&
			(meminfo.Protect & PAGE_WRITECOPY) == 0
			)
			return { false, regionEnd };

		if (regionEnd < checkRangeEnd) {

			auto newsize = checkRangeEnd - regionEnd;

			return isMemoryValid((void*)(regionEnd), newsize);
		}

		return { true, regionEnd };
	}
#endif
#endif

	//Always usefull
	static PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
		return ResolvedAddr;
	}

private:
	static unsigned char hexCharToU8(char c) {
		if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
		if (c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
		if (c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
		return 0;
	}

	static unsigned char hexByteToU8(const char* s) {
		return (unsigned char)((hexCharToU8(s[0]) << 4) | hexCharToU8(s[1]));
	}

	static bool isHex(char c) {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	}

	// Parse a decimal unsigned integer starting at &str[i], advancing i.
	// Returns true on success. On failure i is left where it couldn't parse.
	static bool parseDecimal(const char* str, size_t& i, size_t len, unsigned int& out) {
		if (i >= len || str[i] < '0' || str[i] > '9') return false;
		unsigned int v = 0;
		while (i < len && str[i] >= '0' && str[i] <= '9') {
			v = v * 10 + (unsigned int)(str[i] - '0');
			++i;
		}
		out = v;
		return true;
	}

	// Compile the textual pattern to a sequence of tokens.
	// Supports:
	//   "AA"           - byte literal (two hex chars). Spaces optional.
	//   "?" or "??"    - single wildcard byte
	//   "[N-M]"        - variable-width wildcard (N..M bytes, N<=M)
	// Returns 0 on parse error; otherwise writes `outCount` tokens
	// into `outTokens`. `maxTokens` caps the output buffer.
	static size_t compile(const char* pattern, sTok* outTokens, size_t maxTokens) {
#ifndef _KERNEL_MODE
		size_t plen = strlen(pattern);
#else
		size_t plen = 0; while (pattern[plen]) ++plen;
#endif
		size_t n = 0;
		size_t i = 0;
		while (i < plen) {
			char c = pattern[i];
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }
			if (n >= maxTokens) return 0;

			if (c == '?') {
				outTokens[n++] = sTok::MakeWildcard();
				// swallow a trailing '?' so "??" == "?"
				if (i + 1 < plen && pattern[i + 1] == '?') i += 2;
				else ++i;
				continue;
			}
			if (c == '[') {
				// [N-M]
				size_t j = i + 1;
				unsigned int lo = 0, hi = 0;
				if (!parseDecimal(pattern, j, plen, lo)) return 0;
				if (j >= plen || pattern[j] != '-') return 0;
				++j;
				if (!parseDecimal(pattern, j, plen, hi)) return 0;
				if (j >= plen || pattern[j] != ']') return 0;
				if (lo > hi) return 0;
				outTokens[n++] = sTok::MakeRange(lo, hi);
				i = j + 1;
				continue;
			}
			if (i + 1 < plen && isHex(c) && isHex(pattern[i + 1])) {
				outTokens[n++] = sTok::MakeByte(hexByteToU8(&pattern[i]));
				i += 2;
				continue;
			}
			return 0; // garbage
		}
		return n;
	}

	// Compute the minimum/maximum possible length (in bytes) that the
	// compiled pattern can match. Needed to bound the forward loop.
	static void patternSize(const sTok* toks, size_t n, size_t& outMin, size_t& outMax) {
		outMin = 0; outMax = 0;
		for (size_t k = 0; k < n; ++k) {
			if (toks[k].kind == sTok::Range) {
				outMin += toks[k].minSkip;
				outMax += toks[k].maxSkip;
			} else {
				outMin += 1;
				outMax += 1;
			}
		}
	}

	// Match the compiled pattern starting at `data[pos]`, length `len`.
	// Returns true on match. Handles variable-width ranges with greedy
	// low-to-high backtracking.
	static bool matchAt(const unsigned char* data, size_t len,
		const sTok* toks, size_t tokCount) {

		return matchFrom(data, len, 0, toks, tokCount, 0);
	}

	static bool matchFrom(const unsigned char* data, size_t len,
		size_t pos, const sTok* toks, size_t tokCount, size_t t) {

		while (t < tokCount) {
			const sTok& tk = toks[t];
			if (tk.kind == sTok::Range) {
				// Try minSkip..maxSkip, lowest first.
				for (unsigned int skip = tk.minSkip; skip <= tk.maxSkip; ++skip) {
					if (pos + skip > len) break;
					if (matchFrom(data, len, pos + skip, toks, tokCount, t + 1))
						return true;
				}
				return false;
			}
			// Byte or single wildcard
			if (pos >= len) return false;
			if (!tk.wildcard && data[pos] != tk.data) return false;
			++pos;
			++t;
		}
		return true;
	}

public:

	/*
	* Pattern format wilcard must be "??" or "?" or "?? ?? ??" or "? ? ??" But never "???" for 3 bytes
	* Pattern format: "AA BB CC DD EE ?? FF GG HH"
	* Pattern format alternative: "AABBCCDDEEFF??FFGGHH"
	* Pattern format alternative2: "AA BB CC DD EE ? ? FF GG HH"
	* Pattern format Not supported: "AA BB CC DD EE ???? FF GG HH"
	* Pattern format Not supported: "AABBCCDDEEFF???FFGGHH"
	* Variable-width wildcard: "AA BB [5-24] CC DD"
	* SkipCount if pattern is found and skip is >0 then skip to next pattern
	*/
	static DWORD64 Scan(DWORD64 dwStart, size_t dwLength, const char* pattern, size_t skipCount = 0) {

#ifndef _KERNEL_MODE
		std::vector<sTok> bufv; bufv.resize(512);
		sTok* buf = bufv.data();
		size_t tokCount = compile(pattern, buf, bufv.size());
#else
		sTok buf[256]{};
		size_t tokCount = compile(pattern, buf, 256);
#endif
		if (tokCount == 0) return 0;

		size_t minLen = 0, maxLen = 0;
		patternSize(buf, tokCount, minLen, maxLen);
		if (minLen == 0 || minLen > dwLength) return 0;

#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY
		auto vCheck = isMemoryValid((void*)dwStart, minLen);
#endif
#endif
		const size_t lastPossibleStart = dwLength - minLen;
		for (DWORD64 i = 0; i <= lastPossibleStart; i++) {
			UINT8* lpCurrentByte = (UINT8*)(dwStart + i);
#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY
			if ((DWORD64)lpCurrentByte + minLen > vCheck.endOfThisSection || !vCheck.valid) {
				vCheck = isMemoryValid(lpCurrentByte, minLen);
				if (!vCheck.valid) {
					i += vCheck.endOfThisSection - (DWORD64)lpCurrentByte; //skip page
					--i; // i will be increased in continue
					continue;
				}
			}
#endif
#endif
			size_t remaining = dwLength - (size_t)i;
			if (matchAt(lpCurrentByte, remaining, buf, tokCount)) {
				if (skipCount == 0) return (DWORD64)lpCurrentByte;
				--skipCount;
			}
		}
		return 0;
	}

	/*
	* Backward counterpart of Scan: returns the HIGHEST address in
	* [dwStart, dwStart + dwLength) at which the pattern matches, or 0.
	* skipCount skips N matches starting from the highest.
	*/
	static DWORD64 ScanBackward(DWORD64 dwStart, size_t dwLength, const char* pattern, size_t skipCount = 0) {

#ifndef _KERNEL_MODE
		std::vector<sTok> bufv; bufv.resize(512);
		sTok* buf = bufv.data();
		size_t tokCount = compile(pattern, buf, bufv.size());
#else
		sTok buf[256]{};
		size_t tokCount = compile(pattern, buf, 256);
#endif
		if (tokCount == 0) return 0;

		size_t minLen = 0, maxLen = 0;
		patternSize(buf, tokCount, minLen, maxLen);
		if (minLen == 0 || minLen > dwLength) return 0;

#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY
		// Validate the whole range up front: callers of ScanBackward
		// typically pass a window they already know is committed
		// (e.g. a `.text` section or a bounded walk-back from a hit),
		// so a single validation is enough and avoids re-querying for
		// every candidate position.
		auto vCheck = isMemoryValid((void*)dwStart, dwLength);
		if (!vCheck.valid) return 0;
#endif
#endif
		DWORD64 i = (DWORD64)(dwLength - minLen);
		while (true) {
			UINT8* lpCurrentByte = (UINT8*)(dwStart + i);
			size_t remaining = (size_t)(dwLength - i);
			if (matchAt(lpCurrentByte, remaining, buf, tokCount)) {
				if (skipCount == 0) return (DWORD64)lpCurrentByte;
				--skipCount;
			}
			if (i == 0) break;
			--i;
		}
		return 0;
	}

	static PIMAGE_SECTION_HEADER GetSectionByName(const void* module, const char* sectionName) {
		auto dosHeader = (PIMAGE_DOS_HEADER)module;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((DWORD64)dosHeader + dosHeader->e_lfanew);
		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
		auto searchlen = strlen(sectionName);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (searchlen == 8 && memcmp(sectionHeader->Name, sectionName, searchlen) == 0) {
				return sectionHeader;
			}
			else if (strcmp((char*)sectionHeader->Name, sectionName) == 0) {
				return sectionHeader;
			}
			sectionHeader++;
		}
		return 0;
	}

	/*
	* Pattern format wilcard must be "??" or "?" or "?? ?? ??" or "? ? ??" But never "???" for 3 bytes
	* Pattern format: "AA BB CC DD EE ?? FF GG HH"
	* Pattern format alternative: "AABBCCDDEEFF??FFGGHH"
	* Pattern format alternative2: "AA BB CC DD EE ? ? FF GG HH"
	* Pattern format Not supported: "AA BB CC DD EE ???? FF GG HH"
	* Pattern format Not supported: "AABBCCDDEEFF???FFGGHH"
	* Variable-width wildcard: "AA BB [5-24] CC DD"
	* SkipCount if pattern is found and skip is >0 then skip to next pattern
	*/
	static DWORD64 ScanPatternInSection(const void* module, const char* sectionName, const char* pattern, size_t skipCount = 0) {
		auto section = GetSectionByName(module, sectionName);
		if (!section)
			return 0;
		auto sectionSize = section->Misc.VirtualSize;
		auto sectionAddress = (DWORD64)section->VirtualAddress + (DWORD64)module;
		return Scan(sectionAddress, sectionSize, pattern, skipCount);
	}

	static DWORD64 ScanBackwardInSection(const void* module, const char* sectionName, const char* pattern, size_t skipCount = 0) {
		auto section = GetSectionByName(module, sectionName);
		if (!section)
			return 0;
		auto sectionSize = section->Misc.VirtualSize;
		auto sectionAddress = (DWORD64)section->VirtualAddress + (DWORD64)module;
		return ScanBackward(sectionAddress, sectionSize, pattern, skipCount);
	}

	/*
	* Pattern format wilcard must be "??" or "?" or "?? ?? ??" or "? ? ??" But never "???" for 3 bytes
	* Pattern format: "AA BB CC DD EE ?? FF GG HH"
	* Pattern format alternative: "AABBCCDDEEFF??FFGGHH"
	* Pattern format alternative2: "AA BB CC DD EE ? ? FF GG HH"
	* Pattern format Not supported: "AA BB CC DD EE ???? FF GG HH"
	* Pattern format Not supported: "AABBCCDDEEFF???FFGGHH"
	* Variable-width wildcard: "AA BB [5-24] CC DD"
	* SkipCount if pattern is found and skip is >0 then skip to next pattern in executable section, all skip needs to be in same section
	*/
	static DWORD64 ScanPatternInExecutableSection(const void* module, const char* pattern, size_t skipCount = 0) {
		auto dosHeader = (PIMAGE_DOS_HEADER)module;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((DWORD64)dosHeader + dosHeader->e_lfanew);
		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
				(sectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				auto sectionSize = sectionHeader->Misc.VirtualSize;
				auto sectionAddress = (DWORD64)sectionHeader->VirtualAddress + (DWORD64)module;
				auto result = Scan(sectionAddress, sectionSize, pattern, skipCount);
				if (result != 0) {
					return result;
				}
			}
			sectionHeader++;
		}
		return 0;
	}

	static DWORD64 ScanBackwardInExecutableSection(const void* module, const char* pattern, size_t skipCount = 0) {
		auto dosHeader = (PIMAGE_DOS_HEADER)module;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((DWORD64)dosHeader + dosHeader->e_lfanew);
		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
				(sectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				auto sectionSize = sectionHeader->Misc.VirtualSize;
				auto sectionAddress = (DWORD64)sectionHeader->VirtualAddress + (DWORD64)module;
				auto result = ScanBackward(sectionAddress, sectionSize, pattern, skipCount);
				if (result != 0) {
					return result;
				}
			}
			sectionHeader++;
		}
		return 0;
	}
};

#endif

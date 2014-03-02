/*
 * Copyright (C) 2013 midnightBITS
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "pch.h"
#include <new.hpp>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef MEMORY_DEBUGGER

#include <windows.h>

#undef UNICODE
#include <DbgHelp.h>
#include <tlhelp32.h>
#define UNICODE

#pragma comment(lib, "DbgHelp.lib")

constexpr size_t SYMBOL_NAME_MAXLEN = 1024;

struct SymStartup {
	HANDLE process;
	SymStartup(HANDLE process) : process(process)
	{
		char current[MAX_PATH];
		char path[(MAX_PATH + 1) * 6 + 1] = "";
		if (GetCurrentDirectoryA(MAX_PATH, current) > 0)
		{
			strcat(strcpy(path, current), ";");
		}

		if (GetModuleFileNameA(NULL, current, MAX_PATH) > 0)
		{
			char * ptr = strrchr(current, '\\');
			if (ptr) *ptr = 0;
			strcat(strcat(path, current), ";");
		}

		if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", current, MAX_PATH) > 0)
		{
			strcat(strcat(path, current), ";");
		}

		if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", current, MAX_PATH) > 0)
		{
			strcat(strcat(path, current), ";");
		}

		if (GetEnvironmentVariableA("SYSTEMROOT", current, MAX_PATH) > 0)
		{
			strcat(strcat(path, current), ";");
			strcat(strcat(path, current), "\\System32;");
		}

		if (!SymInitialize(process, path, FALSE))
			throw 1;

		DWORD options = SymGetOptions();
		options |= SYMOPT_LOAD_LINES;
		options |= SYMOPT_FAIL_CRITICAL_ERRORS;

		options = SymSetOptions(options);
	}

	~SymStartup() {
		if (process)
			SymCleanup(process);
	}
};

struct SymbolName
{
	char name[SYMBOL_NAME_MAXLEN];
	char file[SYMBOL_NAME_MAXLEN];
	int line;

	SymbolName() : line(0)
	{
		name[0] = 0;
		file[0] = 0;
	}
};

class StackTraceImpl
{
	void load_modules(HANDLE process, DWORD processID)
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
		if (snap == INVALID_HANDLE_VALUE)
			return;

		MODULEENTRY32 entry;
		entry.dwSize = sizeof(entry);

		if (Module32First(snap, &entry))
		{
			do
			{
				SymLoadModule64(process, NULL, entry.szExePath, entry.szModule, (DWORD64)entry.modBaseAddr, entry.modBaseSize);
			} while (Module32Next(snap, &entry));
		}
		CloseHandle(snap);
	}

	void retrieve_context(CONTEXT& context) {
		memset(&context, 0, sizeof(context));
		context.ContextFlags = CONTEXT_FULL;
		RtlCaptureContext(&context);
	}

	void retrieve_frame(CONTEXT& context, STACKFRAME64& frame, DWORD& imageType) {
		memset(&frame, 0, sizeof(frame));
#ifdef _M_IX86
		imageType = IMAGE_FILE_MACHINE_I386;
		frame.AddrPC.Offset = context.Eip;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = context.Ebp;
		frame.AddrFrame.Mode = AddrModeFlat;
		frame.AddrStack.Offset = context.Esp;
		frame.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
		imageType = IMAGE_FILE_MACHINE_AMD64;
		frame.AddrPC.Offset = context.Rip;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = context.Rsp;
		frame.AddrFrame.Mode = AddrModeFlat;
		frame.AddrStack.Offset = context.Rsp;
		frame.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
		imageType = IMAGE_FILE_MACHINE_IA64;
		frame.AddrPC.Offset = context.StIIP;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = context.IntSp;
		frame.AddrFrame.Mode = AddrModeFlat;
		frame.AddrBStore.Offset = context.RsBSP;
		frame.AddrBStore.Mode = AddrModeFlat;
		frame.AddrStack.Offset = context.IntSp;
		frame.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif
	}

	HANDLE process;
public:

	StackTraceImpl(HANDLE process) : process(process)
	{
			load_modules(process, GetCurrentProcessId());
	}

	template <size_t length>
	size_t retrieve(SymbolName(&stack)[length]) { return retrieve(stack, length); }
	size_t retrieve(SymbolName* stack, size_t length)
	{
		size_t count = 0;
		try
		{
			HANDLE thread = GetCurrentThread();

			CONTEXT context;
			retrieve_context(context);

			DWORD imageType = 0;
			STACKFRAME64 frame;
			retrieve_frame(context, frame, imageType);

			char symbolData[sizeof(IMAGEHLP_SYMBOL64) + SYMBOL_NAME_MAXLEN];
			IMAGEHLP_SYMBOL64* symbol = reinterpret_cast<IMAGEHLP_SYMBOL64*>(symbolData);
			symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
			symbol->MaxNameLength = SYMBOL_NAME_MAXLEN;

			IMAGEHLP_LINE64 line;
			memset(&line, 0, sizeof(IMAGEHLP_LINE64));
			line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

			for (int frameNum = 0; count < length; ++frameNum)
			{
				if (!StackWalk64(imageType, process, thread, &frame, &context, NULL, &SymFunctionTableAccess64, &SymGetModuleBase64, NULL))
					break;

				if (frame.AddrPC.Offset == frame.AddrReturn.Offset)
					break;

				if (frame.AddrPC.Offset != 0)
				{
					DWORD64 displacement64 = 0;
					if (SymGetSymFromAddr64(process, frame.AddrPC.Offset, &displacement64, symbol))
						UnDecorateSymbolName(symbol->Name, stack[count].name, SYMBOL_NAME_MAXLEN, UNDNAME_COMPLETE);

					DWORD displacement = 0;
					if (SymGetLineFromAddr64(process, frame.AddrPC.Offset, &displacement, &line))
					{
						stack[count].line = line.LineNumber;
						strcpy(stack[count].file, line.FileName);
					}

					++count;
				}
				if (frame.AddrReturn.Offset == 0)
					break;
			}
		}
		catch (...) {
		}

		return count;
	}
};

struct Allocation
{
	size_t magic;
	size_t count;
	size_t size;
	size_t type;
	time_t when;
	size_t separator;
};

enum
{
	MAGIC = 0x10FACADE,
	SEPARATOR = 0xCDCDCDCD
};

SymStartup startup{ GetCurrentProcess() };
StackTraceImpl retriever{ GetCurrentProcess() };


void report(time_t when, size_t count, const char* type, size_t size, void* ptr)
{
	SymbolName name[30];
	size_t _size = retriever.retrieve(name);

	char filename[100];
	sprintf(filename, "memory_%u.txt", _getpid());
	FILE *f = fopen(filename, "a");

	fprintf(f, "%10u\t%u\t%s\t%u\t%p\n", when, count, type, size, ptr);
	if (_size > 5)
	{
		_size -= 5;
		for (size_t i = 0; i < _size; ++i)
			fprintf(f, "\t%d)\t%s:%d\t%s\n", i, name[i + 5].file, name[i + 5].line, name[i + 5].name);
	}
	fclose(f);
}

void newlog_print(const char* fmt, ...)
{
	char filename[100];
	sprintf(filename, "memory_%u.txt", _getpid());
	FILE *f = fopen(filename, "a");

	va_list args;
	va_start(args, fmt);
	vfprintf(f, fmt, args);
	va_end(args);

	fclose(f);
}

void* xmalloc(size_t size, bool should_throw, bool type)
{
	size_t changed = size + sizeof(Allocation);
	Allocation* ptr = (Allocation*)malloc(changed);
	if (!ptr)
	{
		if (should_throw)
			throw std::bad_alloc();

		return nullptr;
	}

	static size_t counter = 0;

	ptr->magic = MAGIC;
	ptr->count = counter++;
	ptr->size = size;
	ptr->type = type ? 1 : 0;
	time(&ptr->when);
	ptr->separator = SEPARATOR;

	report(ptr->when, ptr->count, type ? "NV" : "NS", ptr->size, ptr + 1);

	return ++ptr;
}

void barf(const char* fmt, ...)
{
	char filename[100];
	sprintf(filename, "memory_%u.txt", _getpid());
	FILE *f = fopen(filename, "a");

	va_list args;
	va_start(args, fmt);
	vfprintf(f, fmt, args);
	va_end(args);

	terminate();
}

void xfree(void* in, bool type)
{
	if (!in)
		return;

	Allocation* ptr = (Allocation*)in;
	--ptr;

	if (ptr->magic != MAGIC)
		barf("Magic not found (%p)!\n", in);

	if (ptr->separator != SEPARATOR)
		barf("Overwritten at %llu\n", ptr->count);

	if (ptr->type != (type ? 1 : 0))
		barf("Array and non-array mixed at %llu\n", ptr->count);

	time_t when;
	time(&when);
	report(when, ptr->count, type ? "DV" : "DS", ptr->size, in);

	free(ptr);
}

void* operator new  (size_t count){ return xmalloc(count, true, false); }
void* operator new[](size_t count){ return xmalloc(count, true, true); }
void* operator new  (size_t count, const std::nothrow_t& tag){ return xmalloc(count, false, false); }
void* operator new[](size_t count, const std::nothrow_t& tag){ return xmalloc(count, false, true); }

void operator delete  (void* ptr){ return xfree(ptr, false); }
void operator delete[](void* ptr){ return xfree(ptr, true); }
void operator delete  (void* ptr, const std::nothrow_t& tag){ return xfree(ptr, false); }
void operator delete[](void* ptr, const std::nothrow_t& tag){ return xfree(ptr, true); }

#endif // MEMORY_DEBUGGER

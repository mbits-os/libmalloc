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

#ifndef __LIBMALLOC_NEW_HPP__
#define __LIBMALLOC_NEW_HPP__

//#define MEMORY_DEBUGGER
#ifdef MEMORY_DEBUGGER

#define __PLACEMENT_NEW_INLINE
#define __PLACEMENT_VEC_NEW_INLINE

#include <new>

void* operator new  (size_t count);
void* operator new[](size_t count);
void* operator new  (size_t count, const std::nothrow_t& tag);
void* operator new[](size_t count, const std::nothrow_t& tag);
inline void* operator new  (size_t count, void* ptr){ return ptr; }
inline void* operator new[](size_t count, void* ptr){ return ptr; }

void operator delete  (void* ptr);
void operator delete[](void* ptr);
void operator delete  (void* ptr, const std::nothrow_t& tag);
void operator delete[](void* ptr, const std::nothrow_t& tag);
inline void operator delete  (void* ptr, void* place){ }
inline void operator delete[](void* ptr, void* place){}

void newlog_print(const char* fmt, ...);

#endif // MEMORY_DEBUGGER

#endif // __LIBMALLOC_NEW_HPP__

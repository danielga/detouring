/*************************************************************************
* Detouring::ClassProxy
* A C++ class that allows you to "proxy" virtual tables and receive
* calls in substitute classes. Contains helpers for detouring regular
* member functions as well.
*------------------------------------------------------------------------
* Copyright (c) 2017, Daniel Almeida
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*************************************************************************/

/*************************************************************************
* Implementation of the Detouring::GetVirtualAddress function heavily
* based on meepdarknessmeep's vhook.h header at
* https://github.com/glua/gm_fshook/blob/master/src/vhook.h
* Thanks a lot, xoxo.
*************************************************************************/

#include "classproxy.hpp"

#if defined _WIN32

#include <Windows.h>

#define PAGE_EXECUTE_FLAGS \
	( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY )

#elif defined __linux

#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cinttypes>

#elif defined __APPLE__

#include <sys/mman.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#else

#error Unsupported operating system.

#endif

#if defined( _M_X64 ) || defined( __amd64__ ) || defined( __amd64 ) || \
	defined( __x86_64__ ) || defined( __x86_64 )

#define ARCH_X86_64

#elif defined( _M_IX86 ) || defined( ___i386__ ) || defined( __i386 ) || \
	defined( __X86__ ) || defined( _X86_ ) || defined( __I86__ )

#define ARCH_X86

#else

#error Unsupported architecture.

#endif

namespace Detouring
{
	Member::Member( )
	{
		address = nullptr;
		index = static_cast<size_t>( ~0 );
	}

	Member::Member( size_t idx, void *addr )
	{
		address = addr;
		index = idx;
	}

	bool ProtectMemory( void *pMemory, size_t uiLen, bool protect )
	{

#ifdef _WIN32

		static unsigned long before = 0;
		return VirtualProtect(
			pMemory,
			uiLen,
			protect ? before : PAGE_EXECUTE_READWRITE,
			&before
		) == 1;

#else

		uintptr_t uiMemory = reinterpret_cast<uintptr_t>( pMemory ),
			diff = uiMemory % static_cast<uintptr_t>( sysconf( _SC_PAGESIZE ) );
		return mprotect(
			reinterpret_cast<void *>( uiMemory - diff ),
			diff + uiLen,
			( protect ? 0 : PROT_WRITE ) | PROT_READ | PROT_EXEC
		) == 0;

#endif

	}

	bool IsExecutableAddress( void *pAddress )
	{

#if defined _WIN32

		MEMORY_BASIC_INFORMATION mi = { 0 };
		return VirtualQuery( pAddress, &mi, sizeof( mi ) ) != 0 &&
			mi.State == MEM_COMMIT &&
			( mi.Protect & PAGE_EXECUTE_FLAGS ) != 0;

#elif defined __APPLE__

		mach_vm_address_t address = reinterpret_cast<mach_vm_address_t>( pAddress );
		mach_vm_size_t vmsize;

#ifdef ARCH_X86_64

		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;

#else

		vm_region_basic_info_data_t info;
		mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT;

#endif

		memory_object_name_t object;
		kern_return_t status = mach_vm_region(
			mach_task_self( ),
			&address,
			&vmsize,
			VM_REGION_BASIC_INFO,
			reinterpret_cast<vm_region_info_t>( &info ),
			&info_count,
			&object
		);
		return status == KERN_SUCCESS && ( info.protection & VM_PROT_EXECUTE ) != 0;

#else

		uintptr_t address = reinterpret_cast<uintptr_t>( pAddress );
		char line[BUFSIZ] = { 0 };

		FILE *file = fopen( "/proc/self/maps", "r" );
		if( file == NULL )
			return false;

		while( fgets( line, sizeof( line ), file ) != NULL )
		{
			uint64_t start = 0, end = 0;
			char prot[5] = { 0 };
			if( sscanf( line, "%" SCNx64 "-%" SCNx64 " %4[rwxsp-]", &start, &end, prot ) == 3 &&
				start <= address &&
				end >= address
			)
			{
				fclose( file );
				return prot[2] == 'x';
			}
		}

		fclose( file );
		return false;

#endif

	}
}

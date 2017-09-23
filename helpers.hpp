/*************************************************************************
* Detouring::Helpers
* C++ helpers for detouring member functions.
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

#pragma once

#include <stdint.h>
#include <cstddef>
#include "hook.hpp"
#include "../Platform.hpp"

namespace Detouring
{
	namespace MemoryProtection
	{
		enum : int32_t
		{
			Error = static_cast<int32_t>( 0xFFFFFFF0 ),
			Unknown = static_cast<int32_t>( 0xFFFFFFF8 ),
			None = 0x00000000,
			Read = 0x00000001,
			Write = 0x00000002,
			Execute = 0x00000004
		};
	}

	struct Member
	{
		enum class Type
		{
			Unknown = -1,
			Static,
			NonVirtual,
			Virtual
		};

		Member( );
		Member( size_t idx, void *addr, Type type );

		bool IsValid( ) const;

		void *address;
		size_t index;
		Type type;
	};

	int32_t GetMemoryProtection( void *address );

	bool SetMemoryProtection( void *address, size_t length, int32_t protection );

	bool ProtectMemory( void *address, size_t length, bool protect );

	bool IsExecutableAddress( void *address );

	template<typename Class>
	inline void **GetVirtualTable( Class *instance )
	{
		return *reinterpret_cast<void ***>( instance );
	}

	template<typename RetType, typename Class, typename... Args>
	inline void *GetAddress( RetType ( Class::* method )( Args... ) )
	{
		RetType ( Class::** pmethod )( Args... ) = &method;

#ifdef COMPILER_VC

		void *address = *reinterpret_cast<void **>( pmethod );

#else

		void *address = reinterpret_cast<void *>( pmethod );

#endif

		// Check whether the function starts with a relative far jump and assume a debug compilation thunk
		uint8_t *method_code = reinterpret_cast<uint8_t *>( address );
		if( method_code[0] == 0xE9 )
			address = method_code + 5 + *reinterpret_cast<int32_t *>( method_code + 1 );

		return address;
	}

	// Can be used with interfaces and implementations
	template<typename RetType, typename Class, typename... Args>
	inline Member GetVirtualAddress(
		void **vtable,
		size_t size,
		RetType ( Class::* method )( Args... )
	)
	{
		if( vtable == nullptr || size == 0 || method == nullptr )
			return Member( );

#ifdef COMPILER_VC

		void *member = GetAddress( method );
		uint8_t *addr = reinterpret_cast<uint8_t *>( member );

#ifdef ARCHITECTURE_X86_64

		// x86-64, mov rax, [rcx]
		if( addr[0] == 0x48 )
			addr += 3;

#else

		if( addr[0] == 0x8B )
			addr += 2;

#endif

		// check for jmp functions
		if( addr[0] == 0xFF && ( ( addr[1] >> 4 ) & 3 ) == 2 )
		{
			uint8_t jumptype = addr[1] >> 6;
			uint32_t offset = 0;
			if( jumptype == 1 ) // byte
				offset = addr[2];
			else if( jumptype == 2 )
				offset = *reinterpret_cast<uint32_t *>( &addr[2] );

			size_t index = offset / sizeof( void * );
			if( index >= size )
				return Member( );

			return Member( index, vtable[index], Member::Type::Virtual );
		}

		for( size_t index = 0; index < size; ++index )
			if( vtable[index] == member )
				return Member( index, member, Member::Type::Virtual );

		return Member( );

#else

		RetType ( Class::** pmethod )( Args... ) = &method;
		void *address = *reinterpret_cast<void **>( pmethod );
		size_t offset = ( reinterpret_cast<uintptr_t>( address ) - 1 ) / sizeof( void * );
		if( offset >= size )
		{
			for( size_t index = 0; index < size; ++index )
				if( vtable[index] == address )
					return Member( index, address, Member::Type::Virtual );

			return Member( );
		}

		return Member( offset, vtable[offset], Member::Type::Virtual );

#endif

	}
}

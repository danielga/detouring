/*************************************************************************
* ClassDetouring
* A C++ header that allows you to "proxy" virtual tables and receive
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
* Implementation of the ClassDetouring::GetVirtualAddress function heavily
* based on meepdarknessmeep's vhook.h header at
* https://github.com/glua/gm_fshook/blob/master/src/vhook.h
* Thanks a lot, xoxo.
*************************************************************************/

#pragma once

#include <cstddef>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <type_traits>

#if defined __linux || defined __APPLE__

#include <sys/mman.h>
#include <unistd.h>

#elif !defined _WIN32

#error Platform not supported!

#endif

namespace ClassDetouring
{

#if defined _WIN32

	extern "C" __declspec( dllimport ) int __stdcall VirtualProtect(
		void *lpAddress,
		size_t dwSize,
		unsigned long flNewProtect,
		unsigned long *lpflOldProtect
	);

#endif

	struct Member
	{
		Member( )
		{
			address = nullptr;
			index = static_cast<size_t>( ~0 );
		}

		Member( size_t idx, void *addr )
		{
			address = addr;
			index = idx;
		}

		void *address;
		size_t index;
	};

	typedef std::unordered_map<void *, Member> CacheMap;

	template<typename Class>
	inline void **GetVirtualTable( Class *instance )
	{
		return *reinterpret_cast<void ***>( instance );
	}

	template<typename RetType, typename Class, typename... Args>
	inline void *GetAddress( RetType ( Class::* method )( Args... ) )
	{
		RetType ( Class::** pmethod )( Args... ) = &method;

#ifdef _MSC_VER

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

	// can be used with interfaces and implementations
	template<typename RetType, typename Class, typename... Args>
	inline Member GetVirtualAddress(
		void **vtable,
		size_t size,
		RetType ( Class::* method )( Args... )
	)
	{
		if( vtable == nullptr || size == 0 || method == nullptr )
			return Member( );

#if defined _WIN32

		void *member = GetAddress( method );
		uint8_t *addr = reinterpret_cast<uint8_t *>( member );

		// check for rel jmp opcode (debug mode adds this layer of indirection)
		if( addr[0] == 0xE9 )
			addr += 5 + *reinterpret_cast<int32_t *>( &addr[1] );

		// check for jmp functions
		if( addr[0] == 0x8B )
			addr += 2;

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

			return Member( index, vtable[index] );
		}

		for( size_t index = 0; index < size; ++index )
			if( vtable[index] == member )
				return Member( index, member );

		return Member( );

#else

		union u_addr
		{
			RetType ( Class::* func )( Args... );
			void *addr;
			uintptr_t offset_plus_one;
		};

		// TODO: find better way to find which impl it is using
		u_addr u;
		u.func = method;

		size_t offset = ( u.offset_plus_one - 1 ) / sizeof( void * );
		if( offset >= size )
		{
			for( size_t index = 0; index < size; ++index )
				if( vtable[index] == u.addr )
					return Member( index, u.addr );

			return Member( );
		}

		return Member( offset, vtable[offset] );

#endif

	}

	template<typename Target, typename Substitute>
	class Proxy
	{
	protected:
		Proxy( )
		{ }

		Proxy( Target *instance )
		{
			Initialize( instance );
		}

		virtual ~Proxy( )
		{
			if( target_vtable != nullptr && target_size != 0 )
			{
				ProtectMemory( target_vtable, target_size * sizeof( void * ), false );

				void **vtable = target_vtable;
				for(
					auto it = original_vtable.begin( );
					it != original_vtable.end( );
					++vtable, ++it
				)
					if( *vtable != *it )
						*vtable = *it;

				ProtectMemory( target_vtable, target_size * sizeof( void * ), true );
			}
		}

	public:
		static bool Initialize( Target *instance, Substitute *substitute )
		{
			if( target_vtable != nullptr )
				return false;

			target_vtable = GetVirtualTable( instance );

			for(
				void **vtable = target_vtable;
				original_vtable.size( ) < original_vtable.max_size( ) && *vtable != nullptr;
				++vtable
			)
				original_vtable.push_back( *vtable );

			target_size = original_vtable.size( );

			substitute_vtable = GetVirtualTable( substitute );

			for( ; substitute_vtable[substitute_size] != nullptr; ++substitute_size );

			return true;
		}

		inline bool Initialize( Target *instance )
		{
			return Initialize( instance, static_cast<Substitute *>( this ) );
		}

		inline Target *This( )
		{
			return reinterpret_cast<Target *>( this );
		}

		template<typename RetType, typename... Args>
		static bool IsHooked( RetType ( Target::* original )( Args... ) )
		{
			return IsHookedInternal( original );
		}

		template<typename RetType, typename... Args>
		static bool IsHooked( RetType ( Target::* original )( Args... ) const )
		{
			return IsHookedInternal(
				reinterpret_cast<RetType ( Target::* )( Args... )>( original )
			);
		}

		template<typename RetType, typename... Args>
		static bool Hook(
			RetType ( Target::* original )( Args... ),
			RetType ( Substitute::* substitute )( Args... )
		)
		{
			return HookInternal( original, substitute );
		}

		template<typename RetType, typename... Args>
		static bool Hook(
			RetType ( Target::* original )( Args... ) const,
			RetType ( Substitute::* substitute )( Args... ) const
		)
		{
			return HookInternal(
				reinterpret_cast<RetType ( Target::* )( Args... )>( original ),
				reinterpret_cast<RetType ( Target::* )( Args... )>( substitute )
			);
		}

		template<typename RetType, typename... Args>
		static bool UnHook( RetType ( Target::* original )( Args... ) )
		{
			return UnHookInternal( original );
		}

		template<typename RetType, typename... Args>
		static bool UnHook( RetType ( Target::* original )( Args... ) const )
		{
			return UnHookInternal(
				reinterpret_cast<RetType ( Target::* )( Args... )>( original )
			);
		}

		template<typename RetType, typename... Args>
		static RetType Call(
			Target *instance,
			RetType ( Target::* original )( Args... ),
			Args... args
		)
		{
			return CallInternal( instance, original, args... );
		}

		template<typename RetType, typename... Args>
		static RetType Call(
			Target *instance,
			RetType ( Target::* original )( Args... ) const,
			Args... args
		)
		{
			return CallInternal(
				instance,
				reinterpret_cast<RetType ( Target::* )( Args... )>( original ),
				args...
			);
		}

		template<typename RetType, typename... Args>
		inline RetType Call( RetType ( Target::* original )( Args... ), Args... args )
		{
			return Call( reinterpret_cast<Target *>( this ), original, args... );
		}

		template<typename RetType, typename... Args>
		inline RetType Call( RetType ( Target::* original )( Args... ) const, Args... args )
		{
			return Call( reinterpret_cast<Target *>( this ), original, args... );
		}

		template<typename RetType, typename... Args>
		static Member GetTargetVirtualAddress( RetType ( Target::* method )( Args... ) )
		{
			return GetVirtualAddress( target_cache, target_vtable, target_size, method );
		}

		template<typename RetType, typename... Args>
		static Member GetTargetVirtualAddress( RetType ( Target::* method )( Args... ) const )
		{
			return GetVirtualAddress( target_cache, target_vtable, target_size, method );
		}

		template<typename RetType, typename... Args>
		static Member GetSubstituteVirtualAddress( RetType ( Substitute::* method )( Args... ) )
		{
			return GetVirtualAddress(
				substitute_cache,
				substitute_vtable,
				substitute_size,
				method
			);
		}

		template<typename RetType, typename... Args>
		static Member GetSubstituteVirtualAddress( RetType ( Substitute::* method )( Args... ) const )
		{
			return GetVirtualAddress(
				substitute_cache,
				substitute_vtable,
				substitute_size,
				method
			);
		}

	private:
		// can be used with interfaces and implementations
		template<typename RetType, typename Class, typename... Args>
		static Member GetVirtualAddress(
			CacheMap &cache,
			void **vtable,
			size_t size,
			RetType ( Class::* method )( Args... )
		)
		{
			void *member = GetAddress( method );
			if( cache.find( member ) != cache.end( ) )
				return cache[member];

			Member address = ClassDetouring::GetVirtualAddress( vtable, size, method );

			if( address.index < size )
				cache[member] = address;

			return address;
		}

		static bool ProtectMemory( void *pMemory, size_t uiLen, bool protect )
		{

#if defined _WIN32

			static unsigned long before = 0;
			// PAGE_EXECUTE_READWRITE == 0x40
			return VirtualProtect( pMemory, uiLen, protect ? before : 0x40, &before ) == 1;

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

		template<typename RetType, typename... Args>
		static bool IsHookedInternal( RetType ( Target::* original )( Args... ) )
		{
			Member target = GetTargetVirtualAddress( original );
			if( target.index >= target_size )
				return false;

			return target_vtable[target.index] != original_vtable[target.index];
		}

		template<typename RetType, typename... Args>
		static bool HookInternal(
			RetType ( Target::* original )( Args... ),
			RetType ( Substitute::* substitute )( Args... )
		)
		{
			if( IsHooked( original ) )
				return false;

			Member target = GetTargetVirtualAddress( original );
			if( target.index >= target_size )
				return false;

			Member subst = GetSubstituteVirtualAddress( substitute );
			if( subst.index >= substitute_size )
				return false;

			ProtectMemory( target_vtable + target.index, sizeof( void * ), false );
			target_vtable[target.index] = subst.address;
			ProtectMemory( target_vtable + target.index, sizeof( void * ), true );

			return true;
		}

		template<typename RetType, typename... Args>
		static bool UnHookInternal( RetType ( Target::* original )( Args... ) )
		{
			if( !IsHooked( original ) )
				return false;

			Member target = GetTargetVirtualAddress( original );
			if( target.index >= target_size )
				return false;

			void *vfunction = original_vtable[target.index];

			ProtectMemory( target_vtable + target.index, sizeof( void * ), false );
			target_vtable[target.index] = vfunction;
			ProtectMemory( target_vtable + target.index, sizeof( void * ), true );

			return true;
		}

		template<typename RetType, typename... Args>
		static RetType CallInternal(
			Target *instance,
			RetType ( Target::* original )( Args... ),
			Args... args
		)
		{
			Member target = GetTargetVirtualAddress( original );
			if( target.index >= target_size )
				return RetType( );

			target.address = original_vtable[target.index];
			auto typedfunc = reinterpret_cast<RetType ( Target::** )( Args... )>( &target );
			return ( instance->**typedfunc )( args... );
		}

		static size_t target_size;
		static void **target_vtable;
		static CacheMap target_cache;
		static std::vector<void *> original_vtable;
		static size_t substitute_size;
		static void **substitute_vtable;
		static CacheMap substitute_cache;
	};

	template<typename Target, typename Substitute>
	size_t Proxy<Target, Substitute>::target_size = 0;
	template<typename Target, typename Substitute>
	void **Proxy<Target, Substitute>::target_vtable = nullptr;
	template<typename Target, typename Substitute>
	CacheMap Proxy<Target, Substitute>::target_cache;
	template<typename Target, typename Substitute>
	std::vector<void *> Proxy<Target, Substitute>::original_vtable;
	template<typename Target, typename Substitute>
	size_t Proxy<Target, Substitute>::substitute_size = 0;
	template<typename Target, typename Substitute>
	void **Proxy<Target, Substitute>::substitute_vtable = nullptr;
	template<typename Target, typename Substitute>
	CacheMap Proxy<Target, Substitute>::substitute_cache;
}

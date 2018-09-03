/*************************************************************************
* Detouring::ClassProxy
* A C++ class that allows you to "proxy" virtual tables and receive
* calls in substitute classes. Contains helpers for detouring regular
* member functions as well.
*------------------------------------------------------------------------
* Copyright (c) 2017-2018, Daniel Almeida
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

#pragma once

#include "hook.hpp"
#include "helpers.hpp"
#include "platform.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <unordered_map>
#include <utility>

#if defined( COMPILER_VC ) && defined( ARCHITECTURE_X86 )

#define CLASSPROXY_CALLING_CONVENTION __thiscall

#endif

namespace Detouring
{
	typedef std::unordered_map<void *, Member> CacheMap;
	typedef std::unordered_map<void *, Detouring::Hook> HookMap;

	template<typename Target, typename Substitute>
	class ClassProxy
	{
	protected:
		ClassProxy( )
		{ }

		ClassProxy( Target *instance )
		{
			Initialize( instance );
		}

		virtual ~ClassProxy( )
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
			if( target_vtable == nullptr || !IsExecutableAddress( *target_vtable ) )
			{
				target_vtable = nullptr;
				return false;
			}

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
		static bool IsHooked( RetType ( *original )( Target *, Args... ) )
		{
			return IsHookedFunction( original );
		}

#if defined( COMPILER_VC ) && defined( ARCHITECTURE_X86 )

		template<typename RetType, typename... Args>
		static bool IsHooked(
			RetType ( CLASSPROXY_CALLING_CONVENTION *original )( Target *, Args... )
		)
		{
			return IsHookedFunction(
				reinterpret_cast<RetType ( * )( Target *, Args... )>( original )
			);
		}

#endif

		template<typename RetType, typename... Args>
		static bool IsHooked( RetType ( Target::*original )( Args... ) )
		{
			return IsHookedMember( original );
		}

		template<typename RetType, typename... Args>
		static bool IsHooked( RetType ( Target::*original )( Args... ) const )
		{
			return IsHookedMember(
				reinterpret_cast<RetType ( Target::* )( Args... )>( original )
			);
		}

		template<typename RetType, typename... Args>
		static bool Hook(
			RetType ( *original )( Target *, Args... ),
			RetType ( Substitute::*substitute )( Args... )
		)
		{
			return HookFunction( original, substitute );
		}

#if defined( COMPILER_VC ) && defined( ARCHITECTURE_X86 )

		template<typename RetType, typename... Args>
		static bool Hook(
			RetType ( CLASSPROXY_CALLING_CONVENTION *original )( Target *, Args... ),
			RetType ( Substitute::*substitute )( Args... )
		)
		{
			return HookFunction(
				reinterpret_cast<RetType ( * )( Target *, Args... )>( original ),
				substitute
			);
		}

#endif

		template<typename RetType, typename... Args>
		static bool Hook(
			RetType ( Target::*original )( Args... ),
			RetType ( Substitute::*substitute )( Args... )
		)
		{
			return HookMember( original, substitute );
		}

		template<typename RetType, typename... Args>
		static bool Hook(
			RetType ( Target::*original )( Args... ) const,
			RetType ( Substitute::*substitute )( Args... ) const
		)
		{
			return HookMember(
				reinterpret_cast<RetType ( Target::* )( Args... )>( original ),
				reinterpret_cast<RetType ( Target::* )( Args... )>( substitute )
			);
		}

		template<typename RetType, typename... Args>
		static bool UnHook( RetType ( *original )( Target *, Args... ) )
		{
			return UnHookFunction( original );
		}

#if defined( COMPILER_VC ) && defined( ARCHITECTURE_X86 )

		template<typename RetType, typename... Args>
		static bool UnHook(
			RetType ( CLASSPROXY_CALLING_CONVENTION *original )( Target *, Args... )
		)
		{
			return UnHookFunction(
				reinterpret_cast<RetType ( * )( Target *, Args... )>( original )
			);
		}

#endif

		template<typename RetType, typename... Args>
		static bool UnHook( RetType ( Target::*original )( Args... ) )
		{
			return UnHookMember( original );
		}

		template<typename RetType, typename... Args>
		static bool UnHook( RetType ( Target::*original )( Args... ) const )
		{
			return UnHookMember(
				reinterpret_cast<RetType ( Target::* )( Args... )>( original )
			);
		}

		template<typename RetType, typename... Args>
		static RetType Call(
			Target *instance,
			RetType ( *original )( Target *, Args... ),
			Args... args
		)
		{
			void *target = CallFunctionTarget( original );
			if( target == nullptr )
				return RetType( );

			auto method = reinterpret_cast<RetType ( * )( Target *, Args... )>( target );
			return method( instance, std::forward<Args>( args )... );
		}

#if defined( COMPILER_VC ) && defined( ARCHITECTURE_X86 )

		template<typename RetType, typename... Args>
		static RetType Call(
			Target *instance,
			RetType ( CLASSPROXY_CALLING_CONVENTION *original )( Target *, Args... ),
			Args... args
		)
		{
			void *target = CallFunctionTarget(
				reinterpret_cast<RetType ( * )( Target *, Args... )>( original )
			);
			if( target == nullptr )
				return RetType( );

			auto method =
				reinterpret_cast<RetType ( CLASSPROXY_CALLING_CONVENTION * )( Target *, Args... )>(
					target
				);
			return method( instance, std::forward<Args>( args )... );
		}

#endif

		template<typename RetType, typename... Args>
		static RetType Call(
			Target *instance,
			RetType ( Target::*original )( Args... ),
			Args... args
		)
		{
			return CallMember<RetType, Args...>( instance, original, std::forward<Args>( args )... );
		}

		template<typename RetType, typename... Args>
		static RetType Call(
			Target *instance,
			RetType ( Target::*original )( Args... ) const,
			Args... args
		)
		{
			return CallMember<RetType, Args...>(
				instance,
				reinterpret_cast<RetType ( Target::* )( Args... )>( original ),
				std::forward<Args>( args )...
			);
		}

		template<typename RetType, typename... Args>
		inline RetType Call( RetType ( *original )( Target *, Args... ), Args... args )
		{
			return Call<RetType, Args...>(
				reinterpret_cast<Target *>( this ), original, std::forward<Args>( args )...
				);
		}

#if defined( COMPILER_VC ) && defined( ARCHITECTURE_X86 )

		template<typename RetType, typename... Args>
		inline RetType Call(
			RetType ( CLASSPROXY_CALLING_CONVENTION *original )( Target *, Args... ),
			Args... args
		)
		{
			return Call<RetType, Args...>(
				reinterpret_cast<Target *>( this ), original, std::forward<Args>( args )...
			);
		}

#endif

		template<typename RetType, typename... Args>
		inline RetType Call( RetType ( Target::*original )( Args... ), Args... args )
		{
			return Call<RetType, Args...>(
				reinterpret_cast<Target *>( this ), original, std::forward<Args>( args )...
			);
		}

		template<typename RetType, typename... Args>
		inline RetType Call( RetType ( Target::*original )( Args... ) const, Args... args )
		{
			return Call<RetType, Args...>(
				reinterpret_cast<Target *>( this ), original, std::forward<Args>( args )...
			);
		}

		template<typename RetType, typename... Args>
		static Member GetTargetVirtualAddress( RetType ( Target::*method )( Args... ) )
		{
			return GetVirtualAddressInternal(
				target_cache, target_vtable, target_size, method
			);
		}

		template<typename RetType, typename... Args>
		static Member GetTargetVirtualAddress( RetType ( Target::*method )( Args... ) const )
		{
			return GetVirtualAddressInternal(
				target_cache, target_vtable, target_size, method
			);
		}

		template<typename RetType, typename... Args>
		static Member GetSubstituteVirtualAddress( RetType ( Substitute::*method )( Args... ) )
		{
			return GetVirtualAddressInternal(
				substitute_cache,
				substitute_vtable,
				substitute_size,
				method
			);
		}

		template<typename RetType, typename... Args>
		static Member GetSubstituteVirtualAddress( RetType ( Substitute::*method )( Args... ) const )
		{
			return GetVirtualAddressInternal(
				substitute_cache,
				substitute_vtable,
				substitute_size,
				method
			);
		}

	private:
		template<typename RetType, typename... Args>
		static bool IsHookedFunction( RetType ( *original )( Target *, Args... ) )
		{
			return hooks.find( reinterpret_cast<void *>( original ) ) != hooks.end( );
		}

		template<typename RetType, typename... Args>
		static bool IsHookedMember( RetType ( Target::*original )( Args... ) )
		{
			auto it = hooks.find( GetAddress( original ) );
			if( it != hooks.end( ) )
				return true;

			Member vtarget = GetTargetVirtualAddress( original );
			if( !vtarget.IsValid( ) )
				return false;

			return target_vtable[vtarget.index] != original_vtable[vtarget.index];
		}

		template<typename RetType, typename... Args>
		static bool HookFunction(
			RetType ( *original )( Target *, Args... ),
			RetType ( Substitute::*substitute )( Args... )
		)
		{
			void *address = reinterpret_cast<void *>( original );
			if( address == nullptr )
				return false;

			auto it = hooks.find( address );
			if( it != hooks.end( ) )
				return true;

			void *subst = GetAddress( substitute );
			if( subst == nullptr )
				return false;

			Detouring::Hook &hook = hooks[address];
			if( !hook.Create( address, subst ) )
			{
				hooks.erase( address );
				return false;
			}

			return hook.Enable( );
		}

		template<typename RetType, typename... Args>
		static bool HookMember(
			RetType ( Target::*original )( Args... ),
			RetType ( Substitute::*substitute )( Args... )
		)
		{
			Member target = GetTargetVirtualAddress( original );
			if( target.IsValid( ) )
			{
				if( target_vtable[target.index] != original_vtable[target.index] )
					return true;

				Member subst = GetSubstituteVirtualAddress( substitute );
				if( !subst.IsValid( ) )
					return false;

				ProtectMemory( target_vtable + target.index, sizeof( void * ), false );
				target_vtable[target.index] = subst.address;
				ProtectMemory( target_vtable + target.index, sizeof( void * ), true );

				return true;
			}

			void *address = GetAddress( original );
			if( address == nullptr )
				return false;

			auto it = hooks.find( address );
			if( it != hooks.end( ) )
				return true;

			void *subst = GetAddress( substitute );
			if( subst == nullptr )
				return false;

			Detouring::Hook &hook = hooks[address];
			if( !hook.Create( address, subst ) )
			{
				hooks.erase( address );
				return false;
			}

			return hook.Enable( );
		}

		template<typename RetType, typename... Args>
		static bool UnHookFunction( RetType ( *original )( Target *, Args... ) )
		{
			auto it = hooks.find( reinterpret_cast<void *>( original ) );
			if( it != hooks.end( ) )
			{
				hooks.erase( it );
				return true;
			}

			return false;
		}

		template<typename RetType, typename... Args>
		static bool UnHookMember( RetType ( Target::*original )( Args... ) )
		{
			auto it = hooks.find( GetAddress( original ) );
			if( it != hooks.end( ) )
			{
				hooks.erase( it );
				return true;
			}

			Member target = GetTargetVirtualAddress( original );
			if( !target.IsValid( ) )
				return false;

			void *vfunction = original_vtable[target.index];
			if( target_vtable[target.index] == vfunction )
				return false;

			ProtectMemory( target_vtable + target.index, sizeof( void * ), false );
			target_vtable[target.index] = vfunction;
			ProtectMemory( target_vtable + target.index, sizeof( void * ), true );

			return true;
		}

		template<typename RetType, typename... Args>
		static void *CallFunctionTarget( RetType ( *original )( Target *, Args... ) )
		{
			void *address = reinterpret_cast<void *>( original ), *target = nullptr;

			auto it = hooks.find( address );
			if( it != hooks.end( ) )
				target = ( *it ).second.GetTrampoline( );

			if( target == nullptr )
				target = address;

			return target;
		}

		template<typename RetType, typename... Args>
		static RetType CallMember(
			Target *instance,
			RetType ( Target::*original )( Args... ),
			Args... args
		)
		{
			Member target;
			void *address = GetAddress( original );
			auto it = hooks.find( address );
			if( it != hooks.end( ) )
			{
				void *trampoline = ( *it ).second.GetTrampoline( );
				if( trampoline != nullptr )
				{
					target.address = ( *it ).second.GetTrampoline( );
					target.index = 0;
					target.type = Member::Type::NonVirtual;
				}
			}

			if( !target.IsValid( ) )
			{
				target = GetTargetVirtualAddress( original );
				if( target.IsValid( ) )
					target.address = original_vtable[target.index];
			}

			if( !target.IsValid( ) )
			{
				if( address != nullptr )
				{
					target.address = address;
					target.index = 0;
					target.type = Member::Type::NonVirtual;
				}
				else
					return RetType( );
			}

			auto typedfunc = reinterpret_cast<RetType ( Target::** )( Args... )>( &target );
			return ( instance->**typedfunc )( std::forward<Args>( args )... );
		}

		// can be used with interfaces and implementations
		template<typename RetType, typename Class, typename... Args>
		static Member GetVirtualAddressInternal(
			CacheMap &cache,
			void **vtable,
			size_t size,
			RetType ( Class::*method )( Args... )
		)
		{
			void *member = GetAddress( method );
			auto it = cache.find( member );
			if( it != cache.end( ) )
				return ( *it ).second;

			Member address = GetVirtualAddress( vtable, size, method );

			if( address.IsValid( ) )
				cache[member] = address;

			return address;
		}

		static size_t target_size;
		static void **target_vtable;
		static CacheMap target_cache;
		static std::vector<void *> original_vtable;
		static size_t substitute_size;
		static void **substitute_vtable;
		static CacheMap substitute_cache;
		static HookMap hooks;
	};

	template<typename Target, typename Substitute>
	size_t ClassProxy<Target, Substitute>::target_size = 0;
	template<typename Target, typename Substitute>
	void **ClassProxy<Target, Substitute>::target_vtable = nullptr;
	template<typename Target, typename Substitute>
	CacheMap ClassProxy<Target, Substitute>::target_cache;
	template<typename Target, typename Substitute>
	std::vector<void *> ClassProxy<Target, Substitute>::original_vtable;
	template<typename Target, typename Substitute>
	size_t ClassProxy<Target, Substitute>::substitute_size = 0;
	template<typename Target, typename Substitute>
	void **ClassProxy<Target, Substitute>::substitute_vtable = nullptr;
	template<typename Target, typename Substitute>
	CacheMap ClassProxy<Target, Substitute>::substitute_cache;
	template<typename Target, typename Substitute>
	HookMap ClassProxy<Target, Substitute>::hooks;
}

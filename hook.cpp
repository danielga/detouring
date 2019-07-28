/*************************************************************************
* Detouring::Hook
* A C++ class that allows you to detour functions.
*------------------------------------------------------------------------
* Copyright (c) 2017-2019, Daniel Almeida
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

#include "hook.hpp"
#include "helpers.hpp"
#include "minhook/include/minhook.h"

namespace Detouring
{
	Hook::Hook( void *_target, void *_detour )
	{
		Create( _target, _detour );
	}

	Hook::Hook( const std::string &module, const std::string &_target, void *_detour )
	{
		Create( module, _target, _detour );
	}

	Hook::Hook( const std::wstring &module, const std::string &_target, void *_detour )
	{
		Create( module, _target, _detour );
	}

	Hook::~Hook( )
	{
		Destroy( );
	}

	bool Hook::IsValid( ) const
	{
		return target != nullptr && detour != nullptr;
	}

	bool Hook::Create( void *_target, void *_detour )
	{
		if( _target == nullptr || _detour == nullptr )
			return false;

		Initialize( );
		if( MH_CreateHook( _target, _detour, &trampoline ) == MH_OK )
		{
			target = _target;
			detour = _detour;
			return true;
		}

		return false;
	}

	bool Hook::Create( const std::string &module, const std::string &_target, void *_detour )
	{
		const std::wstring wmodule;
		return Create( wmodule, _target, _detour );
	}

	bool Hook::Create( const std::wstring &module, const std::string &_target, void *_detour )
	{
		if( module.empty( ) || _target.empty( ) || _detour == nullptr )
			return false;

		Initialize( );
		if( MH_CreateHookApiEx( module.c_str( ), _target.c_str( ), _detour, &trampoline, &target ) == MH_OK )
		{
			detour = _detour;
			return true;
		}

		return false;
	}

	bool Hook::Destroy( )
	{
		if( target == nullptr )
			return false;

		if( MH_RemoveHook( target ) != MH_OK )
			return false;

		target = nullptr;
		detour = nullptr;
		trampoline = nullptr;
		return true;
	}

	bool Hook::Enable( )
	{
		return MH_EnableHook( target ) == MH_OK;
	}

	bool Hook::Disable( )
	{
		return MH_DisableHook( target ) == MH_OK;
	}

	void *Hook::GetTarget( ) const
	{
		return target;
	}

	void *Hook::GetDetour( ) const
	{
		return detour;
	}

	void *Hook::GetTrampoline( ) const
	{
		return trampoline;
	}
}

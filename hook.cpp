/*************************************************************************
* Detouring::Hook
* A C++ class that allows you to detour functions.
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

#include "hook.hpp"
#include "minhook/include/minhook.h"
#include <stdexcept>
#include <iostream>

namespace Detouring
{
	Initializer::Initializer( )
	{
		MH_STATUS status = MH_Initialize( );
		if( status != MH_OK )
			throw std::runtime_error( MH_StatusToString( status ) );
	}

	Initializer::~Initializer( )
	{
		MH_STATUS status = MH_Uninitialize( );
		if( status != MH_OK )
			std::cerr << "MinHook uninitialization failed: " << MH_StatusToString( status ) << std::endl;
	}

	Hook::Hook( ) :
		target( nullptr ),
		detour( nullptr ),
		trampoline( nullptr )
	{ }

	Hook::Hook( void *_target, void *_detour ) :
		target( nullptr ),
		detour( nullptr ),
		trampoline( nullptr )
	{
		Create( _target, _detour );
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

		static Initializer _initializer;
		if( MH_CreateHook( _target, _detour, &trampoline ) == MH_OK )
		{
			target = _target;
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

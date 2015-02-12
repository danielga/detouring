/********************************************************************
Virtual function table hook mechanism
written by LanceVorgin aka stosw aka like 90 other names
ty to qizmo for helping and uni for owning me
oh and go play in traffic trimbo - real mature eh - I blame the drugs
********************************************************************/

/*
class someinterface
{
public:
	virtual void somefunc( char *somearg ) = 0;
};

class someclass : public someinterface
{
public:
	void somefunc( char *somearg )
	{
		printf( "someclass::somefunc: %x %s\n", someval, somearg ? somearg : "NULL" );
	}

	int someval;
};


DEFVFUNC( someclass_somefunc, ( someclass *pa, char *somearg ) );

void VFUNC hookedsomefunc( someclass *pa, char *somearg )
{
	printf( "hooked it: %s\n", somearg ? somearg : "NULL" );
	someclass_somefunc( pa, "lol owned" );
	printf( "leaving hook\n" );
}

someclass q;
someclass w;

void main( )
{
	q.someval = 0xdeadbeef;
	w.someval = 0xc0defeed;

	HOOKVFUNC( &q, 0, someclass_somefunc, hookedsomefunc );
	
	dynamic_cast<someinterface *>( &q )->somefunc( "testing" ); //forces vtable lookup
	
	someclass_somefunc( &w, "should be codefeed yo" );
}
*/

#define ADDRTYPE unsigned long

#define VTBL( classptr ) ( *(ADDRTYPE *)classptr )
#define PVFN_( classptr, offset ) (VTBL( classptr ) + offset )
#define VFN_( classptr, offset ) *(ADDRTYPE *)PVFN_( classptr, offset )
#define PVFN( classptr, offset ) PVFN_( classptr, ( offset * sizeof( void * ) ) )
#define VFN( classptr, offset ) VFN_( classptr, ( offset * sizeof( void * ) ) )

#define HDEFVFUNC( funcname, returntype, proto ) \
	typedef returntype ( VFUNC * funcname##Func ) proto; \
	extern funcname##Func funcname;

#if defined _WIN32

	#define WIN32_LEAN_AND_MEAN
	#define WIN32_EXTRA_LEAN
	#include <windows.h>

	class CVirtualCallGate
	{
	public:
		void Build( void *pOrigFunc, void *pNewFunc, void *pOrgFuncCaller )
		{
			BYTE szGate[] = {
				//pop a	push c	push a	mov a, <dword>	jmp a
				0x58,	0x51,	0x50,	0xB8, 0,0,0,0,	0xFF, 0xE0,
				//pop a	pop c	push a	mov a, <dword>	jmp a
				0x58,	0x59,	0x50,	0xB8, 0,0,0,0,	0xFF, 0xE0
			};

			memcpy( m_szGate, &szGate, sizeof( szGate ) );

			*(ADDRTYPE *)&m_szGate[4] = (ADDRTYPE)pNewFunc;
			*(ADDRTYPE *)&m_szGate[14] = (ADDRTYPE)pOrigFunc;
			
			*(ADDRTYPE *)pOrgFuncCaller = (ADDRTYPE)&m_szGate[10];
		}

		ADDRTYPE Gate( )
		{
			return (ADDRTYPE)&m_szGate[0];
		}

	private:
		char m_szGate[20];
	};

	inline bool DeProtect( void *pMemory, unsigned int uiLen, bool bLock = false )
	{
		DWORD dwIDontCare;
		return VirtualProtect( pMemory, uiLen, bLock ? PAGE_READONLY : PAGE_EXECUTE_READWRITE, &dwIDontCare ) ? true : false;
	}

	#define VFUNC __stdcall

	#define DEFVFUNC( funcname, returntype, proto ) \
		funcname##Func funcname = NULL; \
		void *funcname##Raw_Org = NULL; \
		CVirtualCallGate funcname##Gate;
	
	#define HOOKVFUNC( classptr, index, funcname, newfunc ) \
		DeProtect( (void *)VTBL( classptr ), ( index * sizeof( void * ) ) + 4 ); \
		funcname##Raw_Org = (void *)VFN( classptr, index ); \
		funcname##Gate.Build( funcname##Raw_Org, newfunc, & funcname ); \
		*(ADDRTYPE *)PVFN( classptr, index ) = funcname##Gate.Gate( ); \
		DeProtect( (void *)VTBL( classptr ), ( index * sizeof( void * ) ) + 4 );

	#define UNHOOKVFUNC( classptr, index, funcname ) \
		*(ADDRTYPE *)PVFN( classptr, index ) = (ADDRTYPE)funcname##Raw_Org;

#elif defined __linux || defined __APPLE__

	#define VFUNC

	#define DEFVFUNC( funcname, returntype, proto ) \
		funcname##Func funcname = NULL; 

	#define HOOKVFUNC( classptr, index, funcname, newfunc ) \
		funcname = ( funcname##Func )VFN( classptr, index ); \
		*(ADDRTYPE *)PVFN( classptr, index ) = (ADDRTYPE)newfunc;

	#define UNHOOKVFUNC( classptr, index, funcname ) \
		*(ADDRTYPE *)PVFN( classptr, index ) = (ADDRTYPE)funcname;

#else

	#error unsupported platform

#endif

#define DEFVFUNC_( funcname, returntype, proto ) \
	HDEFVFUNC( funcname, returntype, proto ); \
	DEFVFUNC( funcname, returntype, proto )
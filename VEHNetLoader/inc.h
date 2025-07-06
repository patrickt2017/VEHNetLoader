// https://github.com/passthehashbrowns/Being-A-Good-CLR-Host/blob/main/iea.h

#pragma once
#include <Windows.h>
#include <mscoree.h>
#include <metahost.h>
#include <stdio.h>

typedef struct _AppDomain               IAppDomain;
typedef struct _Assembly                IAssembly;
typedef struct _Type                    IType;
typedef struct _MethodInfo              IMethodInfo;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAppDomain *This)

typedef struct _AppDomainVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IAppDomain* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IAppDomain* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IAppDomain* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(InitializeLifetimeService);
    DUMMY_METHOD(GetLifetimeService);
    DUMMY_METHOD(Evidence);
    DUMMY_METHOD(add_DomainUnload);
    DUMMY_METHOD(remove_DomainUnload);
    DUMMY_METHOD(add_AssemblyLoad);
    DUMMY_METHOD(remove_AssemblyLoad);
    DUMMY_METHOD(add_ProcessExit);
    DUMMY_METHOD(remove_ProcessExit);
    DUMMY_METHOD(add_TypeResolve);
    DUMMY_METHOD(remove_TypeResolve);
    DUMMY_METHOD(add_ResourceResolve);
    DUMMY_METHOD(remove_ResourceResolve);
    DUMMY_METHOD(add_AssemblyResolve);
    DUMMY_METHOD(remove_AssemblyResolve);
    DUMMY_METHOD(add_UnhandledException);
    DUMMY_METHOD(remove_UnhandledException);
    //DUMMY_METHOD(DefineDynamicAssembly);
    HRESULT(STDMETHODCALLTYPE* DefineDynamicAssembly)(
        IAppDomain* This,
        /*[in]*/ struct _AssemblyName* name,
        /*[in]*/ enum AssemblyBuilderAccess access,
        /*[out,retval]*/ struct _AssemblyBuilder** pRetVal);
    DUMMY_METHOD(DefineDynamicAssembly_2);
    DUMMY_METHOD(DefineDynamicAssembly_3);
    DUMMY_METHOD(DefineDynamicAssembly_4);
    DUMMY_METHOD(DefineDynamicAssembly_5);
    DUMMY_METHOD(DefineDynamicAssembly_6);
    DUMMY_METHOD(DefineDynamicAssembly_7);
    DUMMY_METHOD(DefineDynamicAssembly_8);
    DUMMY_METHOD(DefineDynamicAssembly_9);
    DUMMY_METHOD(CreateInstance);
    DUMMY_METHOD(CreateInstanceFrom);
    DUMMY_METHOD(CreateInstance_2);
    DUMMY_METHOD(CreateInstanceFrom_2);
    DUMMY_METHOD(CreateInstance_3);
    DUMMY_METHOD(CreateInstanceFrom_3);
    /*
    HRESULT(STDMETHODCALLTYPE* Load) (
        IAppDomain* This,
        IAssemblyName* assemblyRef,
        IAssembly** pRetVal);
        */
    DUMMY_METHOD(Load);
    //DUMMY_METHOD(Load_2);
    HRESULT(STDMETHODCALLTYPE* Load_2) (
        IAppDomain* This,
        BSTR assemblyString,
        IAssembly** pRetVal
        );

    HRESULT(STDMETHODCALLTYPE* Load_3)(
        IAppDomain* This,
        SAFEARRAY* rawAssembly,
        IAssembly** pRetVal);

    //DUMMY_METHOD(Load_4);
    HRESULT(STDMETHODCALLTYPE* Load_4)(
        IAppDomain* This,
        SAFEARRAY* rawAssembly,
        SAFEARRAY* rawSymbolStore,
        IAssembly** pRetVal);
    DUMMY_METHOD(Load_5);
    DUMMY_METHOD(Load_6);
    DUMMY_METHOD(Load_7);
    DUMMY_METHOD(ExecuteAssembly);
    DUMMY_METHOD(ExecuteAssembly_2);
    DUMMY_METHOD(ExecuteAssembly_3);
    DUMMY_METHOD(FriendlyName);
    DUMMY_METHOD(BaseDirectory);
    DUMMY_METHOD(RelativeSearchPath);
    DUMMY_METHOD(ShadowCopyFiles);
    //DUMMY_METHOD(GetAssemblies);
    HRESULT(STDMETHODCALLTYPE* GetAssemblies)(
        IAppDomain* This,
        SAFEARRAY** pRetVal);
    DUMMY_METHOD(AppendPrivatePath);
    DUMMY_METHOD(ClearPrivatePath);
    DUMMY_METHOD(SetShadowCopyPath);
    DUMMY_METHOD(ClearShadowCopyPath);
    DUMMY_METHOD(SetCachePath);
    DUMMY_METHOD(SetData);
    DUMMY_METHOD(GetData);
    DUMMY_METHOD(SetAppDomainPolicy);
    DUMMY_METHOD(SetThreadPrincipal);
    DUMMY_METHOD(SetPrincipalPolicy);
    DUMMY_METHOD(DoCallBack);
    DUMMY_METHOD(DynamicDirectory);

    END_INTERFACE
} AppDomainVtbl;

typedef struct _AppDomain {
    AppDomainVtbl* lpVtbl;
} AppDomain;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAssembly *This)

typedef struct _AssemblyVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IAssembly* This,
            REFIID riid,
            void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IAssembly* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IAssembly* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);
    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(CodeBase);
    DUMMY_METHOD(EscapedCodeBase);
    DUMMY_METHOD(GetName);
    DUMMY_METHOD(GetName_2);
    DUMMY_METHOD(FullName);

    HRESULT(STDMETHODCALLTYPE* EntryPoint)(
        IAssembly* This,
        IMethodInfo** pRetVal);

    HRESULT(STDMETHODCALLTYPE* GetType_2)(
        IAssembly* This,
        BSTR        name,
        IType** pRetVal);

    DUMMY_METHOD(GetType_3);
    DUMMY_METHOD(GetExportedTypes);
    DUMMY_METHOD(GetTypes);
    DUMMY_METHOD(GetManifestResourceStream);
    DUMMY_METHOD(GetManifestResourceStream_2);
    DUMMY_METHOD(GetFile);
    DUMMY_METHOD(GetFiles);
    DUMMY_METHOD(GetFiles_2);
    DUMMY_METHOD(GetManifestResourceNames);
    DUMMY_METHOD(GetManifestResourceInfo);
    DUMMY_METHOD(Location);
    DUMMY_METHOD(Evidence);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);
    DUMMY_METHOD(GetObjectData);
    DUMMY_METHOD(add_ModuleResolve);
    DUMMY_METHOD(remove_ModuleResolve);
    DUMMY_METHOD(GetType_4);
    DUMMY_METHOD(GetSatelliteAssembly);
    DUMMY_METHOD(GetSatelliteAssembly_2);
    DUMMY_METHOD(LoadModule);
    DUMMY_METHOD(LoadModule_2);
    DUMMY_METHOD(CreateInstance);
    DUMMY_METHOD(CreateInstance_2);
    DUMMY_METHOD(CreateInstance_3);
    DUMMY_METHOD(GetLoadedModules);
    DUMMY_METHOD(GetLoadedModules_2);
    DUMMY_METHOD(GetModules);
    DUMMY_METHOD(GetModules_2);
    DUMMY_METHOD(GetModule);
    DUMMY_METHOD(GetReferencedAssemblies);
    DUMMY_METHOD(GlobalAssemblyCache);

    END_INTERFACE
} AssemblyVtbl;

typedef struct _Assembly {
    AssemblyVtbl* lpVtbl;
} Assembly;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IMethodInfo *This)

typedef struct _MethodInfoVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IMethodInfo* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IMethodInfo* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IMethodInfo* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(MemberType);
    DUMMY_METHOD(name);
    DUMMY_METHOD(DeclaringType);
    DUMMY_METHOD(ReflectedType);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);

    HRESULT(STDMETHODCALLTYPE* GetParameters)(
        IMethodInfo* This,
        SAFEARRAY** pRetVal);

    DUMMY_METHOD(GetMethodImplementationFlags);
    DUMMY_METHOD(MethodHandle);
    DUMMY_METHOD(Attributes);
    DUMMY_METHOD(CallingConvention);
    DUMMY_METHOD(Invoke_2);
    DUMMY_METHOD(IsPublic);
    DUMMY_METHOD(IsPrivate);
    DUMMY_METHOD(IsFamily);
    DUMMY_METHOD(IsAssembly);
    DUMMY_METHOD(IsFamilyAndAssembly);
    DUMMY_METHOD(IsFamilyOrAssembly);
    DUMMY_METHOD(IsStatic);
    DUMMY_METHOD(IsFinal);
    DUMMY_METHOD(IsVirtual);
    DUMMY_METHOD(IsHideBySig);
    DUMMY_METHOD(IsAbstract);
    DUMMY_METHOD(IsSpecialName);
    DUMMY_METHOD(IsConstructor);

    HRESULT(STDMETHODCALLTYPE* Invoke_3)(
        IMethodInfo* This,
        VARIANT     obj,
        SAFEARRAY* parameters,
        VARIANT* ret);

    DUMMY_METHOD(returnType);
    DUMMY_METHOD(ReturnTypeCustomAttributes);
    DUMMY_METHOD(GetBaseDefinition);

    END_INTERFACE
} MethodInfoVtbl;

typedef struct _MethodInfo {
    MethodInfoVtbl* lpVtbl;
} MethodInfo;

// Rc4EncryptionViaSystemFunc032
// Definition of the USTRING structure used for data encryption / decryption
typedef struct {
    DWORD   Length;         // Size of the data to encrypt/decrypt
    DWORD   MaximumLength;  // Max size of the data to encrypt/decrypt (often the same as Length)
    PVOID   payload;         // Pointer to the data to encrypt/decrypt
} USTRING;

// Typedef for the function pointer for SystemFunction032
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Data,  // Pointer to the data USTRING
    struct USTRING* Key    // Pointer to the key USTRING
    );

/*CLR GUIDS, Stucts -> Mostly from https://github.com/TheWover/donut*/
static GUID xIID_AppDomain = { 0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13} };
static GUID xCLSID_CLRMetaHost = { 0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };
static GUID xIID_ICLRMetaHost = { 0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };
static GUID xIID_ICLRRuntimeInfo = { 0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };
static GUID xIID_ICorRuntimeHost = { 0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
static GUID xCLSID_CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
static GUID xCLSID_ICLRRuntimeHost = { 0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02} };
static GUID xIID_ICLRRuntimeHost = { 0x90F1A06C, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };
static GUID xIID_ICLRAssemblyIdentityManager = { 0x15f0a9da, 0x3ff6, 0x4393, {0x9d, 0xa9, 0xfd, 0xfd, 0x28, 0x4e, 0x69, 0x72} };
static GUID xIID_IAssemblyName = { 0xB42B6AAC, 0x317E, 0x34D5, {0x9F, 0xA9, 0x09, 0x3B, 0xB4, 0x16, 0x0C, 0x50 } };

/* Pipe for redirecting console output of .NET assembly */
#define PIPE_BUFFER_LENGTH 0x10000 * 5

// Etw Patching
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_MOV_INSTRUCTION_OPCODE			0xB8		// 'mov'	- instruction opcode

#define	x64_SYSCALL_STUB_SIZE				0x20		// size of a syscall stub is 32

// https://ntdoc.m417z.com/
// Native API definitions
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // q: UNICODE_STRING
    MemoryRegionInformation, // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation, // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation, // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped, // 10
    MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation, // since WIN11
    MemoryBadInformationAllProcesses, // since 22H1
    MemoryImageExtensionInformation, // MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef NTSYSAPI NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL);
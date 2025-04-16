#pragma once

#include <string> // std::string
#include <unordered_map> // std::unordered_map
#include <windows.h>
#include <winternl.h>
#include <any> // std::any 
#include <iostream> // std::cout, std::endl

/*
    NTAPI functions return a LONG. 
    This return value indicates the function
    was successful.
*/
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

/*
    https://ntdoc.m417z.com/shutdown_action
    
    Undocumented enum used by the Windows API,
    particularly NtShutdownSystem. Denotes the type of
    shutdown for NtShutdownSystem to perform.
*/
typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

/*
    https://ntdoc.m417z.com/client_id

    Typedef for _CLIENT_ID that doesn't exist
    in documented Windows headers for some reason.ABC

    PCLIENT_ID contains a unique thread and process ID 
    Used to start processes by process ID with NtOpenProcess.
*/
typedef struct _CLIENT_ID *PCLIENT_ID;

extern "C" {
    /**
     * https://ntdoc.m417z.com/ntopenprocess
     * Opens an existing process object.
     *
     * @param ProcessHandle A pointer to a handle that receives the process object handle.
     * @param DesiredAccess The access rights desired for the process object.
     * @param ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the attributes of the new process.
     * @param ClientId Optional. A pointer to a CLIENT_ID structure that specifies the client ID of the process to be opened.
     * @return NTSTATUS Successful or errant status.
     */
    NTSTATUS SysNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );
    
    /**
     * The NtClose routine closes the specified handle.
     *
     * @param Handle The handle being closed.
     * @return NTSTATUS Successful or errant status.
     * @sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwclose
     */
    NTSTATUS SysNtClose(HANDLE handle);
    
    /**
     * The NtDuplicateToken function creates a handle to a new access token that duplicates an existing token.
     *
     * @param ExistingTokenHandle A handle to an existing access token that was opened with the TOKEN_DUPLICATE access right.
     * @param DesiredAccess ACCESS_MASK structure specifying the requested types of access to the access token.
     * @param ObjectAttributes Pointer to an OBJECT_ATTRIBUTES structure that describes the requested properties for the new token.
     * @param EffectiveOnly A Boolean value that indicates whether the entire existing token should be duplicated into the new token or just the effective (currently enabled) part of the token.
     * @param Type Specifies the type of token to create either a primary token or an impersonation token.
     * @param NewTokenHandle Pointer to a caller-allocated variable that receives a handle to the newly duplicated token.
     * @return NTSTATUS Successful or errant status.
     * @remarks https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntduplicatetoken
     */
    NTSTATUS SysNtDuplicateToken(
        HANDLE ExistingTokenHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        BOOLEAN EffectiveOnly,
        TOKEN_TYPE Type,
        PHANDLE NewTokenHandle
    );
    
    
    /**
     * The NtOpenProcessTokenEx routine opens the access token associated with a process, and returns a handle that can be used to access that token.
     *
     * @param ProcessHandle Handle to the process whose access token is to be opened. The handle must have PROCESS_QUERY_INFORMATION access.
     * @param DesiredAccess ACCESS_MASK structure specifying the requested types of access to the access token.
     * @param HandleAttributes Attributes for the created handle. Only OBJ_KERNEL_HANDLE is currently supported.
     * @param TokenHandle Pointer to a caller-allocated variable that receives a handle to the newly opened access token.
     * @return NTSTATUS Successful or errant status.
     * @remarks https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenprocesstokenex
     */
    NTSTATUS SysNtOpenProcessTokenEx(
        HANDLE processHandle,
        ACCESS_MASK desiredAccess,
        ULONG handleAttributes,
        PHANDLE tokenHandle
    );
    
    /**
     * Sends a HARDERROR_MSG LPC message to listener (typically CSRSS.EXE).
     * The function used to cause a Blue Screen.
     * 
     * @param ErrorStatus Error code to be displayed on the Blue Screen
     * @param NumberOfParameters Number of optional parameters in Parameters array.
     * @param UnicodeStringParameterMask Optional string parameter (can be only one per error code).
     * @param Parameters Array of DWORD parameters for use in error message string.
     * @param ValidResponseOptions An enum of HARDERROR_RESPONSE_OPTION. See https://ntdoc.m417z.com/harderror_response_option
     * @param Response Pointer to HARDERROR_RESPONSE enum. Inserts the response indicated by the user.
     */
    NTSTATUS SysNtRaiseHardError(
        NTSTATUS ErrorStatus,
        ULONG NumberOfParameters,
        ULONG UnicodeStringParameterMask,
        PULONG_PTR Parameters,
        ULONG ValidResponseOptions,
        PULONG Response
    );
    
    /**
     * Used to ensure the calling thread is not impersonating any security context.
     * 
     * @returns NTSTATUS
     */
    NTSTATUS SysNtRevertContainerImpersonation();
    
    /**
     * Creates a new registry key routine or opens an existing one.
     *
     * @param[out] KeyHandle A pointer to a handle that receives the key handle.
     * @param[in] DesiredAccess The access mask that specifies the desired access rights.
     * @param[in] ObjectAttributes A pointer to an OBJECT_ATTRIBUTES structure that specifies the object attributes.
     * @param[in] TitleIndex Reserved.
     * @param[in, optional] Class A pointer to a UNICODE_STRING structure that specifies the class of the key.
     * @param[in] CreateOptions The options to use when creating the key.
     * @param[out, optional] Disposition A pointer to a variable that receives the disposition value.
     * @return NTSTATUS Successful or errant status.
     */
    NTSTATUS SysNtCreateKey(
        PHANDLE KeyHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG TitleIndex,
        PUNICODE_STRING Class,
        ULONG CreateOptions,
        PULONG Disposition
    );
    
    /**
     * Sets the value of a registry key.
     *
     * @param[in] KeyHandle A handle to the key to be modified.
     * @param[in] ValueName A pointer to a UNICODE_STRING structure that specifies the name of the value to be set.
     * @param[in, optional] TitleIndex Reserved.
     * @param[in] Type The type of the value.
     * @param[in] Data A pointer to a buffer that contains the value data.
     * @param[in] DataSize The size of the buffer.
     * @return NTSTATUS Successful or errant status.
     */
    NTSTATUS SysNtSetValueKey(
        HANDLE KeyHandle,
        PUNICODE_STRING ValueName,
        ULONG TitleIndex,
        ULONG Type,
        PVOID Data,
        ULONG DataSize
    );
    
    /**
     * The NtDelayExecution routine suspends the current thread until the specified condition is met.
     *
     * @param Alertable The function returns when either the time-out period has elapsed or when the APC function is called.
     * @param DelayInterval The time interval for which execution is to be suspended, in milliseconds.
     * - A value of zero causes the thread to relinquish the remainder of its time slice to any other thread that is ready to run.
     * - If there are no other threads ready to run, the function returns immediately, and the thread continues execution.
     * - A value of INFINITE indicates that the suspension should not time out.
     * @return NTSTATUS Successful or errant status. The return value is STATUS_USER_APC when Alertable is TRUE, and the function returned due to one or more I/O completion callback functions.
     * @remarks Note that a ready thread is not guaranteed to run immediately. Consequently, the thread will not run until some arbitrary time after the sleep interval elapses,
     * based upon the system "tick" frequency and the load factor from other processes.
     * @see https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex
     */
    NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
    
    /**
     * Forcefully shuts down the system. This function does not warn processes.
     * 
     * @param The type of SHUTDOWN_ACTION to perform. For example, ShutdownReboot would
     *        tell the system to restart. 
     */
    NTSTATUS SysNtShutdownSystem(SHUTDOWN_ACTION action);

    /**
     * Returns the address of the process environment block (PEB) for the current process.
     * @return Pointer to a PEB struct containing information about the current processes
     *         process environment block (PEB)
     */
    PPEB GetPebAddress();
}

/*
    Handles to dynamically loaded modules.
    These are initialized in the ProcessManager constructor.
*/
inline HMODULE Kernel32DLL = nullptr;
inline HMODULE NTDLL       = nullptr;
inline HMODULE AdvApi32DLL = nullptr;

/*
    A bool denoted whether or not the above modules
    have been loaded.
*/
inline bool DllsLoaded = false;

/**
 * A struct representing a function pointer.
 * 
 * fp is the function signature of the function pointer.
 * For example, an 'fp' template type could look something like
 * SC_HANDLE(WINAPI* _OpenServiceA)( SC_HANDLE, LPCSTR, DWORD )
 * 
 * Above, you would use 'call' like so:
 * function_pointer.call(scm_manager, service_name, GENERIC_READ)
 * 
 * @param call The function pointer that will be called. This should not be NULL.
 * @param name The name of the function.
 * @param from The handle of the module this function is from
 */
template <typename fp>
struct FunctionPointer {
    fp          call;
    std::string name;
    HMODULE     from;
};

/*
    A simple class representing the different
    levels of security context in Windows.

    Specifically for the ProcessManager class to tell
    what context the process token is.
*/
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
    bool               FreeUsedLibrary(const std::string& lib);                     // Free a loaded library 'lib'
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
    bool               OpenProcessAsImposter(HANDLE token, 
                                             DWORD dwLogonFlags, 
                                             LPCWSTR lpApplicationName, 
                                             LPWSTR lpCommandLine, 
                                             DWORD dwCreationFlags, 
                                             LPVOID lpEnvironment, 
                                             LPCWSTR lpCurrentDirectory, 
                                             bool saveOutput, 
                                             std::string& cmdOutput);
    bool               ElevatedPermissions();

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

    const bool NativesLoaded() const { return this->m_NativesLoaded; }

private:
    inline static std::unordered_map<std::string, std::any> m_Natives; // native function pointers
    std::unordered_map<std::string, HMODULE> m_LoadedDLLs;
    bool               m_NativesLoaded    = false;
    SecurityContext    m_Context          = SecurityContext::User;
    HANDLE             m_ElevatedToken    = NULL;

    template <typename type>
    void               LoadNative(const std::string& name, HMODULE from);
    void               LoadAllNatives();
    HMODULE            GetLoadedModule(std::string libName); // Get the handle of a dll 'libname'};
    void               SetThisContext(SecurityContext newContext);
};
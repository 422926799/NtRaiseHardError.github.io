---
layout: post
title: API Monitoring via Userland Hooks and Code Injection Detection
---

# API Monitoring via Userland Hooks and Code Injection Detection

## About This Paper

The following document is a result of self-research of malicious software (malware) and its interaction with the Windows Application Programming Interface (WinAPI). It details the fundamental concepts behind how malware is able to implant malicious payloads into other processes and how it is possible to detect such functionality by monitoring communication with the Windows operating system. The notion of observing calls to the API will also be illustrated by the procedure of _hooking_ certain functions which will be used to achieve the code injection techniques.

**Disclaimer**: Since this was a relatively accelerated project due to some time constraints, I would like to kindly apologise in advance for any potential misinformation that may be presented and would like to ask that I be notified as soon as possible so that it may revised. On top of this, the accompanying code may be under-developed for practical purposes and have unforseen design flaws.

## Introduction

In the present day, malware are developed by cyber-criminals with the intent of compromising machines that may be leveraged to perform activities from which they can profit. For many of these activities, the malware must be able survive out in the wild, in the sense that they must operate covertly with all attempts to avert any attention from the victims of the infected and thwart detection by anti-virus software. Thus, the inception of stealth via code injection was the solution to this problem.

----

# Section I: Fundamental Concepts

## Inline Hooking

Inline hooking is the act of detouring the flow of code via _hotpatching_. Hotpatching is defined as the modification of code during the runtime of an executable image<sup>[1]</sup>. The purpose of inline hooking is to be able to capture the instance of when the program calls a function and then from there, observation and/or manipulation of the call can be accomplished. Here is a visual representation of how normal execution works:

```
Normal Execution of a Function Call

+---------+                                                                       +----------+
| Program | ----------------------- calls function -----------------------------> | Function |  | execution
+---------+                                                                       |    .     |  | of
                                                                                  |    .     |  | function
                                                                                  |    .     |  |
                                                                                  |          |  v
                                                                                  +----------+

```

versus execution of a hooked function:

```
Execution of a Hooked Function Call

+---------+                       +--------------+                    + ------->  +----------+
| Program | -- calls function --> | Intermediate | | execution        |           | Function |  | execution
+---------+                       |   Function   | | of             calls         |    .     |  | of
                                  |       .      | | intermediate   normal        |    .     |  | function
                                  |       .      | | function      function       |    .     |  |
                                  |       .      | v                  |           |          |  v
                                  +--------------+  ------------------+           +----------+

```


This can be separated into three steps. To demonstrate this process, the WinAPI function [MessageBox](https://msdn.microsoft.com/en-us/library/windows/desktop/ms645505(v=vs.85).aspx) will be used.

1. Hooking the function

To hook the function, we first require the intermediate function which **must** replicate parameters of the targetted function. Microsoft Developer Network (MSDN) defines `MessageBox` as the following:

```c
int WINAPI MessageBox(
    _In_opt_ HWND    hWnd,
    _In_opt_ LPCTSTR lpText,
    _In_opt_ LPCTSTR lpCaption,
    _In_     UINT    uType
);
```

So the intermediate function may be defined like so:

```c
int WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    // our code in here
}
```

Once this exists, execution flow has somewhere for the code to be redirected. To actually _hook_ the `MessageBox` function, the first few bytes of the code can be _patched_ (keep in mind that the original bytes must be saved so that the function may be restored for when the intermediate function is finished). Here are the original assembly instructions of the function as represented in its corresponding module `user32.dll`:

```asm
; MessageBox
8B FF   mov edi, edi
55      push ebp
8B EC   mov ebp, esp
```

versus the hooked function:

```asm
; MessageBox
68 xx xx xx xx  push <HookedMessageBox> ; our hooked function
C3              ret
```

Here I have opted to use the `push-ret` combination instead of an absolute `jmp` due to my past experiences of it not being reliable for reasons I have yet to discover. `xx xx xx xx` represents the little-endian byte-order address of `HookedMessageBox`.

2. Capturing the function call

When the program calls `MessageBox`, it will execute the `push-ret` and effectively jump into the `HookedMessageBox` function and once there, it has complete control over the paramaters and the call itself. To replace the text that will be shown on the message box dialog, the following can be defined in `HookedMessageBox`:

```c
int WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    TCHAR szMyText[] = TEXT("This function has been hooked!");
}
```

`szMyText` can be used to replace the `LPCTSTR lpText` parameter of `MessageBox`.

3. Resuming normal execution

To forward this parameter, execution needs to continue to the original `MessageBox` so that the operating system can display the dialog. Since calling `MessageBox` again will just result in an infinite recursion, the original bytes must be restored (as previously mentioned).

```c
int WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    TCHAR szMyText[] = TEXT("This function has been hooked!");
    
    // restore the original bytes of MessageBox
    // ...
    
    // continue to MessageBox with the replaced parameter and return the return value to the program
    return MessageBox(hWnd, szMyText, lpCaption, uType);
}
```

If rejecting the call to `MessageBox` was desired, it is as easy as returning a value, preferrably one that is defined in the documentation. For example, to return the "No" option from a "Yes/No" dialog, the intermediate function can be:

```c
int WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    return IDNO;  // IDNO defined as 7
}
```


## API Monitoring

The concept of API monitoring follows on from function hooking. Because gaining control of function calls is possible, observation of all of the parameters is also possible, as previously mentioned hence the name _API monitoring_. However, there is a small issue which is caused by the availability of different high-level API calls that are unique but operate using the same set of API at a lower level. This is called _function wrapping_, defined as _subroutines whose purpose is to call a secondary subroutine_. Returning to the `MessageBox` example, there are two defined functions: `MessageBoxA` for parameters that contain ASCII characters and a `MessageBoxW` for parameters that contain wide characters. In reality, to hook `MessageBox`, it is required that both `MessageBoxA` **and** `MessageBoxW` be patched. The solution to this problem is to hook at the **lowest** possible **common** point of the function call hierarchy. 

```
                                                      +---------+
                                                      | Program |
                                                      +---------+
                                                     /           \
                                                    |             |
                                            +------------+   +------------+
                                            | Function A |   | Function B |
                                            +------------+   +------------+
                                                    |             |
                                            +-----------------------------+
                                            |         Windows API         |
                                            +-----------------------------+
       +---------+       +-------- hook -----------------> |
       |   API   | <---- +              +-------------------------------------+
       | Monitor | <-----+              |                ntdll                |
       +---------+       |              +-------------------------------------+
                         +-------- hook -----------------> |                           User mode
                                 -----------------------------------------------------
                                                                                       Kernel mode
```

Here is what the `MessageBox` call hierarchy looks like:

Here is `MessageBoxA`:

```
user32!MessageBoxA -> user32!MessageBoxExA -> user32!MessageBoxTimeoutA -> user32!MessageBoxTimeoutW
```

and `MessageBoxW`:

```
user32!MessageBoxW -> user32!MessageBoxExW -> user32!MessageBoxTimeoutW
```

The call hierarchy both funnel into `MessageBoxTimeoutW` which is an appropriate location to hook. For functions that have a deeper hierarchy, hooking any lower could prove to be unecessarily troublesome due to the possibility of an increasing complexity of the function's parameters. `MessageBoxTimeoutW` is an undocumented WinAPI function and is defined<sup>[2]</sup> like so:

```
int WINAPI MessageBoxTimeoutW(
    HWND hWnd, 
    LPCWSTR lpText, 
    LPCWSTR lpCaption, 
    UINT uType, 
    WORD wLanguageId, 
    DWORD dwMilliseconds
);
```

To log the usage:

```c++
int WINAPI MessageBoxTimeoutW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType, WORD wLanguageId, DWORD dwMilliseconds) {
    std::wofstream logfile;     // declare wide stream because of wide parameters
    logfile.open(L"log.txt", std::ios::out | std::ios::app);
    
    logfile << L"Caption: " << lpCaption << L"\n";
    logfile << L"Text: " << lpText << L"\n";
    logfile << L"Type: " << uType << :"\n";
    
    logfile.close();
    
    // restore the original bytes
    // ...
    
    // pass execution to the normal function and save the return value
    int ret = MessageBoxTimeoutW(hWnd, lpText, lpCaption, uType, wLanguageId, dwMilliseconds);
    
    // rehook the function for next calls
    // ...
    
    return ret;   // return the value of the original function
}
```

Once the hook has been placed into `MessageBoxTimeoutW`, `MessageBoxA` and `MessageBoxW` should both be captured.

----

## Code Injection Primer

For the purposes of this paper, code injection will be defined as the insertion of executable code into an external process. The possibility of injecting code is a natural result of the functionality allowed by the WinAPI. If certain functions are stringed together, it is possible to access an existing process, write data to it and then execute it remotely under its context. In this section, the relevant techniques of code injection that was covered in the research will be introduced.

### DLL Injection

Code can come from a variety of forms, one of which is a _Dynamic Link Library_ (DLL). DLLs are libraries that are designed to offer extended functionality to an executable program which is made available by exporting subroutines. Here is an example DLL that will be used for the remainder of the paper:

```c++
extern "C" void __declspec(dllexport) Demo() {
    ::MessageBox(nullptr, TEXT("This is a demo!"), TEXT("Demo"), MB_OK);
}

bool APIENTRY DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH)
        ::CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Demo, nullptr, 0, nullptr);
    return true;
}
```

When a DLL is loaded into a process and initialised, the loader will call `DllMain` with `fdwReason` set to `DLL_PROCESS_ATTACH`. For this example, when it is loaded into a process, it will thread the `Demo` subroutine to display a message box with the title `Demo` and the text `This is a demo!`. To correctly finish the initialisation of a DLL, it must return `true` or it will be unloaded.

#### CreateRemoteThread

DLL injection via the [CreateRemoteThread](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx) function utilises this function to execute a remote thread in the virtual space of another process. As mentioned above, all that is required to execute a DLL is to have it load into the process by forcing it to execute the `LoadLibrary` function. The following code can be used to accomplish this:

```c++
void injectDll(const HANDLE hProcess, const std::string dllPath) {
    LPVOID lpBaseAddress = ::VirtualAllocEx(hProcess, nullptr, dllPath.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
    ::WriteProcessMemory(hProcess, lpBaseAddress, dllPath.c_str(), dllPath.length(), &dwWritten);
  
    HMODULE hModule = ::GetModuleHandle(TEXT("kernel32.dll"));
  
    LPVOID lpStartAddress = ::GetProcAddress(hModule, "LoadLibraryA");      // LoadLibraryA for ASCII string
  
    ::CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, nullptr);
}
```

MSDN defines [LoadLibrary](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175(v=vs.85).aspx) as:

```c
HMODULE WINAPI LoadLibrary(
    _In_ LPCTSTR lpFileName
);
```

It takes a single parameter which is the path name to the desired library to load. The `CreateRemoteThread` function allows one parameter to be passed into the thread routine which matches exactly that of `LoadLibrary`'s function definition. The goal is to allocate the string parameter in the virtual address space of the target process and then pass that allocated space's address into the parameter argument of `CreateRemoteThread` so that `LoadLibrary` can be invoked to load the DLL.

1. Allocating virtual memory in the target process

Using `VirtualAllocEx` allows space to be allocated within a selected process and on success, it will return the starting address of the allocated memory.

```
Virtual Address Space of Target Process
                                              +--------------------+
                                              |                    |
                        VirtualAllocEx        +--------------------+
                        Allocated memory ---> |     Empty space    |
                                              +--------------------+
                                              |                    |
                                              +--------------------+
                                              |     Executable     |
                                              |       Image        |
                                              +--------------------+
                                              |                    |
                                              |                    |
                                              +--------------------+
                                              |    kernel32.dll    |
                                              +--------------------+
                                              |                    |
                                              +--------------------+
```

2. Writing the DLL path to allocated memory

Once memory has been initialised, the path to the DLL can be injected into the allocated memory returned by `VirtualAllocEx` using `WriteProcessMemory`.

```
Virtual Address Space of Target Process
                                              +--------------------+
                                              |                    |
                        WriteProcessMemory    +--------------------+
                        Inject DLL path ----> | "..\..\myDll.dll"  |
                                              +--------------------+
                                              |                    |
                                              +--------------------+
                                              |     Executable     |
                                              |       Image        |
                                              +--------------------+
                                              |                    |
                                              |                    |
                                              +--------------------+
                                              |    kernel32.dll    |
                                              +--------------------+
                                              |                    |
                                              +--------------------+
```

3. Get address of `LoadLibrary`

Since all system DLLs are mapped to the same address space across all processes, the address of `LoadLibrary` does not have to be directly retrieved from the target process. Simply calling `GetModuleHandle(TEXT("kernel32.dll"))` and `GetProcAddress(hModule, "LoadLibraryA")` will do the job.

4. Loading the DLL

The address of `LoadLibrary` and the path to the DLL are the two main elements required to load the DLL. Using the `CreateRemoteThread` function, `LoadLibrary` is executed under the context of the target process with the DLL path as a parameter.

```
Virtual Address Space of Target Process
                                              +--------------------+
                                              |                    |
                                              +--------------------+
                                   +--------- | "..\..\myDll.dll"  |
                                   |          +--------------------+
                                   |          |                    |
                                   |          +--------------------+ <---+
                                   |          |     myDll.dll      |     |
                                   |          +--------------------+     |
                                   |          |                    |     | LoadLibrary
                                   |          +--------------------+     | loads
                                   |          |     Executable     |     | and
                                   |          |       Image        |     | initialises
                                   |          +--------------------+     | myDll.dll
                                   |          |                    |     |
                                   |          |                    |     |
          CreateRemoteThread       v          +--------------------+     |
          LoadLibraryA("..\..\myDll.dll") --> |    kernel32.dll    | ----+
                                              +--------------------+
                                              |                    |
                                              +--------------------+
```

#### SetWindowsHookEx

Windows offers developers the ability to monitor certain events with the installation of _hooks_ by using the [SetWindowsHookEx](https://msdn.microsoft.com/en-us/library/windows/desktop/ms644990(v=vs.85).aspx) function. While this function is very common in the monitoring of keystrokes for keylogger functionality, it can also be used to inject DLLs. The following code demonstrates DLL injection into itself:

```c++
int main() {
    HMODULE hMod = ::LoadLibrary(DLL_PATH);
    HOOKPROC lpfn = (HOOKPROC)::GetProcAddress(hMod, "Demo");
    HHOOK hHook = ::SetWindowsHookEx(WH_GETMESSAGE, lpfn, hMod, ::GetCurrentThreadId());
    ::PostThreadMessageW(::GetCurrentThreadId(), WM_RBUTTONDOWN, (WPARAM)0, (LPARAM)0);

    // message queue to capture events
    MSG msg;
    while (::GetMessage(&msg, nullptr, 0, 0) > 0) {
        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
    }
    
    return 0;
}
```

`SetWindowsHookEx` defined by MSDN as:

```c
HHOOK WINAPI SetWindowsHookEx(
    _In_ int       idHook,
    _In_ HOOKPROC  lpfn,
    _In_ HINSTANCE hMod,
    _In_ DWORD     dwThreadId
);
```

takes a `HOOKPROC` parameter which is a user-defined callback subroutine that is executed when the specific hook event is trigged. In this case, the event is `WH_GETMESSAGE` which deals with messages in the message queue. The code initially loads the DLL into its own virtual process space and the exported `Demo` function's address is obtained and defined as the callback function in the call to `SetWindowsHookEx`. To force the callback function to execute, `PostThreadMessage` is called with the message `WM_RBUTTONDOWN` which will trigger the `WH_GETMESSAGE` hook and thus the message box will be displayed.

#### QueueUserAPC

DLL injection with [QueueUserAPC](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684954(v=vs.85).aspx) works similarly to that of `CreateRemoteThread`. Both allocate and inject the DLL path into the virtual address space of a target process and then force a call to `LoadLibrary` under its context.

```c++
int main() {
    HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);

    HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, false, dwThreadId);
    
    LPVOID lpLoadLibraryParam = ::VirtualAllocEx(hProcess, nullptr, dllPath.length(), MEM_COMMIT, PAGE_READWRITE);
    
    ::WriteProcessMemory(hProcess, lpLoadLibraryParam, dllPath.data(), dllPath.length(), &dwWritten);
    
    ::QueueUserAPC((PAPCFUNC)::GetProcAddress(::GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA"), hThread, (ULONG_PTR)lpLoadLibraryParam);
    
    return 0;
}
```

One major difference between this and `CreateRemoteThread` is that `QueueUserAPC` operates on _alertable states_. Asynchronous procedures queued by `QueueUserAPC` are only handled when a thread enters this state.

### Process Hollowing

Process hollowing, AKA RunPE, is a popular method used to bypass anti-virus detection. It allows executable files to be loaded into a target process and executed under its context.

----

# References:

* [1] https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Sotirov.pdf
* [2] https://www.codeproject.com/Articles/7914/MessageBoxTimeout-API

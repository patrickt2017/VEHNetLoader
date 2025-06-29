# VEHNetLoader
Another version of .NET loader provides capabilities of bypassing ETW and AMSI, utilizing VEH for syscalls and loading .NET assemblies

# Explanation
## Vectored Syscalls
Syscalls via Vectored Exception Handling (as known as Vectored Syscalls) run Native APIs in a form of indirect syscalls as shown below. It firstly calls the native API with address of SSN to trigger `ACCESS_VIOLATION` exception. The registered vectored exception handler will form the structure of syscalls. The RIP has stored the SSN, since we pass SSN to the address previously. We could copy RIP to EAX for SSN and set RIP to the address of the stub syscall instruction from a Native API (e.g. `NtDrawText()` in this case).
```
mov r10, rcx
mov eax, [SSN]
syscall
```

It is worth noting that EDR or malware analyst may still detect our abnormal syscalls by inspecting the call stack of the native API, since the caller address (syscall) is in the memory region of `NtDrawText()` instead of that of the original native API.

![](/images/Syscalls_VEH_concept.png)
(Reference: https://redops.at/en/blog/syscalls-via-vectored-exception-handling)

## ETW Patching
ETW providers usually call common WinAPIs such as `EtwEventWrite` and `EtwEventWriteFull` to pass the events to ETW tracing session. At the end, The Native API `NtTraceEvent` is called by these ETW functions. Hence, We could directly apply byte patching to replace its SSN to a dummy value to cause the syscall failure.

For ETW CLR providers, please refer to Microsoft's documentation: https://learn.microsoft.com/en-us/dotnet/framework/performance/clr-etw-providers.

## AMSI Patching
Practical Securiy Analytics LLC has discussed Microsoft's new behavior detection signature protecting AMSI API in https://practicalsecurityanalytics.com/obfuscating-api-patches-to-bypass-new-windows-defender-behavior-signatures/. 

The new technique is to overwrite the string `AmsiScanBuffer` in `.rdata` section of CLR.dll with dummy values, so that it will trigger an error in `GetProcAddress` function call and CLR.dll cannot resolve the method from amsi.dll. 

Moreover, AMSI is responsible to scan any assembly content during reflective assembly loads in CLR environment, hence bypassing AMSI here is critical for us to avoid being detected by AMSI and EDR. 

## RC4 Encryption
Other encryption algorithms, such as AES or XOR, should also be applicable, since the primary purpose is to protect our payload placed on disk against EDR detection. Without bypassing techniques, the payload could still be possibily detected when decrypted and loaded into memory regions in the current process.

## CLR Hosting
The .NET loader references to a few resoruces in the resource and credits section for me to understand and implement CLR hosting to load .NET assemblies and invoke the EntryPoint in the assembly with the user-provided arguments. Throughout reading materials, both `Load_3` and `Invoke_3` API calls require to pass a byte array (`SAFEARRAY`) as an argument.

`Load_3`:

![](/images/CLR-Load_3.png)

`Invoke_3`:

![](/images/CLR-Invoke_3.png)

# Usage
```
.\VEHNetLoader.exe -pe <payload> -key <key> -parm <arguments>
```

An example...

Sophos EDR:
![](/images/Sophos-EDR.png)

# Resources and Credits
Special Thanks to the following resources for me to learn a lot of writing .NET loaders and bypassing techniques.

1. Basics of Loading .NET assemblies using C
    - HostingCLR: https://github.com/etormadiv/HostingCLR
    - Being-A-Good-CLR-Host: https://github.com/passthehashbrowns/Being-A-Good-CLR-Host
2. Existing .NET Loaders (especially for loading user-controlled arguments into .Net assemblies)
    - BetterNetLoader: https://github.com/racoten/BetterNetLoader
    - PatchedCLRLoader: https://github.com/alexlee820/PatchedCLRLoader
3. AMSI Bypass to prevent runtime loading .NET modules into Anti-virus - Practical Security Analytics LLC: https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/
4. ETW Patching - AMSI-ETW-Patch: https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch
5. Syscalls via Vectored Exception Hanlding - RedOps: https://redops.at/en/blog/syscalls-via-vectored-exception-handling

# Disclaimer
This tool is developed for learning purposes only. Do not use this tool for any illegal, unauthorized or malicious activities.

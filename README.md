# Profiling EDR Telemetry Sources Before Implementing Evasion Techniques


> *Forenote: Real EDR environments can have configurations that do not match your test environment, even if you are using the same EDR product as your adversary. So, this isn't really a one-shot problem solver. It is just interesting, and it might help. Maybe this blog should really be called: Why Not To Use Syscalls.*

There is a current issue I think a lot of ethical hackers might be facing: they use an indirect syscall without really knowing if it's appropriate to do so - it's almost obligatory. It's important to know if the target EDR actually relies on your obligatory hooks for detection.
Of course, this matters because syscalls add complexity to your tooling, and they can even introduce their own detection surface.

So, in this post I will walk you through a controlled experiment against OpenEDR v2.5.1, which will prove my point. I will be utilizing a custom hook scanner and syscall test harness. The goal here is to show you whether indirect syscalls are even worth using in the first place. I'd just like to make a quick note: even though in this experiment I used OpenEDR v2.5.1 this methodology should be applicable to any EDR solution. 

**Also, check the releases tab for the two programs.

---

## The Decision Framework

I think the most important thing to understand before reading the rest of this post is the thought process behind this tooling. So I'm putting this up front.

**Step 1: Define your operation.** Let's say you need to inject into a remote process. That means you need to call some combination of NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, etc.

**Step 2: Run the hook scanner.** Make sure to get a clean snapshot for the associated Windows version first. After running it on the machine with the EDR installed, you compare reports and see that NtWriteVirtualMemory is hooked, but NtAllocateVirtualMemory and NtCreateThreadEx are not. Now you know which of your required functions have usermode interception points — and more importantly, which ones definitively don't. For the unhooked functions, indirect syscalls are unnecessary.

**Step 3:** Realize that a hook being present tells you the EDR can intercept that call, but it does not tell you that it does anything useful with that interception. The hook might log, it might block, it might inspect parameters and only act on suspicious patterns, or it might feed a rule engine that silently drops the event. You don't know from the scan alone.

**Step 4: Test with the syscall harness.** Call the hooked functions through the normal path and observe whether telemetry or blocking occurs. If that does occur, then test with direct and indirect paths and observe again. If the normal path produces nothing, you've answered the question — the hook isn't your problem.

**Step 5: Think about what else is watching.** Even if an indirect syscall bypasses the hook's telemetry, that might not be enough. NtWriteVirtualMemory to a remote process might not trigger the usermode hook's telemetry, but the kernel callback for cross-process handle operations or the ETW provider might still see it. Bypassing one layer doesn't mean you've bypassed all layers.

---

## The Hook Scanner

I think before choosing an evasion technique to be used against an EDR it's important to actually know what the EDR product is doing. That means you need to be able to scan the process for inline hooks — mapping the hooked functions, the DLLs they are applied to, and where they redirect. That is why I built a hook scanner.

### Why It Matters

The scanner's primary value isn't telling you what is hooked. It's telling you what isn't. If a function isn't hooked, you know with 100% certainty that indirect syscalls are unnecessary for that function. That's a deterministic answer you can't get any other way. The hooked functions are where certainty ends and testing begins — but without the scanner, you don't even know which functions need testing.

EDR vendors don't publish their hook lists. It's treated as implementation detail that they don't want adversaries to know.

### How It Works

The scanner first takes a snapshot. Every DLL on disk contains the original, unmodified function code. When an EDR hooks a function, it overwrites the first few bytes in memory — usually with a JMP instruction. The scanner reads both versions, compares them byte by byte, and flags any differences.

It optionally covers ntdll, kernel32, kernelbase, user32, win32u, advapi32, and several other DLLs. When it finds a mismatch, it classifies what kind of hook was placed (E9 relative JMP, FF25 indirect JMP, MOV RAX/JMP RAX, etc.), resolves where the hook redirects to, identifies which module owns that destination, and rates severity. It also supports baseline snapshots — you can scan a clean system before installing an EDR and save the report, then scan again after installation. With both reports side by side, you can identify which hooks were introduced by the EDR versus OS-level relocations and legitimate variations that were already present.


<img width="1266" height="723" alt="HookedHookScanner" src="https://github.com/user-attachments/assets/9239da66-2cd9-479d-9369-702742cb1f77" />


---

## The Hook Map

Running the scanner on a Windows 11 VM with OpenEDR v2.5.1 installed produced 28 findings across 5 DLLs:

### ntdll.dll — 4 unique hooked functions:

- NtReadVirtualMemory (SSN 0x3F)
- NtWriteVirtualMemory (SSN 0x3A)
- NtSetInformationThread (SSN 0x0D)
- NtCreateSymbolicLinkObject (SSN 0xC8)

### user32.dll — 10 hooks

Covering keystate monitoring (GetAsyncKeyState, GetKeyState), clipboard access (GetClipboardData, SetClipboardViewer), window hooking (SetWindowsHookExA), input simulation (keybd_event, mouse_event), and system parameter access (SystemParametersInfoA/W, EnableWindow).

### win32u.dll — 6 hooks

On GUI-layer syscall stubs: NtUserSendInput, NtUserGetKeyboardState, NtUserBlockInput, NtUserClipCursor, NtUserRegisterHotKey, NtUserRegisterRawInputDevices.

### advapi32.dll — 2 hooks

CreateProcessWithLogonW and ImpersonateNamedPipeClient.

### kernel32.dll — 2 hooks

ExitProcess and FatalExit.

[hook scanner full report screenshot here]

Every hook uses the same pattern — a 5-byte E9 relative JMP overwriting the function prologue. Every hook destination resolves to an unknown module, meaning the trampolines land in an unbacked executable memory region. This is characteristic of MadcHook's injection framework, which OpenEDR uses to place hooks from its injected DLL (edrpm64.dll).

Two observations worth noting here:

First, only 4 out of 28 hooks are on ntdll syscall stubs. The remaining 24 are on user32, win32u, advapi32, and kernel32 — functions that indirect ntdll syscalls won't touch.

Second, the win32u hooks target GUI-layer syscall stubs that go through a different dispatch path (win32k.sys) than ntdll syscalls (ntoskrnl). An indirect syscall technique targeting ntdll gadgets doesn't help against win32u hooks. These are rarely discussed in the offensive security community, but they cover keylogging and input injection detection — relevant to operators deploying keyloggers or input simulation.

---

## The Syscall Harness

With the hook map in hand, I built a test harness to answer the real question: does bypassing these hooks change what the EDR detects?

The harness runs each hooked ntdll function through three execution paths:

**Path A — Normal API call.** Calls the function through ntdll normally. Execution hits the E9 hook, flows through the EDR's trampoline, and then completes the syscall. If the hook generates telemetry, this path will produce it.

**Path B — Direct syscall.** Loads the SSN into EAX and executes the syscall instruction from the harness's own .text section. Completely bypasses the hook. Return address points to the harness module.

**Path C — Indirect syscall.** Same SSN setup, but instead of executing syscall directly, JMPs to a syscall; ret gadget inside ntdll's .text section (found by scanning for the 0F 05 C3 byte sequence at runtime). Bypasses the hook and the return address points into ntdll.

For NtReadVirtualMemory and NtWriteVirtualMemory, the test targets a remote process — spawning notepad.exe and performing cross-process memory read/write. Self-process memory operations are too benign to be detection-relevant. For NtSetInformationThread, the test sets ThreadHideFromDebugger — an inherently suspicious operation used by a lot of anti-debug malware.

All telemetry was monitored through OpenEDR's ELK pipeline (Filebeat shipping from the output_events directory to Elasticsearch/Kibana on a separate VM) and verified against the raw local telemetry log on the endpoint.

[syscall harness menu screenshot here]

[syscall harness running NtReadVirtualMemory screenshot here]

---

## Results

When tested against OpenEDR's four hooked ntdll functions, none of the three execution paths — normal API, direct syscall, or indirect syscall — produced telemetry events. This was confirmed both through the ELK pipeline and the raw local telemetry log on the endpoint.

The only telemetry OpenEDR consistently produced throughout testing was process creation events (logging the spawned notepad.exe and the harness itself) and file I/O events. These come from kernel callbacks and the minifilter — not from the usermode hooks.

This means the hooks didn't matter. A red teamer who scans this endpoint, sees 28 hooks, and deploys indirect syscalls has optimized against the wrong layer entirely.

[Kibana showing process creation events but no syscall telemetry screenshot here]

[raw local telemetry log showing no syscall events screenshot here]

---

## What's Actually Happening

Looking at the architecture of OpenEDR explains the result. The service logs reveal that MadcHook is the active hooking engine (despite v2.5.1 release notes claiming its removal). The hooks are placed by the injected DLL (edrpm64.dll), loaded into every process by the kernel driver (edrdrv.sys).

However, the hook data doesn't flow directly to the telemetry log. OpenEDR uses a compiled pipeline of .qsc scripts - filter_lle.qsc, match_patterns.qsc, apply_policy.qsc, output.qsc — that process raw events through pattern matching and policy rules before anything reaches output_events. Only events matching configured patterns get written.

---

## When Indirect Syscalls Hurt You

So OpenEDR's hooks weren't producing telemetry. What would have happened if I had deployed indirect syscalls against them anyway?

This is the part a lot of blogs skip — indirect syscalls are not just potentially useless, they can actually make your operation more detectable. Because when you execute a syscall from your own code or jump to a gadget, you end up introducing artifacts that don't exist in a normal API call.

**Unbacked code execution.** If your tool runs from VirtualAlloc'd memory or a reflectively loaded DLL, the return address (for direct syscalls) or the calling module is in an unbacked region. Some EDRs track whether syscall-adjacent instructions originate from legitimate image-backed memory.

**Gadget scanning.** Some EDRs implement gadget scanning, though it's not widely deployed yet.

**Instrumentation callbacks.** NtSetInformationProcess with ProcessInstrumentationCallback allows a process to register a callback that fires on every return from kernel mode. If an EDR uses that, it can observe the syscall regardless of how it was invoked from usermode.

Against an EDR like OpenEDR — where the hooks aren't producing telemetry — deploying indirect syscalls means introducing all of this potential detection surface in exchange for bypassing a detection mechanism that wasn't active. You've made yourself more visible for zero gain.


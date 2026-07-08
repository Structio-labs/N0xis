---
tags: [spec, backend, frontend-contract, tauri, project/n0x]
aliases: [Backend Spec]
---

> Navigation: [[PROJECTS|Map]] · [[CLI_FEATURES_SPEC|CLI Spec]] · **Backend Spec** · [[README|Frontend README]] · [[n0x-cli-rs/README|CLI README]]

# N0x Backend Integration Specification

> The Rust CLI ([[n0x-cli-rs/README|n0x-cli-rs]]) is the practical implementation of the services required below. Use it directly from Tauri via `invoke` over the JSON contract in [[CLI_FEATURES_SPEC#output-contracts]].

> **Desktop (`src-tauri`):** the backend resolves the CLI by scanning the **current working directory**, its **parent** (so `cargo tauri dev` from `…/N0x/src-tauri` still finds `…/N0x/n0x-cli-rs/target/…`), and by walking up until `n0x-cli-rs/Cargo.toml` exists. Override anytime with env **`N0X_CLI_BIN`** (absolute path to `n0x.exe` / `n0x-cli-rs.exe` / project `n0x.cmd`).

## Overview
N0x is a professional reverse engineering and game analysis tool frontend built with React, TypeScript, and Tailwind CSS. While currently running in a web environment, it is designed for **Tauri** integration to access native system APIs.

## Communication Pattern
In a production desktop environment, the frontend expects to use **Tauri's `invoke`** for commands and **`listen`** for real-time events (e.g., process crashes, new modules loaded).

### Core Services Needed
1. **Process Manager**: Listing, attaching, and monitoring system processes.
2. **Memory Engine**: Reading/Writing memory, virtual memory page analysis.
3. **Debugger/Disassembler**: Instructions decoding (using Capstone/Zydis), managing breakpoints.
4. **Pattern Engine**: Fast AOB (Array of Bytes) scanning in remote process memory.

---

## 1. Data Models

### Process Entity
```typescript
interface Process {
  pid: number;
  name: string;
  arch: 'x64' | 'x86';
  cpu: number;         // Current CPU usage %
  memory: string;      // Formatted string (e.g., "124.5 MB")
  threads: number;
  path: string;        // Full executable path
  status: 'Running' | 'Suspended' | 'Terminated';
}
```

### Module Entity
```typescript
interface Module {
  name: string;
  baseAddress: string; // Hex string (e.g., "0x7FF7...")
  size: number;
  path: string;
}
```

### Memory Region
```typescript
interface MemoryRegion {
  address: string;
  size: number;
  protection: string; // e.g., "PAGE_EXECUTE_READWRITE"
  type: string;       // MEM_COMMIT / MEM_FREE / etc.
  tag?: string;       // .text, .data, etc.
}
```

---

## 2. API / Command Requirements

### Process Management
- **`get_processes()`**: Returns a full list of active processes. Needs to be efficient (virtualization used on frontend).
- **`attach_to_process(pid: number)`**: Initializes a handle to the target process. Must return success/failure (Access Denied / PID Not Found).
- **`detach_process()`**: Safely closes handles.

### Memory Operations
- **`read_memory(address: string, size: number)`**: Returns Raw Bytes (Uint8Array). Crucial for Hex Viewer.
- **`write_memory(address: string, bytes: number[])`**: Writes data to process memory. Should handle protection changes automatically if possible (VirtualProtect).
- **`scan_pattern(pattern: string, start: string, end: string)`**: Returns a list of addresses where the signature (e.g., `48 8B ?? ?? ??`) matches.

### Analysis & Disassembly
- **`disassemble_region(address: string, count: number)`**: Returns decoded instructions.
  ```typescript
  interface Instruction {
    address: string;
    bytes: string;
    mnemonic: string;
    operands: string;
    comment?: string;
  }
  ```

---

## 3. Real-time Events (WebSockets or Tauri Events)
The backend should stream the following events to the frontend:
- `on_process_exit`: To clear the current session.
- `on_module_load`: Triggered when a DLL is injected or loaded.
- `on_console_log`: System-level logs (Kernel messages, errors).

---

## 4. Current Frontend State
Store management is implemented using **Zustand** in `/src/store.ts`. 
- `attachedProcess`: Stores the current target.
- `tabs`: Managing multiple analysis views.

## 5. Security & Permissions
The backend must handle privilege escalation (`SeDebugPrivilege`) where necessary to access protected processes.

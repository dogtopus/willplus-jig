# willplus-jig

## Build

```
npm install
npm build  # Or build-fast if using V8
```

To enable automatic building on modification, use

```
npm watch  # Or watch-fast if using V8
```

To target a different game (defaults to Haruka ni Aogi, Uruwashi no zh_TW edition), edit index.ts to include the corresponding offset file and rebuild.

## Usage

### Inside frida REPL

```
# Spawn a new process, attach and immediately resume execution, with V8 runtime.
frida -l willplus-jig.js -f path\to\game.exe --no-pause --runtime=v8
```

All the features are accessible via the REPL.

### As a RPC agent

Load `willplus-jig.js` with your custom host script, then use RPC to access all the features.

## Exported functions

- `flagbank_peek(addr)` and `flagbank_poke(addr, value)`
  - Peek/poke the flag bank.
- `flagbank_list_non_zero(from_addr, to_addr)`
  - Returns a `Map` of all non-zero flags from `from_addr` to `to_addr` along with their current values.
- `rio_traceback()`
  - Returns an array that contains traceback of RIO script (can be used after a script excuting (sic) error before closing the msgbox).
- `rio_goto(label)`
  - Jump to a RIO script (label). Return 0 if it fails.
- `rio_call(label)`
  - Call a RIO script (label). Return 0 if it fails.
- `rio_register_script(addr, name)`
  - Register `addr` an in-memory script and label it `name`. Use it with `Memory.alloc` for ad-hoc script injection and execution.
- `rio_delete_script(name)`
  - Delete an in-memory script. Return `true` if the operation succeeded.
- `rio_list_registered_script()`
  - Returns an array of all registered in-memory script label.
- `rio_set_pc(pc)`
  - Sets the program counter of the VM (relative to the start of the script).
- `rio_get_pc()`
  - Returns the program counter of the VM.
- `rio_get_current_script_buffer()`
  - Returns a `NativePointer` to the current script buffer. Useful for ad-hoc script patching.

## Supported games

- Haruka ni Aogi, Uruwashi no (zh_TW release) (`offset.kanitw.json`)
- Laughter Land (zh_TW release) (`offset.lltw.json`)

### Adding support for new games

Support for other WillPlus games that uses close enough engine should be possible by reverse engineering the offsets for some critical functions and structures and writing a `offset.json` file. Below is a list of all used structures and functions.

- `will_flagbank`
  - Base address for the flag bank that holds all temporary/persistent flags and registers (magic flags that alters the engine behavior). Can typically be found by searching `memset` usage with size=2000 (clear all temporary flags).
- `rio_goto`
  - Function that loads and jumps to a specific RIO script. Can be found by searching for the interpreter and looking for the implementation for `goto` instruction (opcode `0x07`)
- `rio_call`
  - Function that saves the current PC to the RIO call stack and calls `rio_goto` to load (call) another script. Can be found by looking the implementation of `call` instruction (opcode `0x09`) or xrefing for functions that call `rio_goto` internally.
- `rio_current_script`
  - Pointer that points to the current loaded script. Can be found by looking at the implementation of `rio_goto` (HINT: it usually `free()`s the previously loaded script before doing anything else).
- `rio_pc`
  - Program counter of the RIO VM. Contains a pointer to some place within `*rio_current_script`. Can be found by looking at the interpreter for an incrementing pointer.
- `rio_sp`
  - Call stack pointer of the RIO VM. Usually contains a number between 0 and 7 (since the stack size is usually 8). Can be found by looking at the implementation of `rio_call`.
- `rio_stack_base`
  - Base address of the call stack. Can be found by looking at the implementation of `rio_call`.
- `rio_event_id`
  - "Event ID" of the currently executing script. Printed on `rio_traceback()`. Probably used by the engine as a way to mark seen text. Can be found by looking the implementation of `event_id` instruction (opcode `0x8c`).
- `rio_current_label`
  - Current name (label) of the script. Can be found by Can be found by looking at the implementation of `rio_goto` for `memcpy` (could be inlined).
- `engine_malloc_stub` and `engine_free_stub`
  - Engine's `malloc` and `free` implementation.

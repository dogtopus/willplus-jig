import iconv from "iconv-lite";
import shajs from "sha.js";
import { DataOffset, offsets } from "./offsets";


const CreateFileW_ptr = Module.getExportByName('kernel32.dll', 'CreateFileW');
const ReadFile_ptr = Module.getExportByName('kernel32.dll', 'ReadFile');
const CloseHandle_ptr = Module.getExportByName('kernel32.dll', 'CloseHandle');
const CreateFileW = new NativeFunction(CreateFileW_ptr, 'pointer', ['pointer', 'int32', 'int32', 'pointer', 'int32', 'int32', 'pointer']);
const ReadFile = new NativeFunction(ReadFile_ptr, 'int', ['pointer', 'pointer', 'int32', 'pointer', 'pointer']);
const CloseHandle = new NativeFunction(CloseHandle_ptr, 'int', ['pointer']);
const MessageBoxA_ptr = Module.getExportByName('USER32.dll', 'MessageBoxA');
const MessageBoxW_ptr = Module.getExportByName('USER32.dll', 'MessageBoxW');
const MessageBoxW = new NativeFunction(MessageBoxW_ptr, 'int', ['pointer', 'pointer', 'pointer', 'uint32']);
const GENERIC_READ = 1 << 31;
const FILE_SHARE_READ = 1;
const OPEN_EXISTING = 3;
const FILE_ATTRIBUTE_NORMAL = 1 << 7;
const INVALID_HANDLE_VALUE = ptr('-1');


function _match_known_adv_exe(): DataOffset | null {
    // TODO rewrite this with frida-fs after we add Windows support to it...
	const buffer_size = 16384;
	const exemodule = Process.enumerateModules()[0];
	const exepath = exemodule.path;
	const exepath_utf16 = Memory.allocUtf16String(exepath);

	const buf = Memory.alloc(buffer_size);
	const actual = Memory.alloc(Process.pointerSize);

	const fh = CreateFileW(exepath_utf16, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	const hash = shajs('sha256');
	if (fh == INVALID_HANDLE_VALUE) {
		// TODO resolve errno
		send('failed to open file');
		return null;
	}

	try {
		send('hashing exe located at ' + exepath);
		while (true) {
			const result = ReadFile(fh, buf, buffer_size, actual, NULL);
			if (result != 0 && actual.readS32() == 0) {
				break;
			} else if (result == 0) {
				// TODO resolve errno
				send('an error occurred');
				break;
			}
			hash.update(Buffer.from(buf.readByteArray(actual.readS32()) || new ArrayBuffer(0)));
		}
	} finally {
		CloseHandle(fh);
	}
	const hexdigest = hash.digest('hex');
	send("exe hash: " + hexdigest);

	const offset = offsets.get(hexdigest);

	return offset === undefined ? null : offset;
}

const offset = _match_known_adv_exe();

if (offset === null) {
	send('Unknown exe. Instrumentation aborted.')
	throw Error('Unknown exe. Instrumentation aborted.');
}


send('exe detected: ' + offset.entry_name);

const will_flagbank_offset = ptr(offset.will_flagbank);
const rio_goto_offset = ptr(offset.rio_goto);
const rio_call_offset = ptr(offset.rio_call);
const rio_current_script = ptr(offset.rio_current_script);
const rio_pc = ptr(offset.rio_pc);
const rio_sp = ptr(offset.rio_sp);
const rio_stack_base = ptr(offset.rio_stack_base); // uint32_t event_id, uint32_t pc, char label[16]
const rio_event_id_offset = ptr(offset.rio_event_id);
const rio_current_label = ptr(offset.rio_current_label); // 16-bytes literal
const save_persistent_offset = ptr(offset.save_persistent);
const load_persistent_offset = ptr(offset.load_persistent);
const save_game_offset = ptr(offset.save_game);
const load_game_offset = ptr(offset.load_game);
const malloc_stub = ptr(offset.engine_malloc_stub);
const free_stub = ptr(offset.engine_free_stub);
const qsave_index = offset.qsave_index;


// thunks
const rio_goto_offset_thunk = Memory.alloc(Process.pageSize);
Memory.patchCode(rio_goto_offset_thunk, Process.pageSize, code => {
	const writer = new X86Writer(code, { pc: rio_goto_offset_thunk });
	// New frame
	writer.putPushReg('ebp'); // push ebp
	writer.putMovRegReg('ebp', 'esp'); // mov ebp, esp
	// Save edi
	writer.putPushReg('edi'); // push edi
	// Set edi as argument and call
	writer.putMovRegRegOffsetPtr('edi', 'ebp', 8); // mov edi, [ebp+8]
	writer.putCallAddress(rio_goto_offset); // call rio_goto_offset
	// Restore edi
	writer.putPopReg('edi'); // pop edi
	// Restore frame and return
	writer.putMovRegReg('esp', 'ebp'); // mov esp, ebp
	writer.putPopReg('ebp'); // pop ebp
	writer.putRet(); // ret
});
Memory.protect(rio_goto_offset_thunk, Process.pageSize, 'r-x');
const _rio_goto = new NativeFunction(rio_goto_offset_thunk, 'int32', ['pointer']);
const _rio_call = new NativeFunction(rio_call_offset, 'int32', ['pointer']);

const save_persistent = new NativeFunction(save_persistent_offset, 'int32', []);
const load_persistent = new NativeFunction(load_persistent_offset, 'int32', []);

const _save_game = new NativeFunction(save_game_offset, 'int32', ['int32', 'int32']);
const _load_game = new NativeFunction(load_game_offset, 'int32', ['int32', 'int32']);

const engine_malloc = new NativeFunction(malloc_stub, 'pointer', ['uint32']);
const engine_free = new NativeFunction(free_stub, 'void', ['pointer']);

const _temporary_script_registry = new Map<string, NativePointer>();

type RIOStackFrame = {
	event_id: number,
	pc: NativePointer,
	label: string | null,
};

function _resolve_flagbank_addr(addr: number) {
	if (addr < 0x0 || addr > 0xffff) {
		throw Error('Invalid flag address.');
	}
	const abs_addr = will_flagbank_offset.add(addr * 2);
	return abs_addr;
}

function _null_term_bytes(addr: NativePointer) {
	let a = addr;
	let len = 0;
	while (a.readU8() != 0) {
		len++;
		a = a.add(1);
	}
	return addr.readByteArray(len);
}

function flagbank_peek(addr: number) {
	const abs_addr = _resolve_flagbank_addr(addr);
	return abs_addr.readS16();
}

function flagbank_poke(addr: number, value: number) {
	if (value < -32768 || value > 32767) {
		throw Error('Value must be within -32768 and 32767.');
	}
	const abs_addr = _resolve_flagbank_addr(addr);
	abs_addr.writeS16(value);
}

function flagbank_list_non_zero(from_addr: number, to_addr: number) {
	const result = new Map<number, number>();
	for (let a=from_addr; a<to_addr; a++) {
		const v = flagbank_peek(a);
		if (v != 0) {
			result.set(a, v);
		}
	}
	return result;
}

function _rio_jump_to_ram(addr: NativePointer, name: string, halt: boolean = false) {
	// Save a reference to old script
	const old = rio_current_script.readPointer();
	// Redirect to the in-memory script blob and update PC
	rio_current_script.writePointer(addr);
	rio_pc.writePointer(halt ? NULL : addr);
	// Update script name
	rio_current_label.writeAnsiString(name);
	// Delete old script
	engine_free(old);
}

function _rio_read_call_stack_frame(sp: number): RIOStackFrame {
	if (sp < 0 || sp > 7) {
		throw Error('Invalid stack pointer range ' + sp);
	}
	const frame = rio_stack_base.add(24 * sp);
	return {
		event_id: frame.readU32(),
		pc: frame.add(4).readPointer(),
		label: frame.add(8).readCString(),
	};
}

function _rio_read_current_script_info(): RIOStackFrame {
	return {
		event_id: rio_event_id_offset.readU32(),
		pc: rio_get_pc(),
		label: rio_current_label.readCString(),
	};
}

function rio_traceback() {
	const tb = [];
	tb.push(_rio_read_current_script_info());
	for (let sp=rio_sp.readU32()-1; sp>=0; sp--) {
		tb.push(_rio_read_call_stack_frame(sp));
	}
	return tb;
}

function rio_set_pc(pc: NativePointer) {
	rio_pc.writePointer(rio_current_script.readPointer().add(pc));
}

function rio_get_pc() {
	return rio_pc.readPointer().sub(rio_current_script.readPointer());
}

function rio_goto(label: string) {
	return _rio_goto(Memory.allocAnsiString(label));
}

function rio_call(label: string) {
	return _rio_call(Memory.allocAnsiString(label));
}

function rio_register_script(addr: NativePointer, name: string | undefined | null) {
	if (name === undefined || name === null) {
		name = '<' + addr.toString() + '>';
	}
	if (name.length > 15) {
		throw Error('Name must be < 16 bytes.');
	}
	_temporary_script_registry.set(name, addr);
	return name;
}

function rio_delete_script(name: string) {
	return _temporary_script_registry.delete(name);
}

function rio_list_registered_script() {
	return Array.from(_temporary_script_registry.keys());
}

function rio_get_current_script_buffer() {
	return rio_current_script.readPointer();
}

function save_game(index: number, is_auto: boolean | null | undefined) {
	return _save_game(index, (is_auto === null || is_auto === undefined) ? 0 : (is_auto ? 1 : 0));
}

function load_game(index: number, is_auto: boolean | null | undefined) {
	return _load_game(index, (is_auto === null || is_auto === undefined) ? 0 : (is_auto ? 1 : 0));
}

function quick_save() {
	return save_game(qsave_index, false);
}

function quick_load() {
	return load_game(qsave_index, false);
}

Interceptor.replace(rio_goto_offset, new NativeCallback(function () {
	if (this !== undefined) {
		const label = ((this.context as any).edi as NativePointer).readCString();
		if (label != null) {
			send('rio_goto_2: Loading script ' + label);
			const override = _temporary_script_registry.get(label);
			if (override !== undefined) {
				_rio_jump_to_ram(override, label);
				return 1;
			} else {
				return rio_goto(label);
			}
		}
	}
	return 0;
}, 'int32', [])); // No argument parsing from FFI because non-standard CC

Interceptor.attach(rio_call_offset, {
	onEnter: function(args) {
		send('rio_call: ' + args[0].readCString());
	},
	onLeave: function(ret) {
		if (ret.isNull()) {
			send('rio_call: Failed');
		} else {
			send('rio_call: OK');
		}
	},
});

Interceptor.attach(save_persistent_offset, {
	onLeave: function(ret) {
		if (ret.isNull()) {
			send('save_persistent: Failed');
		} else {
			send('save_persistent: OK');
		}
	}
});

Interceptor.attach(load_persistent_offset, {
	onLeave: function(ret) {
		if (ret.isNull()) {
			send('load_persistent: Failed');
		} else {
			send('load_persistent: OK');
		}
	}
});

Interceptor.attach(save_game_offset, {
	onEnter: function(args) {
		send('save_game: Saving to' + (args[1].isNull() ? '' : ' auto' ) + ' slot ' + args[0]);
	},
	onLeave: function(ret) {
		if (ret.isNull()) {
			send('save_game: Failed');
		} else {
			send('save_game: OK');
		}
	}
});

Interceptor.attach(load_game_offset, {
	onEnter: function(args) {
		send('load_game: Loading from' + (args[1].isNull() ? '' : ' auto' ) + ' slot ' + args[0]);
	},
	onLeave: function(ret) {
		if (ret.isNull()) {
			send('load_game: Failed');
		} else {
			send('load_game: OK');
		}
	}
});

// Man I hate shift_jis gore
Interceptor.replace(MessageBoxA_ptr, new NativeCallback((hWnd, lpText, lpCaption, uType) => {
	const lpTextBuffer = Buffer.from(_null_term_bytes(lpText) || new ArrayBuffer(0));
	const lpCaptionBuffer = Buffer.from(_null_term_bytes(lpCaption) || new ArrayBuffer(0));
	const lpTextString = iconv.decode(lpTextBuffer, 'shift_jis');
	const lpCaptionString = iconv.decode(lpCaptionBuffer, 'shift_jis');
	const lpTextW = Memory.allocUtf16String(lpTextString);
	const lpCaptionW = Memory.allocUtf16String(lpCaptionString);
	send('msgbox: ' + lpTextString + ': ' + lpCaptionString);
	send('traceback: ' + JSON.stringify(rio_traceback()));
	return MessageBoxW(hWnd, lpTextW, lpCaptionW, uType);
}, 'int', ['pointer', 'pointer', 'pointer', 'uint32'], 'stdcall'));

// RPC
rpc.exports = {
	flagbank_peek: flagbank_peek,
	flagbank_poke: flagbank_poke,
	flagbank_list_non_zero: flagbank_list_non_zero,
	rio_traceback: rio_traceback,
	rio_goto: rio_goto,
	rio_call: rio_call,
	rio_register_script: rio_register_script,
	rio_delete_script: rio_delete_script,
	rio_list_registered_script: rio_list_registered_script,
	rio_set_pc: rio_set_pc,
	rio_get_pc: rio_get_pc,
	rio_get_current_script_buffer: rio_get_current_script_buffer,
	save_persistent: save_persistent,
	load_persistent: load_persistent,
	save_game: save_game,
	load_game: load_game,
	quick_save: quick_save,
	quick_load: quick_load,
};

// REPL-friendliness
(global as any).flagbank_peek = flagbank_peek;
(global as any).flagbank_poke = flagbank_poke;
(global as any).flagbank_list_non_zero = flagbank_list_non_zero;
(global as any).rio_traceback = rio_traceback;
(global as any).rio_goto = rio_goto;
(global as any).rio_call = rio_call;
(global as any).rio_register_script = rio_register_script;
(global as any).rio_delete_script = rio_delete_script;
(global as any).rio_list_registered_script = rio_list_registered_script;
(global as any).rio_set_pc = rio_set_pc;
(global as any).rio_get_pc = rio_get_pc;
(global as any).rio_get_current_script_buffer = rio_get_current_script_buffer;
(global as any).save_persistent = save_persistent;
(global as any).load_persistent = load_persistent;
(global as any).save_game = save_game;
(global as any).load_game = load_game;
(global as any).quick_save = quick_save;
(global as any).quick_load = quick_load;

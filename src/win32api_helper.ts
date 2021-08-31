const CreateFileW_ptr = Module.getExportByName('kernel32.dll', 'CreateFileW');
const ReadFile_ptr = Module.getExportByName('kernel32.dll', 'ReadFile');
const CloseHandle_ptr = Module.getExportByName('kernel32.dll', 'CloseHandle');
const MessageBoxA_ptr = Module.getExportByName('USER32.dll', 'MessageBoxA');
const MessageBoxW_ptr = Module.getExportByName('USER32.dll', 'MessageBoxW');
const CreateFileA_ptr = Module.getExportByName('kernel32.dll', 'CreateFileA');
const CreateDirectoryW_ptr = Module.getExportByName('kernel32.dll', 'CreateDirectoryW');
const CreateDirectoryA_ptr = Module.getExportByName('kernel32.dll', 'CreateDirectoryA');
const FormatMessageW_ptr = Module.getExportByName('kernel32.dll', 'FormatMessageW');
const LocalFree_ptr = Module.getExportByName('kernel32.dll', 'LocalFree');

export const CreateFileA = new SystemFunction(CreateFileA_ptr, 'pointer', ['pointer', 'int32', 'int32', 'pointer', 'int32', 'int32', 'pointer'], 'stdcall');
export const CreateFileW = new SystemFunction(CreateFileW_ptr, 'pointer', ['pointer', 'int32', 'int32', 'pointer', 'int32', 'int32', 'pointer'], 'stdcall');
export const ReadFile = new NativeFunction(ReadFile_ptr, 'int', ['pointer', 'pointer', 'int32', 'pointer', 'pointer'], 'stdcall');
export const CloseHandle = new NativeFunction(CloseHandle_ptr, 'int', ['pointer'], 'stdcall');
export const MessageBoxA = new NativeFunction(MessageBoxA_ptr, 'int', ['pointer', 'pointer', 'pointer', 'uint32'], 'stdcall');
export const MessageBoxW = new NativeFunction(MessageBoxW_ptr, 'int', ['pointer', 'pointer', 'pointer', 'uint32'], 'stdcall');
export const CreateDirectoryA = new SystemFunction(CreateDirectoryA_ptr, 'bool', ['pointer', 'pointer'], 'stdcall');
export const CreateDirectoryW = new SystemFunction(CreateDirectoryW_ptr, 'bool', ['pointer', 'pointer'], 'stdcall');
export const FormatMessageW = new NativeFunction(FormatMessageW_ptr, 'int32', ['int32', 'pointer', 'int32', 'int32', 'pointer', 'int32', 'pointer'], 'stdcall');
export const LocalFree = new NativeFunction(LocalFree_ptr, 'pointer', ['pointer'], 'stdcall');

// Constants for CreateFileW
export const GENERIC_READ = 1 << 31;
export const FILE_SHARE_READ = 1;
export const OPEN_EXISTING = 3;
export const FILE_ATTRIBUTE_NORMAL = 1 << 7;
export const INVALID_HANDLE_VALUE = ptr('-1');

// Constants for FormatMessageW
export const FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
export const FORMAT_MESSAGE_FROM_STRING = 0x00000400;
export const FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
export const FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
export const FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
export const FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000ff;

export const FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;

export const LANG_NEUTRAL = 0x00;
export const SUBLANG_DEFAULT = 0x01;
export const LANG_NEUTRAL_SUBLANG_DEFAULT = (SUBLANG_DEFAULT << 10) | LANG_NEUTRAL;
// export function MAKELANGID(p: number, s: number) {
//     return ((s << 10) | p);
// }

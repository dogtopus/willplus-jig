interface DataOffset {
    entry_name: string;
    will_flagbank: string;
    rio_goto: string;
    rio_call: string;
    rio_current_script: string;
    rio_pc: string;
    rio_sp: string;
    rio_stack_base: string;
    rio_event_id: string;
    rio_current_label: string;
    save_persistent: string;
    load_persistent: string;
    save_game: string;
    load_game: string;
    engine_malloc_stub: string;
    engine_free_stub: string;
    qsave_index: number;
}
type OffsetTable = Map<string, DataOffset>;

const offsets: OffsetTable = new Map();

offsets.set('0fee62345f0cb82f88ccee490db10ecc36ce7a9df9650b33b1676b79428a86b1', {
    entry_name: "lltw",
    will_flagbank: "0x57fbc8",
    rio_goto: "0x4068f0",
    rio_call: "0x406af0",
    rio_current_script: "0x48f79c",
    rio_pc: "0x48f7a0",
    rio_sp: "0x491770",
    rio_stack_base: "0x491774",
    rio_event_id: "0x490488",
    rio_current_label: "0x48f78c",
    save_persistent: "0x411e50",
    load_persistent: "0x411ed0",
    save_game: "0x411f50",
    load_game: "0x4124c0",
    engine_malloc_stub: "0x44f296",
    engine_free_stub: "0x44f1b9",
    qsave_index: 100,
});

offsets.set('59c6e1edbb9506b04e269808e557394f1e3f1ecd8b825e8431cbde0449811a95', {
    entry_name: "kanitw",
    will_flagbank: "0x57ef50",
    rio_goto: "0x406600",
    rio_call: "0x406800",
    rio_current_script: "0x48e814",
    rio_pc: "0x48e818",
    rio_sp: "0x4906f8",
    rio_stack_base: "0x4906fc",
    rio_event_id: "0x48f500",
    rio_current_label: "0x48e804",
    save_persistent: "0x4119e0",
    load_persistent: "0x411a60",
    save_game: "0x411ae0",
    load_game: "0x412050",
    engine_malloc_stub: "0x44e886",
    engine_free_stub: "0x44e7a9",
    qsave_index: 100,
});

offsets.set('c66b6c49b409656b3d723cd8d296eca274e0903785a36285e81c72395d983917', {
    entry_name: "ymken",
    will_flagbank: "0x557c18",
    rio_goto: "0x405620",
    rio_call: "0x405830",
    rio_current_script: "0x47c144",
    rio_pc: "0x47c148",
    rio_sp: "0x47dc78",
    rio_stack_base: "0x47dc7c",
    rio_event_id: "0x47ce68",
    rio_current_label: "0x47c134",
    save_persistent: "0x40eaa0",
    load_persistent: "0x40eb40",
    save_game: "0x40ebe0",
    load_game: "0x40f0d0",
    engine_malloc_stub: "0x444c96",
    engine_free_stub: "0x444bb9",
    qsave_index: 99,
});

offsets.set('9b02546022477bc471b4003719fcd909b252468bca6150e79603bad014c388e9', {
    entry_name: "io",
    will_flagbank: "0x6b8308",
    rio_goto: "0x409780",
    rio_call: "0x409990",
    rio_current_script: "0x4d6b98",
    rio_pc: "0x4d6b9c",
    rio_sp: "0x4dfb98",
    rio_stack_base: "0x4dfb9c",
    rio_event_id: "0x4dcd78",
    rio_current_label: "0x4d6b88",
    save_persistent: "0x417520",
    load_persistent: "0x4175e0",
    save_game: "0x4176a0",
    load_game: "0x417d40",
    engine_malloc_stub: "0x4774b9",
    engine_free_stub: "0x4773dc",
    qsave_index: 999,
});

export {DataOffset, OffsetTable, offsets};

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
    engine_malloc_stub: string;
    engine_free_stub: string;
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
    engine_malloc_stub: "0x44f296",
    engine_free_stub: "0x44f1b9"
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
    engine_malloc_stub: "0x44e886",
    engine_free_stub: "0x44e7a9"
});

export {DataOffset, OffsetTable, offsets};
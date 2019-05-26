/*
 *  This is a sample plugin module
 *
 *  It can be compiled by any of the supported compilers:
 *
 *      - Borland C++, CBuilder, free C++
 *      - Visual C++
 *      - GCC
 *
 */
#pragma warning(push, 0)        
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <frame.hpp>
#include <lines.hpp>
#include <struct.hpp>
#include <name.hpp>
#include <cstdio>
#include <regex>
#pragma warning(pop)
#include <Zydis/Zydis.h>
#include <RegisterData.h>

int idaapi init(void) { return PLUGIN_OK; }
void idaapi term(void){}

typedef std::vector<uint8> const OpcodeVector;

bool is_member(ZydisRegister reg, int slot) {
	auto it = zydis2slot.find(reg);
	if (it == zydis2slot.end()) { return false; }
	return it->second == slot;
}

void parse(OpcodeVector opcodes, int register_slot, ea_t start_ip, std::vector<ea_t>& out) {
	// Initialize decoder context.
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	// Loop over the instructions in our buffer.
	// The IP is chosen arbitrary here in order to better visualize
	// relative addressing.
	uint64_t instructionPointer = start_ip;
	size_t offset = 0;
	size_t length = opcodes.size();
	uint8 const * opcode_array = &opcodes[0];
	ZydisDecodedInstruction instruction;
	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, opcode_array + offset, length - offset,
		instructionPointer, &instruction)))
	{
		for (int oper_i = 0; oper_i < instruction.operandCount; oper_i++) {
			auto operand = instruction.operands[oper_i];
			switch (operand.type) {
			case ZYDIS_OPERAND_TYPE_REGISTER:
				if (is_member(operand.reg.value, register_slot)) {
					out.push_back(instructionPointer);
				}
				break;
			case ZYDIS_OPERAND_TYPE_POINTER:
				if (is_member(operand.mem.base, register_slot) || is_member(operand.mem.index, register_slot)) {
					out.push_back(instructionPointer);
				}
				break;
			default:
				continue;
			}
		}
		offset += instruction.length;
		instructionPointer += instruction.length;
	}
}

bool idaapi run(size_t arg){
	qstring insn_mnem;
	qstring highlight;
	insn_t insn;
	std::vector<ea_t> found_addresses;
	auto ea = get_screen_ea();
	decode_insn(&insn, ea);

	// Get highlighted register, and its register number
	auto widget = get_current_widget();
	uint32 flags;
	get_highlight(&highlight, widget, &flags);
	if ((flags & HIF_REGISTER) == 0) {
		msg("highlight isn't a register name - got: %s - flags: %x\n", highlight.c_str(), flags);
		return true;
	}

	// Get register slot
	auto iter = reg2slot.find(highlight.c_str());
	if (iter == reg2slot.end()) {
		msg("couldn't map highlighted register text to a registry slot\n");
		return true;
	}
	auto register_slot = iter->second;

	auto func = *get_func(ea);
	OpcodeVector opcodes(func.size());
	get_bytes((uint8 *) &opcodes[0], func.size(), func.start_ea, 0, 0); // Vector data storage is laid out continguously
	parse(opcodes, register_slot, func.start_ea, found_addresses);
	if (found_addresses.size() == 0) {
		msg("found_addresses.size was 0\n");
		return true;
	}

	qstring disassembly_line;
	for (int i = 0; i < found_addresses.size(); i++) {
		generate_disasm_line(&disassembly_line, found_addresses[i]);
		tag_remove(&disassembly_line);
		msg("%llx - %s\n", found_addresses[i], disassembly_line.c_str());
	}
	return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "This is a sample plugin. It does nothing useful";

static const char help[] =
"A sample plugin module\n"
"\n"
"This module shows you how to create plugin modules.\n"
"\n"
"It does nothing useful - just prints a message that is was called\n"
"and shows the current address.\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

static const char wanted_name[] = "Trace register";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

static const char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,           // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
						// it could appear in the status line
						// or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

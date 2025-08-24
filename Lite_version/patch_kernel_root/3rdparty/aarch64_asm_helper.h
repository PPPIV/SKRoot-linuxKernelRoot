#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>

#define ASMJIT_STATIC
#include "asmjit2-src/src/asmjit/core.h"
#include "asmjit2-src/src/asmjit/a64.h"

class MyAsmJitErrorHandler : public asmjit::ErrorHandler {
public:
	void handleError(asmjit::Error err, const char* message, asmjit::BaseEmitter* origin) override {
		std::cerr << "[发生错误] " << asmjit::DebugUtils::errorAsString(err) << ": " << message << std::endl;
		isErr = true;
	}
	bool isError() { return isErr; }
private:
	bool isErr = false;
};

struct aarch64_asm_info {
	std::unique_ptr<asmjit::CodeHolder> codeHolder;
	std::unique_ptr<asmjit::a64::Assembler> a;
	std::unique_ptr<asmjit::StringLogger> logger;
	std::unique_ptr<MyAsmJitErrorHandler> err;
};

static aarch64_asm_info init_aarch64_asm() {
	asmjit::Environment env(asmjit::Arch::kAArch64);
	auto code = std::make_unique<asmjit::CodeHolder>();
	code->init(env);
	auto logger = std::make_unique<asmjit::StringLogger>();
	logger->addFlags(asmjit::FormatFlags::kNone);
	code->setLogger(logger.get());
	auto a = std::make_unique<asmjit::a64::Assembler>(code.get());
	auto err = std::make_unique<MyAsmJitErrorHandler>();
	a->setErrorHandler(err.get());
	return { std::move(code), std::move(a), std::move(logger), std::move(err) };
}

static std::vector<uint8_t> aarch64_asm_to_bytes(const aarch64_asm_info& asm_info) {
	if (asm_info.err->isError()) {
		return {};
	}
	asm_info.codeHolder->flatten();
	asmjit::Section* sec = asm_info.codeHolder->sectionById(0);
	const asmjit::CodeBuffer& buf = sec->buffer();
	const uint8_t* data = buf.data();
	size_t data_size = buf.size();
	return std::vector<uint8_t>(data, data + data_size);
}

static bool aarch64_asm_b(std::unique_ptr<asmjit::a64::Assembler>& a, int32_t b_value) {
	if (b_value % 4 != 0) {
		std::cout << "[发生错误] The B instruction offset must be a multiple of 4" << std::endl;
		return false;
	}
	int64_t imm26 = b_value >> 2;
	if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
		std::cout << "[发生错误] B instruction offset exceeds ± 128MB range" << std::endl;
		return false;
	}
	int32_t offset = b_value >> 2;
	uint32_t instr = 0x14000000 | (offset & 0x03FFFFFF);
	a->embed((const uint8_t*)&instr, sizeof(instr));
	return true;
}

static bool aarch64_asm_bl(std::unique_ptr<asmjit::a64::Assembler>& a, int32_t bl_value) {
	if (bl_value % 4 != 0) {
		std::cout << "[发生错误] The BL instruction offset must be a multiple of 4" << std::endl;
		return false;
	}
	int64_t imm26 = bl_value >> 2;
	if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
		std::cout << "[发生错误] BL instruction offset exceeds ±128MB range" << std::endl;
		return false;
	}
	int32_t offset26 = bl_value >> 2;
	uint32_t instr = 0x94000000u | (static_cast<uint32_t>(offset26) & 0x03FFFFFFu);
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

static bool is_aarch64_asm_b(uint32_t instr) {
	constexpr uint32_t B_MASK = 0xFC000000u;
	constexpr uint32_t B_PATTERN = 0x14000000u;
	return (instr & B_MASK) == B_PATTERN;
}

static int32_t extract_aarch64_asm_b_value(uint32_t instr) {
	int32_t imm26 = instr & 0x03FFFFFF;

	if (imm26 & (1 << 25)) {
		imm26 |= ~((1 << 26) - 1);
	}
	return imm26 << 2;
}

static bool aarch64_asm_adr_x(std::unique_ptr<asmjit::a64::Assembler>& a, asmjit::a64::GpX x, int32_t adr_value) {
	if (adr_value % 4 != 0) {
		std::cout << "[发生错误] The ADR instruction offset must be a multiple of 4" << std::endl;
		return false;
	}
	int64_t immSigned = adr_value >> 2;
	if (immSigned < -(1LL << 20) || immSigned >((1LL << 20) - 1)) {
		std::cout << "[发生错误] ADR instruction offset exceeds ± 1MB range" << std::endl;
		return false;
	}
	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a2 = asm_info.a;
	asmjit::Label label_statr = a2->newLabel();
	int32_t size = abs(adr_value);
	std::vector<uint8_t> filler(size, 0x00);
	if (adr_value > 0) {
		a2->adr(x, label_statr);
		a2->embed(filler.data(), size);
		a2->bind(label_statr);
		a2->nop();
	}
	else {
		a2->bind(label_statr);
		a2->embed(filler.data(), size);
		a2->adr(x, label_statr);
	}
	asm_info.codeHolder->flatten();
	asmjit::Section* sec = asm_info.codeHolder->sectionById(0);
	const asmjit::CodeBuffer& buf = sec->buffer();
	uint8_t* data = (uint8_t*)buf.data();
	size_t dataSize = buf.size();
	if (adr_value < 0) {
		data += size;
	}
	a->embed((const uint8_t*)data, 4);
	return true;
}

static void aarch64_asm_mov_x(std::unique_ptr<asmjit::a64::Assembler>& a, asmjit::a64::GpX x, uint64_t value) {
	bool isInitialized = false;
	for (int idx = 0; idx < 4; ++idx) {
		uint16_t imm16 = (value >> (idx * 16)) & 0xFFFF;
		if (imm16 == 0)
			continue;

		if (!isInitialized) {
			a->movz(x, imm16, idx * 16);
			isInitialized = true;
		}
		else {
			a->movk(x, imm16, idx * 16);
		}
	}
	if (!isInitialized) {
		a->movz(x, 0, 0);
	}
}

static void aarch64_asm_mov_w(std::unique_ptr<asmjit::a64::Assembler>& a, asmjit::a64::GpW w, uint32_t value) {
	bool isInitialized = false;
	for (int idx = 0; idx < 2; ++idx) {
		uint16_t imm16 = (value >> (idx * 16)) & 0xFFFF;
		if (imm16 == 0)
			continue;

		if (!isInitialized) {
			a->movz(w, imm16, idx * 16);
			isInitialized = true;
		}
		else {
			a->movk(w, imm16, idx * 16);
		}
	}
	if (!isInitialized) {
		a->movz(w, 0, 0);
	}
}

static void aarch64_asm_safe_blr(std::unique_ptr<asmjit::a64::Assembler> &a, asmjit::a64::GpX x) {
	a->stp(x29, x30, ptr(sp).pre(-16));
	a->blr(x);
	a->ldp(x29, x30, ptr(sp).post(16));
}

static bool aarch64_asm_pacia(std::unique_ptr<asmjit::a64::Assembler>& a, const asmjit::a64::GpX& reg) {
	uint32_t reg_n = reg.id();
	if (reg_n > 31) {
		std::cout << "[发生错误] Xn 寄存器编号超出范围: " << reg_n << std::endl;
		return false;
	}
	uint32_t instr = 0xDAC103E0 | reg_n;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

static bool aarch64_asm_paciasp(std::unique_ptr<asmjit::a64::Assembler>& a) {
	uint32_t instr = 0xD503233F;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

static bool aarch64_asm_autiasp(std::unique_ptr<asmjit::a64::Assembler>& a) {
	uint32_t instr = 0xD50323BF;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

static bool aarch64_asm_bit_c(std::unique_ptr<asmjit::a64::Assembler>& a) {
	uint32_t instr = 0xD503245F;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

static bool aarch64_asm_bit_j(std::unique_ptr<asmjit::a64::Assembler>& a) {
	uint32_t instr = 0xD503249F;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

static std::string print_aarch64_asm(const aarch64_asm_info& asm_info) {
	std::string text = asm_info.logger->data();
	transform(text.begin(), text.end(), text.begin(), ::toupper);
	return text;
}

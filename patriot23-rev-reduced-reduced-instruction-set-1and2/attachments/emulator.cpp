#define _CRT_SECURE_NO_WARNINGS
#include <cstdint>
#include <cstdio>
#include <conio.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <string>

#include "idadefs.h"


size_t pos = 0;
std::vector<uint8_t> file_content = {};

std::vector<uint8_t> read_file(const std::wstring& path) noexcept {
	std::fstream f(path, std::ios::in | std::ios::binary);
	if (!f)
		return {};

	f.seekg(0, f.end);
	const auto f_size = f.tellg();
	f.seekg(0, f.beg);

	std::vector<uint8_t> buffer(f_size);
	f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

	return buffer;
}

void __endbr64(...) {}

__int64 __fastcall decode_instruction(int a1, __int64 a2)
{
	int i; // [rsp+10h] [rbp-10h]

	__endbr64();
	for (i = 0; i <= 3; ++i) {
		*reinterpret_cast<uint8_t*>(a2 + i) = file_content[pos++];
	}

	return 0LL;
}

std::string FLAG = "";

int inp_count = 0;
char F_INPUT[840 - 1] = {};

bool checked = false;
bool st = false;

int __fastcall execute_instruction(int a1, _BYTE* a2, __int64 a3)
{
	_QWORD* v3; // rax
	int v4; // edx
	unsigned int* v6; // [rsp+30h] [rbp-10h]
	unsigned int* v7; // [rsp+38h] [rbp-8h]

	__endbr64();
	v6 = (unsigned int*)(4LL * (unsigned __int8)a2[1] + a3);
	v7 = (unsigned int*)(4LL * (unsigned __int8)a2[2] + a3);

		// printf("(+%d) VMHANDLER: %d ARGS: { %d %d }\n", pos, *a2,  *v6, *v7);

	auto name_op = [](int op) -> std::string {
		if (op < 90'000)
			return std::to_string(op);
		return "FLAG[" + std::to_string(op - 90'000) + "]";
	};

	if (checked) {
		auto set = []() -> void {
			if (!st)
				st = true;
		};

		switch (*a2) {
		case 5:
		case 6:
		case 4:
		case 9:
			break;

		case 14:
			if (!st) {
				std::cout << "s.add(((" << name_op(*v6) << " ^ " << name_op(*v7) << ")";
			}
			else {
				std::cout << "^" << *v7;
			}
			set();
			break;

		case 1:
			if (!st) {
				std::cout << "s.add((" << name_op(*v6) << " + " << name_op(*v7) << ")";
			}
			else {
				std::cout << " + " << *v7 << ")";
			}
			set();
			break;

		case 19:
			std::cout << " % " << *v7;
			set();
			break;

		case 7:
			std::cout << " == " << *v7 << ")";
			set();
			break;

		case 8:
			std::cout << std::endl;
			st = false;
			break;

		default:
			printf("UNKNOWN %d %d %d\n", *a2, *v6, *v7);
			__debugbreak();
			break;
		}
	}

	switch (*a2)
	{
	case 0:
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 = *v7;
		break;
	case 1:
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 += *v7 + (unsigned __int8)a2[3];
		break;
	case 2:
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 += *v7 + (unsigned __int8)a2[3];
		break;
	case 3:
		LODWORD(v3) = printf("%u\n", *v6);
		break;
	case 4:
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 = (unsigned __int8)a2[3];
		break;
	case 5:
		*(_QWORD*)(a3 + 24) += 8LL;
		v3 = *(_QWORD**)(a3 + 24);
		*v3 = *(_QWORD*)v7;
		break;
	case 6:
		*(_QWORD*)v6 = **(_QWORD**)(a3 + 24);
		LODWORD(v3) = a3;
		*(_QWORD*)(a3 + 24) -= 8LL;
		break;
	case 7:
		LODWORD(v3) = a3;
		//*v6 = *v7; // spoof check
		*(_DWORD*)(a3 + 16) = *v6 - *v7;
		//FLAG += (char)(*v7);
		break;
	case 8:
		LODWORD(v3) = *(_DWORD*)(a3 + 16);
		if (!(_DWORD)v3) {
			pos += (__int16)(((unsigned __int8)a2[2] << 8) + (unsigned __int8)a2[3]);
			LODWORD(v3) = pos;
		}
		else { // spoof the check
			pos += (__int16)(((unsigned __int8)a2[2] << 8) + (unsigned __int8)a2[3]);
			LODWORD(v3) = pos;
		}
		break;
	case 9:
		if (!checked) {
			printf("\n");
			for (std::size_t k = 0; k < (unsigned __int8)a2[3]; ++k) {
				printf("%c", (*(const char**)(a3 + 24))[k]);
			}
		}

		LODWORD(v3) = a2[3];

		//LODWORD(v3) = write(1, *(const void**)(a3 + 24), (unsigned __int8)a2[3]);
		break;
	case 0xA:
		*v6 *= *v7;
		LODWORD(v3) = (_DWORD)v6;
		*v6 += (unsigned __int8)a2[3];
		break;
	case 0xB:
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 += (unsigned __int8)a2[3];
		break;
	case 0xC:
		printf("FLAG IS: %s\n", FLAG.c_str());
		exit(0);
	case 0xD: // 13
		LODWORD(v3) = scanf("%u", v6);
		break;
	case 0xE: // 14
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 ^= *v7;
		break;
	case 0xF: // 15
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 >>= a2[3];
		break;
	case 0x10: // 16
		if (pos <= 8168) {
			v4 = 90000 + inp_count++;

			if (!checked)
				checked = pos == 8168;
		}
		else {
			v4 = _getch();
		}
		LODWORD(v3) = (_DWORD)v6;
		*v6 = v4;
		break;
	case 0x11: // 17
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 <<= a2[3];
		break;
	case 0x12: // 18
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 -= (unsigned __int8)a2[3];
		break;
	case 0x13: // 19
		LODWORD(v3) = 4 * (unsigned __int8)a2[1] + a3;
		*v6 %= *v7;
		break;
	default:
		puts("Error executing instruction!");
		exit(0);
	}

	return (int)v3;
}
_BYTE* __fastcall clear_ins(_BYTE* a1)
{
	_BYTE* result; // rax

	__endbr64();
	*a1 = 0;
	a1[1] = 0;
	a1[2] = 0;
	result = a1;
	a1[3] = 0;
	return result;
}

int main() {
	int fd; // [rsp+10h] [rbp-30h]
	void* v4; // [rsp+20h] [rbp-20h]
	_QWORD* v5; // [rsp+28h] [rbp-18h]
	int buf; // [rsp+34h] [rbp-Ch] BYREF
	unsigned __int64 v7; // [rsp+38h] [rbp-8h]

	file_content = read_file(L"E:\\repos\\es3n1n\\writeups\\patriot23\\rev-reduced-reduced-insn-set2\\password_checker2.smol");
	pos += strlen("SMOL");
	fd = 0;

	v4 = malloc(4uLL);
	if (!v4)
	{
		puts("malloc fail");
		exit(0);
	}
	v5 = (uint64*)malloc(0x20uLL);
	if (!v5)
	{
		puts("malloc fail");
		exit(0);
	}

	v5[3] = (uint64)malloc(0x1000uLL);
	while (1)
	{
		decode_instruction((unsigned int)fd, (__int64)v4);
		execute_instruction((unsigned int)fd, (uint8*)v4, (long long)v5);
		clear_ins((uint8*)v4);
	}
}

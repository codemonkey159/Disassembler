Disassembler.cpp is a single file library that allows you to get the disassembled representation of binary data for any pointer.

To use Disassembler.cpp, simply #include it at the beginning of any relevant source file, then create an instance of the INSTRUCTION struct.

The instruction struct is defined like this:

struct INSTRUCTION
{
    int length;
    unsigned char byteseq[15];
    char disasmstr[200] = {};
    void* adr = 0;
};

after that use the only function exported by the library, disassemble(address), to fill the INSTRUCTION.

length will equal the length of the byte sequence disassembled and can be used to determine where the instruction pointer will be after the instruction is ran

byteseq is the byte sequence of the instruction pointed to by the address of the pointer provided to disassemble().

disasmstr will be a string with the assembly level representation of the byte sequence pointed to by the pointer provided to disassemble()

adr will be the address of the pointer provided to disassemble().


A minimal example of the libraries usage would be something like this:


#include "assembler.cpp"

#include <iostream>

using namespace std;


int main()

{

	unsigned char byte = 0x90;

	INSTRUCTION ins = disassemble(&byte);

	cout << ins.disasmstr;

	return 0;

}


The output when I run this code:

nop
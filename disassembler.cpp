#include <iostream>
#include <iomanip>
#include <cstring>
#include <windows.h>
using namespace std;

char r8map[24][5] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
char r32map[48][5] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

struct INSTRUCTION
{
    int length;
    unsigned char byteseq[15];
    char disasmstr[200] = {};
    void* adr = 0;
};

struct INSTRUCTIONDATA
{
    int length = 1;
    char disasmstr[200] = {};
    void* adr = 0;
    char* rm8 = 0;
    char* rm32 = 0;
    char* reg8 = 0;
    char* reg32 = 0;
    char* imm8 = 0;
    char* imm32 = 0;
    char* rel8 = 0;
    char* rel32 = 0;


    char* xmm = 0;
    char* m8 = 0;
    char* m16 = 0;
    char* m64 = 0;
    char* r64 = 0;
    char* CRn = 0;
    char* DRn = 0;
    char* xmmm128 = 0;
    char* xmmm64 = 0;
    char* xmmm32 = 0;
    char* mmm64 = 0;
    char* m128 = 0;
    char* mm = 0;
    char* r3264 = 0;
    char* rm64 = 0;


    void* opcpv = &opc;
    char* opcptr = (char*)opcpv;
    void* opr1pv = &opr1val;
    void* opr2pv = &opr2val;
    void* opr3pv = &opr3val;
    void* opr4pv = &opr4val;
    char* opr1ptr = (char*)opr1pv;
    char* opr2ptr = (char*)opr2pv;
    char* opr3ptr = (char*)opr3pv;
    char* opr4ptr = (char*)opr4pv;
    char opc[50] = {};
    char opr1val[50] = {};
    char opr2val[50] = {};
    char opr3val[50] = {};
    char opr4val[50] = {};
    uint16_t prefixes = 0; //rex first 5 bits, then 66 = 2, 67 = 4, then segment registers, then lock/rep prefixes.
    bool parsed = 0;
    int disp = 0;
    bool malformed = 0;
    int regorrm = 0;
    bool imm64 = 0;
    bool st = 0;
    bool tword = 0;
    bool fword = 0;
};

int getdigits(uint64_t num)
{
    uint64_t digits = 1;
    if(num >= 0x10000000)
    {
        if(num >= 0x100000000000)
        {
            if(num >= 0x10000000000000)
            {
                if(num >= 0x100000000000000)
                {
                    if(num >= 0x1000000000000000)
                        digits = 16;
                    else
                        digits = 15;
                }
                else
                    digits = 14;
            }
            else if(num >= 0x1000000000000)
                digits = 13;
            else
                digits = 12;
        }
        else if(num >= 0x1000000000)
        {
            if(num >= 0x10000000000)
                digits = 11;
            else
                digits = 10;
        }
        else if(num >= 0x100000000)
        {
            digits = 9;
        }
        else
            digits = 8;
    }
    else if(num >= 0x1000)
    {
        if(num >= 0x100000)
        {
            if(num >= 0x1000000)
                digits = 7;
            else
                digits = 6;
        }
        else if(num >= 0x10000)
            digits = 5;
        else
            digits = 4;
    }
    else if(num >= 0x10)
    {
        if(num >= 0x100)
            digits = 3;
        else
            digits = 2;
    }
    else if(num >= 0x1)
        digits = 1;
    else
    {
        digits = 1;
    }
    return digits;
}

void ntohs(uint64_t num, uint64_t digits, char* hexstr)
{

    if(digits == 0)
    {
        hexstr[0] = 0x30;
        hexstr[1] = 0x0;
        return;
    }
    for(uint64_t i = 0;i<digits;i++)
    {
        uint64_t tempbuf = ((((uint64_t)0xF<<(4*i))&num)>>(4*i));
        if(tempbuf > 9)
            hexstr[digits-(i+1)] = tempbuf+0x37;
        else
            hexstr[digits-(i+1)] = tempbuf+0x30;
    }
    hexstr[digits] = 0x00;
    return;
}

uint64_t hston(char* hexstr, int error)
{
    uint64_t number = 0;
    error = 0;
    uint64_t hsize;
    char* buffer = hexstr;
    while((char)*hexstr)
        hexstr++;
    hsize = hexstr-buffer;
    if(!hsize)
    {
        error = 1;
        return 0;
    }
    if(hsize > 16)
    {
        error = 1;
        return 3;
    }
    hexstr = buffer;
    for(uint64_t i = 0;i<hsize;i++)
    {
        number = number*0x10;
        if((char)*(hexstr+i) < 0x30 || ((char)*(hexstr+i) > 0x39 && (char)*(hexstr+i) < 0x41) || (char)*(hexstr+i) > 0x46)
        {
            error = 2;
            return 0;
        }
        if((unsigned char)*(hexstr+i) < 0x3A)
            number = number+(((unsigned char)*(hexstr+i))-0x30);
        else
            number = number+(((unsigned char)*(hexstr+i))-0x37);
    }
    return number;
}

void parsedata(INSTRUCTIONDATA &data)
{
    data.parsed = 1;
    int doplus = 0;
    int rex = 0;
    void *adr;
    unsigned char byte;
    if(data.xmmm64 && data.m128)
    {
        data.malformed = 1;
        cout << "oh god bad things happened at the beginning of parsedata()\n";
        return;
    }
    if(data.xmmm32)
        data.xmmm128 = data.xmmm32;
    if(data.xmmm64)
        data.xmmm128 = data.xmmm64;
    if(data.m128)
        data.xmmm128 = data.m128;
    if(data.r3264)
        data.reg32 = data.r3264;
    if(data.r64)
    {
        data.reg32 = data.r64;
        data.prefixes = (data.prefixes&0xFFD7)+8;
    }
    if(data.rm64)
    {
        data.rm32 = data.rm64;
        data.prefixes = (data.prefixes&0xFFD7)+8;
    }
    if(data.prefixes&0x1F)
        rex = 1;
    if(data.DRn)
    {
        strcat(data.DRn, "DR");
        char qstr[2] = {((byte&0x7)+0x30), 0x0};
        strcat(data.DRn, qstr);
    }
    else if(data.CRn)
    {
        strcat(data.CRn, "CR");
        char qstr[2] = {((byte&0x7)+0x30), 0x0};
        strcat(data.CRn, qstr);
    }
    if(data.reg8)
    {
        data.regorrm = 1;
        data.length+=1;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        adr = ((char*)data.adr)+data.length-1;
        byte = *(unsigned char*)adr;
        strcat(data.reg8, (char*)&r8map[((byte & 0x38)>>3)+(8*rex)+(2*(data.prefixes & 0x4))][0]);
    }
    else if(data.reg32 || data.xmm || data.mm)
    {
        data.regorrm = 1;
        data.length+=1;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        adr = ((char*)data.adr)+data.length-1;
        byte = *(unsigned char*)adr;
        if(data.xmm)
        {
            strcat(data.xmm, "xmm");
            char qstr[2] = {(((byte&0x38)>>3)+0x30), 0x0};
            strcat(data.xmm, qstr);
        }
        else if(data.mm)
        {
            strcat(data.mm, "mm");
            char qstr[2] = {(((byte&0x38)>>3)+0x30), 0x0};
            strcat(data.mm, qstr);
        }
        else if(data.reg32)
            strcat(data.reg32, (char*)&r32map[((byte & 0x38)>>3)+(6*(data.prefixes & 0x4))+(2*(data.prefixes & 0x8))+((data.prefixes & 0x20)>>2)][0]);
    }
    if(data.rm8)
    {
        if(!data.regorrm)
        {
            data.length+=1;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            strcat(data.rm8, "byte ");
        }
        if(data.prefixes&0x80)
            strcat(data.rm8, "ES:");
        else if(data.prefixes&0x100)
            strcat(data.rm8, "CS:");
        else if(data.prefixes&0x200)
            strcat(data.rm8, "SS:");
        else if(data.prefixes&0x400)
            strcat(data.rm8, "DS:");
        else if(data.prefixes&0x800)
            strcat(data.rm8, "FS:");
        else if(data.prefixes&0x1000)
            strcat(data.rm8, "GS:");
        adr = ((char*)data.adr)+data.length-1;
        byte = *(unsigned char*)adr;
        if(byte>=0xC0 && data.st == 0)
            strcat(data.rm8, (char*)&r8map[(byte & 0x7)+(8*rex)+(8*(data.prefixes & 0x1))][0]);
        else if(byte>=0xC0 && data.st == 1)
        {
            unsigned char innerbyte;
            innerbyte = byte&0x7;
            strcat(data.rm8, "st(");
            switch (innerbyte)
            {
                case 0:
                    strcat(data.rm8, "0");
                    break;
                case 1:
                    strcat(data.rm8, "1");
                    break;
                case 2:
                    strcat(data.rm8, "2");
                    break;
                case 3:
                    strcat(data.rm8, "3");
                    break;
                case 4:
                    strcat(data.rm8, "4");
                    break;
                case 5:
                    strcat(data.rm8, "5");
                    break;
                case 6:
                    strcat(data.rm8, "6");
                    break;
                case 7:
                    strcat(data.rm8, "7");
                    break;
            }
            strcat(data.rm8, ")");
        }
        else if(byte>= 0x80 && byte < 0xC0)
        {
            data.disp = 32;
        }
        else if(byte>= 0x40 && byte < 0x80)
        {
            data.disp = 8;
        }
        if(((byte & 0x7) == 0x4) && byte < 0xC0)
        {
            strcat(data.rm8, "[");
            data.length+=1;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            adr = ((char*)data.adr)+data.length-1;
            byte = *(unsigned char*)adr;
            if(((byte&0x7)^0x5) == 0) //first number is [*] (which is RBP if disp or is nothing and disp becomes 32)
            {
                if(data.disp)
                {
                    strcat(data.rm8, (char*)&r32map[(16+(byte&0x7)+(24*(data.prefixes & 1)))-((data.prefixes & 0x40)>>2)][0]);
                    doplus++;
                }
                else
                    data.disp = 32;
            }
            else
            {
                strcat(data.rm8, (char*)&r32map[(16+(byte&0x7)+(24*(data.prefixes & 1)))-((data.prefixes & 0x40)>>2)][0]);
                doplus++;
            }
            if(((byte & 0x38)^0x20) || (data.prefixes & 0x2))
            {
                if(doplus)
                    strcat(data.rm8, "+");
                strcat(data.rm8, (char*)&r32map[(16+((byte&0x38)>>3)+(12*(data.prefixes & 2)))-((data.prefixes & 0x40)>>2)][0]);
            }
            if(byte>=0xC0)
                strcat(data.rm8, "*8");
            else if(byte>=0x80)
                strcat(data.rm8, "*4");
            else if(byte>=0x40)
                strcat(data.rm8, "*2");
            if(data.disp == 0)
                strcat(data.rm8, "]");
        }
        else if(byte < 0x40 && ((byte&0x7) == 0x5))
        {
            strcat(data.rm8, "[");
            data.disp = 32;
        }
        else if(byte < 0xC0)
        {
            strcat(data.rm8, "[");
            doplus++;
            strcat(data.rm8, (char*)&r32map[16+(byte & 0x7)+(24*(data.prefixes & 0x1)-((data.prefixes & 0x40)>>2))][0]);
            if(data.disp == 0)
                strcat(data.rm8, "]");
        }
    }
    else if(data.rm32 || data.xmmm128 || data.mmm64 || data.m8 || data.m64)
    {
        if(data.xmmm128 && data.rm32 == 0)
            data.rm32 = data.xmmm128;
        else if(data.mmm64 && data.rm32 == 0)
            data.rm32 = data.mmm64;
        if(data.m64)
        {
            data.prefixes = (data.prefixes&0xFFD7)+0x8;
            data.rm32 = data.m64;
        }
        if(data.m8)
        {
            data.prefixes = data.prefixes&0xFFD7;
            data.rm32 = data.m8;
        }
        if(data.m8 && data.regorrm == 0)
        {
            strcat(data.rm32, "byte ");
            data.length+=1;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            goto skipword;
        }
        if(!data.regorrm)
        {
            if(data.fword)
                strcat(data.rm32, "fword ");
            if(data.tword)
                strcat(data.rm32, "tword ");
            else if(data.xmmm128)
                strcat(data.rm32, "xmmword ");
            else if(data.prefixes&8)
                strcat(data.rm32, "qword ");
            else if(data.prefixes&0x20)
                strcat(data.rm32, "word ");
            else
                strcat(data.rm32, "dword ");
            data.length+=1;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
        }
        skipword:
        if(data.prefixes&0x80)
            strcat(data.rm32, "ES:");
        else if(data.prefixes&0x100)
            strcat(data.rm32, "CS:");
        else if(data.prefixes&0x200)
            strcat(data.rm32, "SS:");
        else if(data.prefixes&0x400)
            strcat(data.rm32, "DS:");
        else if(data.prefixes&0x800)
            strcat(data.rm32, "FS:");
        else if(data.prefixes&0x1000)
            strcat(data.rm32, "GS:");
        adr = ((char*)data.adr)+data.length-1;
        byte = *(unsigned char*)adr;
        if(data.m64 && byte>=0xC0)
        {
            data.malformed = 1;
            return;
        }
        if(byte>=0xC0 && data.st == 0 && data.xmmm128)
        {
            strcat(data.xmmm128, "xmm");
            char qstr[2] = {((byte&0x7)+0x30), 0x0};
            strcat(data.xmmm128, qstr);
        }
        else if(byte>=0xC0 && data.st == 0 && data.mmm64)
        {
            strcat(data.mmm64, "mm");
            char qstr[2] = {((byte&0x7)+0x30), 0x0};
            strcat(data.mmm64, qstr);
        }
        else if(byte>=0xC0 && data.st == 0)
            strcat(data.rm32, (char*)&r32map[(byte&0x7)+(24*(data.prefixes&0x1)+((data.prefixes & 0x20)>>2)+(2*(data.prefixes&0x8)))][0]);
        else if(byte>=0xC0 && data.st == 1)
        {
            unsigned char innerbyte;
            innerbyte = byte&0x7;
            strcat(data.rm32, "st(");
            switch (innerbyte)
            {
                case 0:
                    strcat(data.rm32, "0");
                    break;
                case 1:
                    strcat(data.rm32, "1");
                    break;
                case 2:
                    strcat(data.rm32, "2");
                    break;
                case 3:
                    strcat(data.rm32, "3");
                    break;
                case 4:
                    strcat(data.rm32, "4");
                    break;
                case 5:
                    strcat(data.rm32, "5");
                    break;
                case 6:
                    strcat(data.rm32, "6");
                    break;
                case 7:
                    strcat(data.rm32, "7");
                    break;
            }
            strcat(data.rm32, ")");
        }
        else if(byte>= 0x80 && byte < 0xC0)
        {
            data.disp = 32;
        }
        else if(byte>= 0x40 && byte < 0x80)
        {
            data.disp = 8;
        }
        if(((byte&0x7) == 0x4) && byte < 0xC0)
        {
            strcat(data.rm32, "[");
            data.length+=1;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            adr = ((char*)data.adr)+data.length-1;
            byte = *(unsigned char*)adr;
            if((byte&0x7) == 5) //first number is [*] (which is RBP if disp or is nothing and disp becomes 32)
            {
                if(data.disp)
                {
                    strcat(data.rm32, (char*)&r32map[(16+(byte&0x7)+(24*(data.prefixes & 1)))-((data.prefixes & 0x40)>>2)][0]);
                    doplus++;
                }
                else
                    data.disp = 32;
            }
            else
            {
                strcat(data.rm32, (char*)&r32map[(16+(byte&0x7)+(24*(data.prefixes & 1)))-((data.prefixes & 0x40)>>2)][0]);
                doplus++;
            }
            if(((byte & 0x38)^0x20) || (data.prefixes & 0x2))
            {
                if(doplus)
                    strcat(data.rm32, "+");
                strcat(data.rm32, (char*)&r32map[(16+((byte&0x38)>>3)+(12*(data.prefixes & 2)))-((data.prefixes & 0x40)>>2)][0]);
            }
            if(byte>=0xC0)
                strcat(data.rm32, "*8");
            else if(byte>=0x80)
                strcat(data.rm32, "*4");
            else if(byte>=0x40)
                strcat(data.rm32, "*2");
            if(data.disp == 0)
                strcat(data.rm32, "]");
        }
        else if(byte < 0x40 && (byte&0x7) == 0x5)
        {
            strcat(data.rm32, "[");
            data.disp = 32;
        }
        else if(byte < 0xC0)
        {
            strcat(data.rm32, "[");
            doplus++;
            strcat(data.rm32, (char*)&r32map[16+(byte & 0x7)+(24*(data.prefixes & 0x1)-((data.prefixes & 0x40)>>2))][0]);
            if(data.disp == 0)
                strcat(data.rm32, "]");
        }
    }
    if(data.disp == 8)
    {
        unsigned char buffer[3];
        uint8_t number = *(uint8_t*)(((char*)data.adr)+data.length);
        data.length++;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        bool negative = 0;
        if(number > 0x80)
        {
            negative = 1;
            number = 0x80-(number-0x80);
        }
        int digits = getdigits(number);
        ntohs(number, digits, (char*)buffer);
        if(data.rm8)
        {
            if(negative)
                strcat(data.rm8, "-");
            else
                strcat(data.rm8, "+");
            strcat(data.rm8, (const char*)buffer);
            strcat(data.rm8, "]");
        }
        if(data.rm32)
        {
            if(negative)
                strcat(data.rm32, "-");
            else
                strcat(data.rm32, "+");
            strcat(data.rm32, (const char*)buffer);
            strcat(data.rm32, "]");
        }
    }
    if(data.disp == 32)
    {
        unsigned char buffer[17];
        uint64_t number = *(uint32_t*)(((char*)data.adr)+data.length);
        data.length+=4;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        bool negative = 0;
        if(number > 0x80000000)
        {
            negative = 1;
            number = 0x80000000-(number-0x80000000);
        }
        if(!doplus)
        {
            if(data.imm32)
            {
                if(negative)
                    number = (uint64_t)data.adr+(uint64_t)data.length+(uint64_t)4-(uint64_t)number;
                else
                    number = (uint64_t)data.adr+(uint64_t)data.length+(uint64_t)4+(uint64_t)number;
            }
            else if(data.imm8)
            {
                if(negative)
                    number = ((uint64_t)data.adr)+data.length+1-number;
                else
                    number = ((uint64_t)data.adr)+data.length+1+number;
            }
        }
        int digits = getdigits(number);
        ntohs(number, digits, (char*)buffer);
        if(data.rm8)
        {
            if(doplus && negative)
                strcat(data.rm8, "-");
            else if(doplus)
                strcat(data.rm8, "+");
            strcat(data.rm8, (const char*)buffer);
            strcat(data.rm8, "]");
        }
        if(data.rm32)
        {
            if(doplus && negative)
                strcat(data.rm32, "-");
            else if(doplus)
                strcat(data.rm32, "+");
            strcat(data.rm32, (const char*)buffer);
            strcat(data.rm32, "]");
        }
    }
    if(data.imm8)
    {
        data.length+=1;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        adr = ((char*)data.adr)+data.length-1;
        byte = *(unsigned char*)adr;
        unsigned char buffer[3] = {};
        if(byte&0xF0)
        {
            if((byte&0xF0)>0x90)
            buffer[0] = ((byte&0xF0)>>4)+0x37;
            else
            buffer[0] = ((byte&0xF0)>>4)+0x30;
            if((byte&0xF)>0x9)
            buffer[1] = (byte&0xF)+0x37;
            else
            buffer[1] = (byte&0xF)+0x30;
            buffer[2] = 0x0;
        }
        else if(byte&0xF)
        {
            if((byte&0xF)>0x9)
            buffer[0] = (byte&0xF)+0x37;
            else
            buffer[0] = (byte&0xF)+0x30;
            buffer[1] = 0x0;
            buffer[2] = 0x0;
        }
        else
        {
            buffer[0] = 0x30;
            buffer[1] = 0x0;
            buffer[2] = 0x0;
        }
        strcat(data.imm8, (const char*)buffer);
    }
    else if(data.imm32)
    {
        int noimm = 1;
        int skip = 0;
        if(data.prefixes&0x20)
        {
            data.length+=2;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            adr = ((char*)data.adr)+data.length-1;
            byte = *(unsigned char*)adr;
            unsigned char buffer[5] = {};
            for(int i = 0; i<2; i++)
            {
                adr = (((char*)data.adr)+data.length-1)-i;
                byte = *(unsigned char*)adr;
                if((byte&0xF0) || noimm == 0)
                {
                    noimm = 0;
                    if((byte&0xF0)>0x90)
                    {
                        buffer[i*2+skip] = ((byte&0xF0)>>4)+0x37;
                    }
                    else
                    {
                        buffer[i*2+skip] = (((byte&0xF0)>>4)+0x30);
                    }
                    if((byte&0xF)>0x9)
                    {
                        buffer[i*2+1+skip] = (byte&0xF)+0x37;
                    }
                    else
                    {
                        buffer[i*2+1+skip] = (byte&0xF)+0x30;
                    }
                }
                else if(byte&0xF)
                {
                    noimm = 0;
                    if((byte&0xF)>0x9)
                    {
                        buffer[i*2+skip] = (byte&0xF)+0x37;
                    }
                    else
                    {
                        buffer[i*2+skip] = (byte&0xF)+0x30;
                    }
                    skip--;
                }
                else
                {
                    skip-=2;
                }
            }
            if(4+skip == 0)
            {
                buffer[0] = 0x30;
                buffer[1] = 0x0;
            }
            else
                buffer[4+skip] = 0x0;
            strcat(data.imm32, (const char*)buffer);
        }
        else
        {
            data.length+=4;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            adr = ((char*)data.adr)+data.length-1;
            byte = *(unsigned char*)adr;
            unsigned char buffer[17] = {};
            for(int i = 0; i<4; i++)
            {
                adr = (((char*)data.adr)+data.length-1)-i;
                byte = *(unsigned char*)adr;
                if(data.prefixes&0x8 && i == 0 && byte > 0x7F)
                {
                    buffer[0] = 0x46;
                    buffer[1] = 0x46;
                    buffer[2] = 0x46;
                    buffer[3] = 0x46;
                    buffer[4] = 0x46;
                    buffer[5] = 0x46;
                    buffer[6] = 0x46;
                    buffer[7] = 0x46;
                    skip +=8;
                }
                if((byte&0xF0) || noimm == 0)
                {
                    noimm = 0;
                    if((byte&0xF0)>0x90)
                    {
                        buffer[i*2+skip] = ((byte&0xF0)>>4)+0x37;
                    }
                    else
                    {
                        buffer[i*2+skip] = (((byte&0xF0)>>4)+0x30);
                    }
                    if((byte&0xF)>0x9)
                    {
                        buffer[i*2+1+skip] = (byte&0xF)+0x37;
                    }
                    else
                    {
                        buffer[i*2+1+skip] = (byte&0xF)+0x30;
                    }
                }
                else if(byte&0xF)
                {
                    noimm = 0;
                    if((byte&0xF)>0x9)
                    {
                        buffer[i*2+skip] = (byte&0xF)+0x37;
                    }
                    else
                    {
                        buffer[i*2+skip] = (byte&0xF)+0x30;
                    }
                    skip--;
                }
                else
                {
                    skip-=2;
                }
            }
            if(8+skip == 0)
            {
                buffer[0] = 0x30;
                buffer[1] = 0x0;
            }
            else
                buffer[8+skip] = 0x0;
            strcat(data.imm32, (const char*)buffer);
        }
    }
    if(data.rel8)
    {
        data.length+=1;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        uint64_t buffer = ((uint64_t)data.adr)+data.length+(*(signed char *)(((char*)data.adr)+data.length-1));
        uint64_t digits = getdigits(buffer);
        char* hexstr = new char[digits+1];
        ntohs(buffer, digits, hexstr);
        strcat(data.rel8, hexstr);
        delete hexstr;
    }
    else if(data.rel32)
    {
        data.length+=4;
        if(data.length > 15)
        {
            data.malformed = 1;
            return;
        }
        uint64_t buffer = ((uint64_t)data.adr)+data.length+(*(int32_t*)(((char*)data.adr)+data.length-1));
        uint64_t digits = getdigits(buffer);
        char* hexstr = new char[digits+1];
        ntohs(buffer, digits, hexstr);
        strcat(data.rel32, hexstr);
        delete hexstr;
    }
    return;
}

void parse2byteins(INSTRUCTIONDATA &data)
{
    unsigned char byte = *(unsigned char*)(((char*)data.adr)+data.length-1);
    unsigned char byte2 = *(unsigned char*)(((char*)data.adr)+data.length);
    unsigned char byte3 = *(unsigned char*)(((char*)data.adr)+data.length+1);
    switch(byte)
	{
		case 0x00:
			switch((byte2&0x38)>>3)
			{
                case 0x0:
					strcat(data.opcptr, "SLDT");
					data.prefixes = (data.prefixes&0xFFF7);
					data.prefixes = (data.prefixes|0x0020);
					data.rm32 = data.opr1ptr;
					break;
                case 0x1:
					strcat(data.opcptr, "STR");
					data.prefixes = (data.prefixes&0xFFF7);
					data.prefixes = (data.prefixes|0x0020);
					data.rm32 = data.opr1ptr;
					break;
                case 0x2:
					strcat(data.opcptr, "LLDT");
					data.prefixes = (data.prefixes&0xFFF7);
					data.prefixes = (data.prefixes|0x0020);
					data.rm32 = data.opr1ptr;
					break;
                case 0x3:
					strcat(data.opcptr, "LTR");
					data.prefixes = (data.prefixes&0xFFF7);
					data.prefixes = (data.prefixes|0x0020);
					data.rm32 = data.opr1ptr;
					break;
                case 0x4:
					strcat(data.opcptr, "VERR");
					data.prefixes = (data.prefixes&0xFFF7);
					data.prefixes = (data.prefixes|0x0020);
					data.rm32 = data.opr1ptr;
					break;
                case 0x5:
					strcat(data.opcptr, "VERW");
					data.prefixes = (data.prefixes&0xFFF7);
					data.prefixes = (data.prefixes|0x0020);
					data.rm32 = data.opr1ptr;
					break;
                case 0x6:
					data.malformed = 1;
					return;
					break;
                case 0x7:
					data.malformed = 1;
					return;
					break;
            }
			break;
		case 0x01:
		    if(byte2 == 0xC1)
			{
				strcat(data.opcptr, "VMCALL");
			}
			else if(byte2 == 0xC2)
			{
				strcat(data.opcptr, "VMLAUNCH");
			}
			else if(byte2 == 0xC3)
			{
				strcat(data.opcptr, "VMRESUME");
			}
			else if(byte2 == 0xC4)
			{
				strcat(data.opcptr, "VMXOFF");
			}
			else if(byte2 == 0xC8)
			{
				strcat(data.opcptr, "MONITOR");
			}
			else if(byte2 == 0xC9)
			{
				strcat(data.opcptr, "MWAIT");
			}
			else if(byte2 == 0xD0)
			{
				strcat(data.opcptr, "XGETBV");
			}
			else if(byte2 == 0xD1)
			{
				strcat(data.opcptr, "XSETBV");
			}
			else if(byte2 == 0xF8)
			{
				strcat(data.opcptr, "SWAPGS");
			}
			else if(byte2 == 0xF9)
			{
				strcat(data.opcptr, "RDTSCP");
			}
			else
            {
                switch((byte2&0x38)>>3)
                {
                    case 0x0:
                        strcat(data.opcptr, "SGDT");
                        data.tword = 1;
                        data.rm32 = data.opr1ptr;
                        break;
                    case 0x1:
                        strcat(data.opcptr, "SIDT");
                        data.tword = 1;
                        data.rm32 = data.opr1ptr;
                        break;
                    case 0x2:
                        strcat(data.opcptr, "LGDT");
                        data.tword = 1;
                        data.rm32 = data.opr1ptr;
                        break;
                    case 0x3:
                        strcat(data.opcptr, "LIDT");
                        data.tword = 1;
                        data.rm32 = data.opr1ptr;
                        break;
                    case 0x4:
                        strcat(data.opcptr, "SMSW");
                        data.rm8 = data.opr1ptr;
                        break;
                    case 0x5:
                        data.malformed = 1;
                        return;
                        break;
                    case 0x6:
                        strcat(data.opcptr, "LMSW");
                        data.rm8 = data.opr1ptr;
                        break;
                    case 0x7:
                        strcat(data.opcptr, "INVLPG");
                        data.rm8 = data.opr1ptr;
                        break;
                }
            }
            break;
		case 0x02:
		    data.prefixes = (data.prefixes&0xFFD7)+0x20;
			strcat(data.opcptr, "LAR");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x03:
		    data.prefixes = (data.prefixes&0xFFD7)+0x20;
			strcat(data.opcptr, "LSL");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x04:
			data.malformed = 1;
			return;
			break;
		case 0x05:
			strcat(data.opcptr, "SYSCALL");
			break;
		case 0x06:
			strcat(data.opcptr, "CLTS");
			break;
		case 0x07:
			strcat(data.opcptr, "SYSRET");
			break;
		case 0x08:
			strcat(data.opcptr, "INVD");
			break;
		case 0x09:
			strcat(data.opcptr, "WBINVD");
			break;
		case 0x0A:
			data.malformed = 1;
			return;
			break;
		case 0x0B:
			strcat(data.opcptr, "UD2");
			break;
		case 0x0C:
			data.malformed = 1;
			return;
			break;
		case 0x0D:
			strcat(data.opcptr, "prefetch");
			data.prefixes = (data.prefixes&0xFFF7);
			data.rm32 = data.opr1ptr;
			break;
		case 0x0E:
			data.malformed = 1;
			return;
			break;
		case 0x0F:
			data.malformed = 1;
			return;
			break;
		case 0x10:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVUPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "MOVSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVUPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x11:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVUPD");
				data.xmmm128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "MOVSD");
				data.xmmm64 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVSS");
				data.xmmm32 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVUPS");
				data.xmmm128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x12:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVLPD");
				data.xmm = data.opr1ptr;
				data.m64 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "MOVDDUP");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVSLDUP");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVHLPS");
				data.xmm = data.opr1ptr;
				data.xmm = data.opr2ptr;
				strcat(data.opcptr, "MOVLPS");
				data.xmm = data.opr1ptr;
				data.m64 = data.opr2ptr;
			}
			break;
		case 0x13:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVLPD");
				data.m64 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVLPS");
				data.m64 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x14:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "UNPCKLPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "UNPCKLPS");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			break;
		case 0x15:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "UNPCKHPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "UNPCKHPS");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			break;
		case 0x16:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVHPD");
				data.xmm = data.opr1ptr;
				data.m64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVSHDUP");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVHPS");
				data.xmm = data.opr1ptr;
				data.m64 = data.opr2ptr;
				strcat(data.opcptr, "MOVLHPS");
				data.xmm = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x17:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVHPD");
				data.m64 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVHPS");
				data.m64 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x18:
		    if(byte2 > 0xc0)
            {
                strcat(data.opcptr, "NOP");
                data.reg32 = data.opr1ptr;
                break;
            }
            else
			switch((byte2&0x38)>>3)
			{
                case 0x0:
					strcat(data.opcptr, "PREFETCHNTA");
					data.rm8 = data.opr1ptr;
					break;
                case 0x1:
					strcat(data.opcptr, "PREFETCHT0");
					data.rm8 = data.opr1ptr;
					break;
                case 0x2:
					strcat(data.opcptr, "PREFETCHT1");
					data.rm8 = data.opr1ptr;
					break;
                case 0x3:
					strcat(data.opcptr, "PREFETCHT2");
					data.rm8 = data.opr1ptr;
					break;
                case 0x4:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
					data.rm32 = data.opr1ptr;
					break;
                case 0x5:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
                case 0x6:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
                case 0x7:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
				}
			break;
		case 0x19:
			strcat(data.opcptr, "HINT_NOP");
			data.prefixes = (data.prefixes&0xFFF7);
            data.rm32 = data.opr1ptr;
			break;
		case 0x1A:
			strcat(data.opcptr, "HINT_NOP");
			data.prefixes = (data.prefixes&0xFFF7);
            data.rm32 = data.opr1ptr;
			break;
		case 0x1B:
			strcat(data.opcptr, "HINT_NOP");
			data.prefixes = (data.prefixes&0xFFF7);
            data.rm32 = data.opr1ptr;
			break;
		case 0x1C:
			strcat(data.opcptr, "HINT_NOP");
			data.prefixes = (data.prefixes&0xFFF7);
            data.rm32 = data.opr1ptr;
			break;
		case 0x1D:
			strcat(data.opcptr, "HINT_NOP");
			data.prefixes = (data.prefixes&0xFFF7);
            data.rm32 = data.opr1ptr;
			break;
		case 0x1E:
			strcat(data.opcptr, "HINT_NOP");
			data.prefixes = (data.prefixes&0xFFF7);
            data.rm32 = data.opr1ptr;
			break;
		case 0x1F:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x1:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x2:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x3:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x4:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x5:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x6:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
			case 0x7:
					strcat(data.opcptr, "HINT_NOP");
					data.prefixes = (data.prefixes&0xFFF7);
                    data.rm32 = data.opr1ptr;
					break;
				}
			break;
		case 0x20:
			strcat(data.opcptr, "MOV");
			data.r64 = data.opr1ptr;
			data.CRn = data.opr2ptr;
			break;
		case 0x21:
			strcat(data.opcptr, "MOV");
			data.r64 = data.opr1ptr;
			data.DRn = data.opr2ptr;
			break;
		case 0x22:
			strcat(data.opcptr, "MOV");
			data.CRn = data.opr1ptr;
			data.r64 = data.opr2ptr;
			break;
		case 0x23:
			strcat(data.opcptr, "MOV");
			data.DRn = data.opr1ptr;
			data.r64 = data.opr2ptr;
			break;
		case 0x24:
			data.malformed = 1;
			return;
			break;
		case 0x25:
			data.malformed = 1;
			return;
			break;
		case 0x26:
			data.malformed = 1;
			return;
			break;
		case 0x27:
			data.malformed = 1;
			return;
			break;
		case 0x28:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVAPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVAPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x29:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVAPD");
				data.xmmm128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVAPS");
				data.xmmm128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x2A:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "CVTPI2PD");
				data.xmm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "CVTSI2SD");
				data.xmm = data.opr1ptr;
				if(byte>=0xC0)
                {
                    strcat(data.opr2ptr, "mm");
                    char qstr[2] = {(((byte&0x38)>>3)+0x30), 0x0};
                    strcat(data.opr2ptr, qstr);
                }
                else
                    data.rm32 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "CVTSI2SS");
				data.xmm = data.opr1ptr;
				if(byte>=0xC0)
                {
                    strcat(data.opr2ptr, "mm");
                    char qstr[2] = {(((byte&0x38)>>3)+0x30), 0x0};
                    strcat(data.opr2ptr, qstr);
                }
                else
                    data.rm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "CVTPI2PS");
				data.xmm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x2B:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVNTPD");
				data.m128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVNTPS");
				data.m128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x2C:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "CVTTPD2PI");
				data.mm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "CVTTSD2SI");
				data.r3264 = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "CVTTSS2SI");
				data.r3264 = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "CVTTPS2PI");
				data.mm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			break;
		case 0x2D:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "CVTPD2PI");
				data.mm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "CVTSD2SI");
				data.r3264 = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "CVTSS2SI");
				data.r3264 = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "CVTPS2PI");
				data.mm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			break;
		case 0x2E:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "UCOMISD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "UCOMISS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			break;
		case 0x2F:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "COMISD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "COMISS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			break;
		case 0x30:
			strcat(data.opcptr, "WRMSR");
			break;
		case 0x31:
			strcat(data.opcptr, "RDTSC");
			break;
		case 0x32:
			strcat(data.opcptr, "RDMSR");
			break;
		case 0x33:
			strcat(data.opcptr, "RDPMC");
			break;
		case 0x34:
			strcat(data.opcptr, "SYSENTER");
			break;
		case 0x35:
			strcat(data.opcptr, "SYSEXIT");
			break;
		case 0x36:
			data.malformed = 1;
			return;
			break;
		case 0x37:
			strcat(data.opcptr, "GETSEC");
			break;
		case 0x38:
			if(data.prefixes&0x20)
			{
			    data.length++;
				if(byte2 == 0x80)
				{
					strcat(data.opcptr, "INVEPT");
					data.r64 = data.opr1ptr;
					data.m128 = data.opr2ptr;
				}
				if(byte2 == 0x81)
				{
					strcat(data.opcptr, "INVVPID");
					data.r64 = data.opr1ptr;
					data.m128 = data.opr2ptr;
				}
			}
			else if(data.prefixes&0x4000)
			{
			    data.length++;
				if(byte2 == 0xF0)
				{
					strcat(data.opcptr, "CRC32");
					data.r3264 = data.opr1ptr;
					data.rm8 = data.opr2ptr;
				}
				if(byte2 == 0xF1)
				{
					strcat(data.opcptr, "CRC32");
					data.r3264 = data.opr1ptr;
					data.rm32 = data.opr2ptr;
				}
			}
			else
			{
			    data.length++;
			    if(byte3>=0xC0)
                {
                    data.malformed = 1;
                    return;
                }
				else if(byte2 == 0xF0)
				{
					strcat(data.opcptr, "MOVBE");
					data.reg32 = data.opr1ptr;
					data.rm32 = data.opr2ptr;
				}
				else if(byte2 == 0xF1)
				{
					strcat(data.opcptr, "MOVBE");
					data.rm32 = data.opr1ptr;
					data.reg32 = data.opr2ptr;
				}
				else
                {
                    data.malformed = 1;
                    return;
                }
			}
			break;
		case 0x39:
			data.malformed = 1;
			return;
			break;
		case 0x3A:
		    data.length++;
			if(data.prefixes&0x20)
			{
				if(byte2 == 0x08)
				{
					strcat(data.opcptr, "ROUNDPS");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x09)
				{
					strcat(data.opcptr, "ROUNDPD");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x0A)
				{
					strcat(data.opcptr, "ROUNDSS");
					data.xmm = data.opr1ptr;
					data.xmmm32 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x0B)
				{
					strcat(data.opcptr, "ROUNDSD");
					data.xmm = data.opr1ptr;
					data.xmmm64 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x0C)
				{
					strcat(data.opcptr, "BLENDPS");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x0D)
				{
					strcat(data.opcptr, "BLENDPD");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x0E)
				{
					strcat(data.opcptr, "PBLENDW");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x0F)
				{
					strcat(data.opcptr, "PALIGNR");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
				}
				if(byte2 == 0x14)
				{
					strcat(data.opcptr, "PEXTRB");
					data.m8 = data.opr1ptr;
					data.xmm = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x15)
				{
				    data.prefixes = (data.prefixes&0xFFD7)+0x20;
					strcat(data.opcptr, "PEXTRW");
					data.rm32 = data.opr1ptr;
					data.xmm = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x16)
				{
					strcat(data.opcptr, "PEXTRD");
					data.rm32 = data.opr1ptr;
					data.xmm = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x17)
				{
					strcat(data.opcptr, "EXTRACTPS");
					data.rm32 = data.opr1ptr;
					data.xmm = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x20)
				{
					strcat(data.opcptr, "PINSRB");
					data.xmm = data.opr1ptr;
					data.m8 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x21)
				{
					strcat(data.opcptr, "INSERTPS");
					data.xmm = data.opr1ptr;
					data.prefixes = data.prefixes&0xFFD7;
					data.rm32 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x22)
				{
					strcat(data.opcptr, "PINSRD");
					data.xmm = data.opr1ptr;
					data.rm32 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x40)
				{
					strcat(data.opcptr, "DPPS");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
				}
				if(byte2 == 0x41)
				{
					strcat(data.opcptr, "DPPD");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
				}
				if(byte2 == 0x42)
				{
					strcat(data.opcptr, "MPSADBW");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x60)
				{
					strcat(data.opcptr, "PCMPESTRM");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x61)
				{
					strcat(data.opcptr, "PCMPESTRI");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x62)
				{
					strcat(data.opcptr, "PCMPISTRM");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
				if(byte2 == 0x63)
				{
					strcat(data.opcptr, "PCMPISTRI");
					data.xmm = data.opr1ptr;
					data.xmmm128 = data.opr2ptr;
					data.imm8 = data.opr3ptr;
				}
			}
			else if(byte2 == 0x0F)
			{
                strcat(data.opcptr, "PALIGNR");
                data.mm = data.opr1ptr;
                data.mmm64 = data.opr2ptr;
			}
			else
            {
                data.malformed = 1;
                break;
            }
			break;
		case 0x3B:
			data.malformed = 1;
			return;
			break;
		case 0x3C:
			data.malformed = 1;
			return;
			break;
		case 0x3D:
			data.malformed = 1;
			return;
			break;
		case 0x3E:
			data.malformed = 1;
			return;
			break;
		case 0x3F:
			data.malformed = 1;
			return;
			break;
		case 0x40:
			strcat(data.opcptr, "CMOVO");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x41:
			strcat(data.opcptr, "CMOVNO");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x42:
			strcat(data.opcptr, "CMOVB");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x43:
			strcat(data.opcptr, "CMOVNB");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x44:
			strcat(data.opcptr, "CMOVZ");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x45:
			strcat(data.opcptr, "CMOVNZ");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x46:
			strcat(data.opcptr, "CMOVBE");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x47:
			strcat(data.opcptr, "CMOVNBE");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x48:
			strcat(data.opcptr, "CMOVS");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x49:
			strcat(data.opcptr, "CMOVNS");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x4A:
			strcat(data.opcptr, "CMOVP");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x4B:
			strcat(data.opcptr, "CMOVNP");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x4C:
			strcat(data.opcptr, "CMOVL");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x4D:
			strcat(data.opcptr, "CMOVNL");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x4E:
			strcat(data.opcptr, "CMOVLE");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x4F:
			strcat(data.opcptr, "CMOVNLE");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0x50:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVMSKPD");
				data.r3264 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVMSKPS");
				data.r3264 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			break;
		case 0x51:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "SQRTPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "SQRTSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "SQRTSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "SQRTPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x52:
			if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "RSQRTSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "RSQRTPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x53:
			if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "RCPSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "RCPPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x54:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "ANDPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "ANDPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x55:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "ANDNPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "ANDNPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x56:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "ORPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "ORPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x57:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "XORPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "XORPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x58:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "ADDPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "ADDSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "ADDSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "ADDPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x59:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MULPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "MULSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MULSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MULPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x5A:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "CVTPD2PS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "CVTSD2SS");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "CVTSS2SD");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "CVTPS2PD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x5B:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "CVTPS2DQ");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "CVTTPS2DQ");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "CVTDQ2PS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x5C:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "SUBPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "SUBSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "SUBSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "SUBPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x5D:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MINPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "MINSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MINSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MINPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x5E:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "DIVPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "DIVSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "DIVSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "DIVPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x5F:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MAXPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "MAXSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MAXSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MAXPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			break;
		case 0x60:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKLBW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PUNPCKLBW");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x61:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKLWD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PUNPCKLWD");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x62:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKLDQ");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PUNPCKLDQ");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x63:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PACKSSWB");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PACKSSWB");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x64:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PCMPGTB");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PCMPGTB");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x65:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PCMPGTW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PCMPGTW");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x66:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PCMPGTD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PCMPGTD");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x67:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PACKUSWB");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PACKUSWB");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x68:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKHBW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PUNPCKHBW");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x69:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKHWD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PUNPCKHWD");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x6A:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKHDQ");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PUNPCKHDQ");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x6B:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PACKSSDW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PACKSSDW");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x6C:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKLQDQ");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
			}
			break;
		case 0x6D:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PUNPCKHQDQ");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
			}
			break;
		case 0x6E:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVD");
				data.xmm = data.opr1ptr;
				data.rm32 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVD");
				data.mm = data.opr1ptr;
				data.rm32 = data.opr2ptr;
			}
			break;
		case 0x6F:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVDQA");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVDQU");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVQ");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x70:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PSHUFD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "PSHUFLW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "PSHUFHW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else
			{
				strcat(data.opcptr, "PSHUFW");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			break;
		case 0x71:
			if(data.prefixes&0x20)
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						strcat(data.opcptr, "PSRLW");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						strcat(data.opcptr, "PSRAW");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "PSLLW");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			else
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						strcat(data.opcptr, "PSRLW");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						strcat(data.opcptr, "PSRAW");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "PSLLW");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			break;
		case 0x72:
			if(data.prefixes&0x20)
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						strcat(data.opcptr, "PSRLD");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						strcat(data.opcptr, "PSRAD");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "PSLLD");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			else
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						strcat(data.opcptr, "PSRLD");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						strcat(data.opcptr, "PSRAD");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "PSLLD");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			break;
		case 0x73:
			if(data.prefixes&0x20)
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						strcat(data.opcptr, "PSRLQ");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x3:
						strcat(data.opcptr, "PSRLDQ");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x4:
						data.malformed = 1;
						return;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "PSLLQ");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x7:
						strcat(data.opcptr, "PSLLDQ");
						data.xmm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
					}
			}
			else
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						strcat(data.opcptr, "PSRLQ");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						data.malformed = 1;
						return;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "PSLLQ");
						data.mm = data.opr1ptr;
						data.imm8 = data.opr2ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			break;
		case 0x74:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PCMPEQB");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PCMPEQB");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x75:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PCMPEQW");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PCMPEQW");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x76:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PCMPEQD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "PCMPEQD");
				data.mm = data.opr1ptr;
				data.mmm64 = data.opr2ptr;
			}
			break;
		case 0x77:
			strcat(data.opcptr, "EMMS");
			break;
		case 0x78:
			strcat(data.opcptr, "VMREAD");
			data.rm64 = data.opr1ptr;
			data.r64 = data.opr2ptr;
			break;
		case 0x79:
			strcat(data.opcptr, "VMWRITE");
			data.r64 = data.opr1ptr;
			data.rm64 = data.opr2ptr;
			break;
		case 0x7A:
			data.malformed = 1;
			return;
			break;
		case 0x7B:
			data.malformed = 1;
			return;
			break;
		case 0x7C:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "HADDPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "HADDPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
			}
			break;
		case 0x7D:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "HSUBPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "HSUBPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
			}
			else
			{
			}
			break;
		case 0x7E:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVD");
				data.rm32 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVQ");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVD");
				data.rm32 = data.opr1ptr;
				data.mm = data.opr2ptr;
			}
			break;
		case 0x7F:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "MOVDQA");
				data.xmmm128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "MOVDQU");
				data.xmmm128 = data.opr1ptr;
				data.xmm = data.opr2ptr;
			}
			else
			{
				strcat(data.opcptr, "MOVQ");
				data.mmm64 = data.opr1ptr;
				data.mm = data.opr2ptr;
			}
			break;
		case 0x80:
			strcat(data.opcptr, "JO");
			data.rel32 = data.opr1ptr;
			break;
		case 0x81:
			strcat(data.opcptr, "JNO");
			data.rel32 = data.opr1ptr;
			break;
		case 0x82:
			strcat(data.opcptr, "JB");
			data.rel32 = data.opr1ptr;
			break;
		case 0x83:
			strcat(data.opcptr, "JNB");
			data.rel32 = data.opr1ptr;
			break;
		case 0x84:
			strcat(data.opcptr, "JZ");
			data.rel32 = data.opr1ptr;
			break;
		case 0x85:
			strcat(data.opcptr, "JNZ");
			data.rel32 = data.opr1ptr;
			break;
		case 0x86:
			strcat(data.opcptr, "JBE");
			data.rel32 = data.opr1ptr;
			break;
		case 0x87:
			strcat(data.opcptr, "JNBE");
			data.rel32 = data.opr1ptr;
			break;
		case 0x88:
			strcat(data.opcptr, "JS");
			data.rel32 = data.opr1ptr;
			break;
		case 0x89:
			strcat(data.opcptr, "JNS");
			data.rel32 = data.opr1ptr;
			break;
		case 0x8A:
			strcat(data.opcptr, "JP");
			data.rel32 = data.opr1ptr;
			break;
		case 0x8B:
			strcat(data.opcptr, "JNP");
			data.rel32 = data.opr1ptr;
			break;
		case 0x8C:
			strcat(data.opcptr, "JL");
			data.rel32 = data.opr1ptr;
			break;
		case 0x8D:
			strcat(data.opcptr, "JNL");
			data.rel32 = data.opr1ptr;
			break;
		case 0x8E:
			strcat(data.opcptr, "JLE");
			data.rel32 = data.opr1ptr;
			break;
		case 0x8F:
			strcat(data.opcptr, "JNLE");
			data.rel32 = data.opr1ptr;
			break;
		case 0x90:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETO");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x91:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNO");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x92:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETB");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x93:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNB");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x94:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETZ");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x95:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNZ");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x96:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETBE");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x97:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNBE");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x98:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETS");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x99:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNS");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x9A:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETP");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x9B:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNP");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x9C:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETL");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x9D:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNL");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x9E:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETLE");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0x9F:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					strcat(data.opcptr, "SETNLE");
					data.rm8 = data.opr1ptr;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					data.malformed = 1;
					return;
					break;
			case 0x7:
					data.malformed = 1;
					return;
					break;
				}
			break;
		case 0xA0:
			strcat(data.opcptr, "PUSH fs");
			break;
		case 0xA1:
			strcat(data.opcptr, "POP fs");
			break;
		case 0xA2:
			strcat(data.opcptr, "CPUID");
			break;
		case 0xA3:
			strcat(data.opcptr, "BT");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xA4:
			strcat(data.opcptr, "SHLD");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			data.imm8 = data.opr3ptr;
			break;
		case 0xA5:
			strcat(data.opcptr, "SHLD");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			strcat(data.opr3ptr, "cl");
			break;
		case 0xA6:
			data.malformed = 1;
			return;
			break;
		case 0xA7:
			data.malformed = 1;
			return;
			break;
		case 0xA8:
			strcat(data.opcptr, "PUSH gs");
			break;
		case 0xA9:
			strcat(data.opcptr, "POP gs");
			break;
		case 0xAA:
			strcat(data.opcptr, "RSM");
			break;
		case 0xAB:
			strcat(data.opcptr, "BTS");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xAC:
			strcat(data.opcptr, "SHRD");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			data.imm8 = data.opr3ptr;
			break;
		case 0xAD:
			strcat(data.opcptr, "SHRD");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			strcat(data.opr3ptr, "cl");
			break;
		case 0xAE:
		    if(byte2 == 0xE8)
            {
                strcat(data.opcptr, "LFENCE");
                break;
            }
            else if(byte2 == 0xF0)
            {
                strcat(data.opcptr, "MFENCE");
                break;
            }
            else if(byte2 == 0xF8)
            {
                strcat(data.opcptr, "SFENCE");
                break;
            }
            else if(byte2 < 0xC0)
            {
                switch((byte2&0x38)>>3)
                {
                case 0x0:
                        strcat(data.opcptr, "FXSAVE");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x1:
                        strcat(data.opcptr, "FXRSTOR");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x2:
                        strcat(data.opcptr, "LDMXCSR");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x3:
                        strcat(data.opcptr, "STMXCSR");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x4:
                        strcat(data.opcptr, "XSAVE");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x5:
                        strcat(data.opcptr, "XRSTOR");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x6:
                        strcat(data.opcptr, "XSAVEOPT");
                        data.rm32 = data.opr1ptr;
                        break;
                case 0x7:
                        strcat(data.opcptr, "CLFLUSH");
                        data.rm32 = data.opr1ptr;
                        break;
                }
            }
            else
            {
                data.malformed = 1;
                return;
            }
			break;
		case 0xAF:
			strcat(data.opcptr, "IMUL");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xB0:
			strcat(data.opcptr, "CMPXCHG");
			data.rm8 = data.opr1ptr;
			data.reg8 = data.opr2ptr;
			break;
		case 0xB1:
			strcat(data.opcptr, "CMPXCHG");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xB2:
		    if(byte2>=0xc0)
            {
                data.malformed = 1;
                return;
            }
			strcat(data.opcptr, "LSS");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xB3:
			strcat(data.opcptr, "BTR");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xB4:
			strcat(data.opcptr, "LFS");
			data.fword = 1;
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xB5:
			if(byte2>= 0xC0)
            {
                data.malformed = 1;
                return;
            }
            strcat(data.opcptr, "LGS");
			data.fword = 1;
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xB6:
			strcat(data.opcptr, "MOVZX");
			data.reg32 = data.opr1ptr;
			data.rm8 = data.opr2ptr;
			break;
		case 0xB7:
			strcat(data.opcptr, "MOVZX");
			data.reg32 = data.opr1ptr;
			data.prefixes = (data.prefixes&0xFFD7)+0x20;
			data.rm32 = data.opr2ptr;
			break;
		case 0xB8:
			if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "POPCNT");
				data.reg32 = data.opr1ptr;
				data.rm32 = data.opr2ptr;
			}
			else
			{
			}
			break;
		case 0xB9:
			strcat(data.opcptr, "UD1");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xBA:
			switch((byte2&0x38)>>3)
			{
			case 0x0:
					data.malformed = 1;
					return;
					break;
			case 0x1:
					data.malformed = 1;
					return;
					break;
			case 0x2:
					data.malformed = 1;
					return;
					break;
			case 0x3:
					data.malformed = 1;
					return;
					break;
			case 0x4:
					strcat(data.opcptr, "BT");
					data.rm32 = data.opr1ptr;
					data.imm8 = data.opr2ptr;
					break;
			case 0x5:
					strcat(data.opcptr, "BTS");
					data.rm32 = data.opr1ptr;
					data.imm8 = data.opr2ptr;
					break;
			case 0x6:
					strcat(data.opcptr, "BTR");
					data.rm32 = data.opr1ptr;
					data.imm8 = data.opr2ptr;
					break;
			case 0x7:
					strcat(data.opcptr, "BTC");
					data.rm32 = data.opr1ptr;
					data.imm8 = data.opr2ptr;
					break;
				}
			break;
		case 0xBB:
			strcat(data.opcptr, "BTC");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xBC:
			strcat(data.opcptr, "BSF");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xBD:
			strcat(data.opcptr, "BSR");
			data.reg32 = data.opr1ptr;
			data.rm32 = data.opr2ptr;
			break;
		case 0xBE:
			strcat(data.opcptr, "MOVSX");
			data.reg32 = data.opr1ptr;
			data.rm8 = data.opr2ptr;
			break;
		case 0xBF:
			strcat(data.opcptr, "MOVSX");
			data.reg32 = data.opr1ptr;
            data.prefixes = (data.prefixes&0xFFD7)+0x20;
			data.rm32 = data.opr2ptr;
			break;
		case 0xC0:
			strcat(data.opcptr, "XADD");
			data.rm8 = data.opr1ptr;
			data.reg8 = data.opr2ptr;
			break;
		case 0xC1:
			strcat(data.opcptr, "XADD");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xC2:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "CMPPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else if(data.prefixes&0x4000)
			{
				strcat(data.opcptr, "CMPSD");
				data.xmm = data.opr1ptr;
				data.xmmm64 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else if(data.prefixes&0x8000)
			{
				strcat(data.opcptr, "CMPSS");
				data.xmm = data.opr1ptr;
				data.xmmm32 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else
			{
				strcat(data.opcptr, "CMPPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			break;
		case 0xC3:
		    if(data.prefixes&0x20)
            {
                data.malformed = 1;
                return;
            }
			strcat(data.opcptr, "MOVNTI");
			data.rm32 = data.opr1ptr;
			data.reg32 = data.opr2ptr;
			break;
		case 0xC4:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PINSRW");
				data.xmm = data.opr1ptr;
				data.r3264 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else
			{
				strcat(data.opcptr, "PINSRW");
				data.mm = data.opr1ptr;
				data.r3264 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			break;
		case 0xC5:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "PEXTRW");
				data.r3264 = data.opr1ptr;
				data.xmm = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else
			{
				strcat(data.opcptr, "PEXTRW");
				data.r3264 = data.opr1ptr;
				data.mm = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			break;
		case 0xC6:
			if(data.prefixes&0x20)
			{
				strcat(data.opcptr, "SHUFPD");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			else
			{
				strcat(data.opcptr, "SHUFPS");
				data.xmm = data.opr1ptr;
				data.xmmm128 = data.opr2ptr;
				data.imm8 = data.opr3ptr;
			}
			break;
		case 0xC7:
			if(data.prefixes&0x20)
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						data.malformed = 1;
						return;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						data.malformed = 1;
						return;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "VMCLEAR");
						data.m64 = data.opr1ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			else if(data.prefixes&0x8000)
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						data.malformed = 1;
						return;
						break;
				case 0x2:
						data.malformed = 1;
						return;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						data.malformed = 1;
						return;
						break;
				case 0x5:
						data.malformed = 1;
						return;
						break;
				case 0x6:
						strcat(data.opcptr, "VMXON");
						data.m64 = data.opr1ptr;
						break;
				case 0x7:
						data.malformed = 1;
						return;
						break;
					}
			}
			else
			{
				switch((byte2&0x38)>>3)
				{
				case 0x0:
						data.malformed = 1;
						return;
						break;
				case 0x1:
						strcat(data.opcptr, "CMPXCHG8B");
						data.m64 = data.opr1ptr;
						break;
				case 0x2:
						data.malformed = 1;
						return;
						break;
				case 0x3:
						data.malformed = 1;
						return;
						break;
				case 0x4:
						data.malformed = 1;
					return;
					break;
			case 0x5:
					data.malformed = 1;
					return;
					break;
			case 0x6:
					strcat(data.opcptr, "VMPTRLD");
					data.m64 = data.opr1ptr;
					break;
			case 0x7:
					strcat(data.opcptr, "VMPTRST");
					data.m64 = data.opr1ptr;
					break;
				}
		}
		break;
	case 0xC8:
		data.malformed = 1;
		return;
		break;
	case 0xC9:
		data.malformed = 1;
		return;
		break;
	case 0xCA:
		data.malformed = 1;
		return;
		break;
	case 0xCB:
		data.malformed = 1;
		return;
		break;
	case 0xCC:
		data.malformed = 1;
		return;
		break;
	case 0xCD:
		data.malformed = 1;
		return;
		break;
	case 0xCE:
		data.malformed = 1;
		return;
		break;
	case 0xCF:
		data.malformed = 1;
		return;
		break;
	case 0xD0:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "ADDSUBPD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else if(data.prefixes&0x4000)
		{
			strcat(data.opcptr, "ADDSUBPS");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
		}
		break;
	case 0xD1:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSRLW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSRLW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xD2:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSRLD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSRLD");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xD3:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSRLQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSRLQ");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xD4:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDQ");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xD5:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMULLW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMULLW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xD6:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "MOVQ");
			data.xmmm64 = data.opr1ptr;
			data.xmm = data.opr2ptr;
		}
		else if(data.prefixes&0x4000)
		{
			strcat(data.opcptr, "MOVDQ2Q");
			data.mm = data.opr1ptr;
			data.xmm = data.opr2ptr;
		}
		else if(data.prefixes&0x8000)
		{
			strcat(data.opcptr, "MOVQ2DQ");
			data.xmm = data.opr1ptr;
			data.mm = data.opr2ptr;
		}
		else
		{
		}
		break;
	case 0xD7:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMOVMSKB");
			data.r3264 = data.opr1ptr;
			data.xmm = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMOVMSKB");
			data.r3264 = data.opr1ptr;
			data.mm = data.opr2ptr;
		}
		break;
	case 0xD8:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBUSB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBUSB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xD9:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBUSW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBUSW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xDA:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMINUB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMINUB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xDB:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PAND");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PAND");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xDC:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDUSB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDUSB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xDD:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDUSW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDUSW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xDE:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMAXUB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMAXUB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xDF:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PANDN");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PANDN");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE0:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PAVGB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PAVGB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE1:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSRAW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSRAW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE2:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSRAD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSRAD");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE3:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PAVGW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PAVGW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE4:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMULHUW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMULHUW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE5:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMULHW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMULHW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE6:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "CVTTPD2DQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else if(data.prefixes&0x4000)
		{
			strcat(data.opcptr, "CVTPD2DQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else if(data.prefixes&0x8000)
		{
			strcat(data.opcptr, "CVTDQ2PD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
		}
		break;
	case 0xE7:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "MOVNTDQ");
			data.m128 = data.opr1ptr;
			data.xmm = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "MOVNTQ");
			data.m64 = data.opr1ptr;
			data.mm = data.opr2ptr;
		}
		break;
	case 0xE8:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBSB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBSB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xE9:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBSW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBSW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xEA:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMINSW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMINSW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xEB:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "POR");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "POR");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xEC:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDSB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDSB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xED:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDSW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDSW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xEE:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMAXSW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMAXSW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xEF:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PXOR");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PXOR");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF0:
		if(data.prefixes&0x4000)
		{
			strcat(data.opcptr, "LDDQU");
			data.xmm = data.opr1ptr;
			data.m128 = data.opr2ptr;
		}
		else
		{
		}
		break;
	case 0xF1:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSLLW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSLLW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF2:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSLLD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSLLD");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF3:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSLLQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSLLQ");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF4:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMULUDQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMULUDQ");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF5:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PMADDWD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PMADDWD");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF6:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSADBW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSADBW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF7:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "MASKMOVDQU");
			data.m128 = data.opr1ptr;
			data.xmm = data.opr2ptr;
			data.xmm = data.opr3ptr;
		}
		else
		{
			strcat(data.opcptr, "MASKMOVQ");
			data.m64 = data.opr1ptr;
			data.mm = data.opr2ptr;
			data.mm = data.opr3ptr;
		}
		break;
	case 0xF8:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xF9:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xFA:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBD");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBD");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xFB:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PSUBQ");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PSUBQ");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xFC:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDB");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDB");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xFD:
		if(data.prefixes&0x20)
		{
			strcat(data.opcptr, "PADDW");
			data.xmm = data.opr1ptr;
			data.xmmm128 = data.opr2ptr;
		}
		else
		{
			strcat(data.opcptr, "PADDW");
			data.mm = data.opr1ptr;
			data.mmm64 = data.opr2ptr;
		}
		break;
	case 0xFE:
		strcat(data.opcptr, "PADDD");
		data.mm = data.opr1ptr;
		data.mmm64 = data.opr2ptr;
		break;
	case 0xFF:
		data.malformed = 1;
		return;
		break;
    }
    if(data.parsed == 0)
    {
        parsedata(data);
    }
    return;
}

void parseins(INSTRUCTIONDATA &data)
{
    unsigned char byte = *(unsigned char*)(((char*)data.adr)+data.length-1);
    void *adr;
    int digits;
    int rex = 0;
    switch(byte)
    {
        case 0x0:
            strcat(data.opcptr, "add");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x1:
            strcat(data.opcptr, "add");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x2:
            strcat(data.opcptr, "add");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x3:
            strcat(data.opcptr, "add");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x4:
            strcat(data.opcptr, "add");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x5:
            strcat(data.opcptr, "add");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x6:
            data.malformed = 1;
            return;
        case 0x7:
            data.malformed = 1;
            return;
        case 0x8:
            strcat(data.opcptr, "or");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x9:
            strcat(data.opcptr, "or");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0xA:
            strcat(data.opcptr, "or");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0xB:
            strcat(data.opcptr, "or");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0xC:
            strcat(data.opcptr, "or");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0xD:
            strcat(data.opcptr, "or");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0xE:
            data.malformed = 1;
            return;
        case 0xF:
            data.length++;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            parse2byteins(data); //fixit
            break;
        case 0x10:
            strcat(data.opcptr, "adc");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x11:
            strcat(data.opcptr, "adc");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x12:
            strcat(data.opcptr, "adc");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x13:
            strcat(data.opcptr, "adc");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x14:
            strcat(data.opcptr, "adc");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x15:
            strcat(data.opcptr, "adc");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x16:
            data.malformed = 1;
            return;
        case 0x17:
            data.malformed = 1;
            return;
        case 0x18:
            strcat(data.opcptr, "sbb");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x19:
            strcat(data.opcptr, "sbb");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x1A:
            strcat(data.opcptr, "sbb");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x1B:
            strcat(data.opcptr, "sbb");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x1C:
            strcat(data.opcptr, "sbb");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x1D:
            strcat(data.opcptr, "sbb");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x1E:
            data.malformed = 1;
            return;
        case 0x1F:
            data.malformed = 1;
            return;
        case 0x20:
            strcat(data.opcptr, "and");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x21:
            strcat(data.opcptr, "and");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x22:
            strcat(data.opcptr, "and");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x23:
            strcat(data.opcptr, "and");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x24:
            strcat(data.opcptr, "and");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x25:
            strcat(data.opcptr, "and");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x26:
            data.prefixes = (data.prefixes&0xE060);
            data.prefixes = (data.prefixes|0x80);
            data.length++;
            parseins(data);
            break;
        case 0x27:
            data.malformed = 1;
            return;
        case 0x28:
            strcat(data.opcptr, "sub");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x29:
            strcat(data.opcptr, "sub");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x2A:
            strcat(data.opcptr, "sub");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x2B:
            strcat(data.opcptr, "sub");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x2C:
            strcat(data.opcptr, "sub");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x2D:
            strcat(data.opcptr, "sub");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x2E:
            data.prefixes = (data.prefixes&0xE060);
            data.prefixes = (data.prefixes|0x100);
            data.length++;
            parseins(data);
            break;
        case 0x2F:
            data.malformed = 1;
            return;
        case 0x30:
            strcat(data.opcptr, "xor");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x31:
            strcat(data.opcptr, "xor");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x32:
            strcat(data.opcptr, "xor");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x33:
            strcat(data.opcptr, "xor");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x34:
            strcat(data.opcptr, "xor");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x35:
            strcat(data.opcptr, "xor");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x36:
            data.prefixes = (data.prefixes&0xE060);
            data.prefixes = (data.prefixes|0x200);
            data.length++;
            parseins(data);
            break;
        case 0x37:
            data.malformed = 1;
            return;
        case 0x38:
            strcat(data.opcptr, "cmp");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x39:
            strcat(data.opcptr, "cmp");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x3A:
            strcat(data.opcptr, "cmp");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x3B:
            strcat(data.opcptr, "cmp");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x3C:
            strcat(data.opcptr, "cmp");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0x3D:
            strcat(data.opcptr, "cmp");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            data.imm32 = data.opr2ptr;
            break;
        case 0x3E:
            data.prefixes = (data.prefixes&0xE060);
            data.prefixes = (data.prefixes|0x400);
            data.length++;
            parseins(data);
            break;
        case 0x3F:
            data.malformed = 1;
            return;
        case 0x40:
            data.prefixes = (data.prefixes&0xFFE0)+0x10;
            data.length++;
            parseins(data);
            break;
        case 0x41:
            data.prefixes = (data.prefixes&0xFFE0)+0x1;
            data.length++;
            parseins(data);
            break;
        case 0x42:
            data.prefixes = (data.prefixes&0xFFE0)+0x2;
            data.length++;
            parseins(data);
            break;
        case 0x43:
            data.prefixes = (data.prefixes&0xFFE0)+0x3;
            data.length++;
            parseins(data);
            break;
        case 0x44:
            data.prefixes = (data.prefixes&0xFFE0)+0x4;
            data.length++;
            parseins(data);
            break;
        case 0x45:
            data.prefixes = (data.prefixes&0xFFE0)+0x5;
            data.length++;
            parseins(data);
            break;
        case 0x46:
            data.prefixes = (data.prefixes&0xFFE0)+0x6;
            data.length++;
            parseins(data);
            break;
        case 0x47:
            data.prefixes = (data.prefixes&0xFFE0)+0x7;
            data.length++;
            parseins(data);
            break;
        case 0x48:
            data.prefixes = (data.prefixes&0xFFC0)+0x8;
            data.length++;
            parseins(data);
            break;
        case 0x49:
            data.prefixes = (data.prefixes&0xFFE0)+0x9;
            data.length++;
            parseins(data);
            break;
        case 0x4A:
            data.prefixes = (data.prefixes&0xFFE0)+0xA;
            data.length++;
            parseins(data);
            break;
        case 0x4B:
            data.prefixes = (data.prefixes&0xFFE0)+0xB;
            data.length++;
            parseins(data);
            break;
        case 0x4C:
            data.prefixes = (data.prefixes&0xFFE0)+0xC;
            data.length++;
            parseins(data);
            break;
        case 0x4D:
            data.prefixes = (data.prefixes&0xFFE0)+0xD;
            data.length++;
            parseins(data);
            break;
        case 0x4E:
            data.prefixes = (data.prefixes&0xFFE0)+0xE;
            data.length++;
            parseins(data);
            break;
        case 0x4F:
            data.prefixes = (data.prefixes&0xFFE0)+0xF;
            data.length++;
            parseins(data);
            break;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
            strcat(data.opcptr, "push");
            strcat(data.opr1ptr, (char*)&r32map[16+(byte&0x7)+(24*(data.prefixes&0x1))-((data.prefixes&0x20)>>2)][0]);
            break;
        case 0x58:
        case 0x59:
        case 0x5A:
        case 0x5B:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F:
            strcat(data.opcptr, "pop");
            strcat(data.opr1ptr, (char*)&r32map[16+(byte&0x7)+(24*(data.prefixes&0x1))-((data.prefixes&0x20)>>2)][0]);
            break;
        case 0x60:
            data.malformed = 1;
            return;
        case 0x61:
            data.malformed = 1;
            return;
        case 0x62:
            data.malformed = 1;
            return;
        case 0x63:
            strcat(data.opcptr, "movsxd");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x64:
            data.prefixes = (data.prefixes&0xE060);
            data.prefixes = (data.prefixes|0x800);
            data.length++;
            parseins(data);
            break;
        case 0x65:
            data.prefixes = (data.prefixes&0xE060);
            data.prefixes = (data.prefixes|0x1000);
            data.length++;
            parseins(data);
            break;
        case 0x66:
            data.prefixes = (data.prefixes&0xFFE0);
            data.prefixes = (data.prefixes|0x20);
            data.length++;
            parseins(data);
            break;
        case 0x67:
            data.prefixes = (data.prefixes&0xFFE0);
            data.prefixes = (data.prefixes|0x40);
            data.length++;
            parseins(data);
            break;
        case 0x68:
            strcat(data.opcptr, "push");
            data.imm32 = data.opr1ptr;
            break;
        case 0x69:
            strcat(data.opcptr, "imul");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            data.imm32 = data.opr3ptr;
            break;
        case 0x6A:
            strcat(data.opcptr, "push");
            data.imm8 = data.opr1ptr;
            break;
        case 0x6B:
            strcat(data.opcptr, "imul");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            data.imm8 = data.opr3ptr;
            break;
        case 0x6C:
            strcat(data.opcptr, "insb");
            break;
        case 0x6D:
            strcat(data.opcptr, "insd");
            break;
        case 0x6E:
            strcat(data.opcptr, "outsb");
            break;
        case 0x6F:
            strcat(data.opcptr, "outsd");
            break;
        case 0x70:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jo");
            data.rel8 = data.opr1ptr;
            break;
        case 0x71:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jno");
            data.rel8 = data.opr1ptr;
            break;
        case 0x72:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jb");
            data.rel8 = data.opr1ptr;
            break;
        case 0x73:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jae");
            data.rel8 = data.opr1ptr;
            break;
        case 0x74:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "je");
            data.rel8 = data.opr1ptr;
            break;
        case 0x75:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jne");
            data.rel8 = data.opr1ptr;
            break;
        case 0x76:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jbe");
            data.rel8 = data.opr1ptr;
            break;
        case 0x77:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "ja");
            data.rel8 = data.opr1ptr;
            break;
        case 0x78:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "js");
            data.rel8 = data.opr1ptr;
            break;
        case 0x79:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jns");
            data.rel8 = data.opr1ptr;
            break;
        case 0x7A:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jp");
            data.rel8 = data.opr1ptr;
            break;
        case 0x7B:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jnp");
            data.rel8 = data.opr1ptr;
            break;
        case 0x7C:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jl");
            data.rel8 = data.opr1ptr;
            break;
        case 0x7D:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jge");
            data.rel8 = data.opr1ptr;
            break;
        case 0x7E:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jle");
            data.rel8 = data.opr1ptr;
            break;
        case 0x7F:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "jg");
            data.rel8 = data.opr1ptr;
            break;
        case 0x80:
            adr = ((char*)data.adr)+data.length;
            byte = *(unsigned char*)adr;
            byte = ((byte&0x38)>>3);
            data.rm8 = data.opr1ptr;
            data.imm8 = data.opr2ptr;
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "add");
                    break;
                case 1:
                    strcat(data.opcptr, "or");
                    break;
                case 2:
                    strcat(data.opcptr, "adc");
                    break;
                case 3:
                    strcat(data.opcptr, "sbb");
                    break;
                case 4:
                    strcat(data.opcptr, "and");
                    break;
                case 5:
                    strcat(data.opcptr, "sub");
                    break;
                case 6:
                    strcat(data.opcptr, "xor");
                    break;
                case 7:
                    strcat(data.opcptr, "cmp");
                    break;
            }
            break;
        case 0x81:
            adr = ((char*)data.adr)+data.length;
            byte = *(unsigned char*)adr;
            byte = ((byte&0x38)>>3);
            data.rm32 = data.opr1ptr;
            data.imm32 = data.opr2ptr;
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "add");
                    break;
                case 1:
                    strcat(data.opcptr, "or");
                    break;
                case 2:
                    strcat(data.opcptr, "adc");
                    break;
                case 3:
                    strcat(data.opcptr, "sbb");
                    break;
                case 4:
                    strcat(data.opcptr, "and");
                    break;
                case 5:
                    strcat(data.opcptr, "sub");
                    break;
                case 6:
                    strcat(data.opcptr, "xor");
                    break;
                case 7:
                    strcat(data.opcptr, "cmp");
                    break;
            }
            break;
        case 0x82:
            data.malformed = 1;
            return;
        case 0x83:
            adr = ((char*)data.adr)+data.length;
            byte = *(unsigned char*)adr;
            byte = ((byte&0x38)>>3);
            data.rm32 = data.opr1ptr;
            data.imm8 = data.opr2ptr;
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "add");
                    break;
                case 1:
                    strcat(data.opcptr, "or");
                    break;
                case 2:
                    strcat(data.opcptr, "adc");
                    break;
                case 3:
                    strcat(data.opcptr, "sbb");
                    break;
                case 4:
                    strcat(data.opcptr, "and");
                    break;
                case 5:
                    strcat(data.opcptr, "sub");
                    break;
                case 6:
                    strcat(data.opcptr, "xor");
                    break;
                case 7:
                    strcat(data.opcptr, "cmp");
                    break;
            }
            break;
        case 0x84:
            strcat(data.opcptr, "test");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x85:
            strcat(data.opcptr, "test");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x86:
            strcat(data.opcptr, "xchg");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x87:
            strcat(data.opcptr, "xchg");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x88:
            strcat(data.opcptr, "mov");
            data.rm8 = data.opr1ptr;
            data.reg8 = data.opr2ptr;
            break;
        case 0x89:
            strcat(data.opcptr, "mov");
            data.rm32 = data.opr1ptr;
            data.reg32 = data.opr2ptr;
            break;
        case 0x8A:
            strcat(data.opcptr, "mov");
            data.reg8 = data.opr1ptr;
            data.rm8 = data.opr2ptr;
            break;
        case 0x8B:
            strcat(data.opcptr, "mov");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x8C:
            strcat(data.opcptr, "mov");
            data.rm32 = data.opr1ptr;
            adr = ((char*)data.adr)+data.length;
            byte = *(unsigned char*)adr;
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                    strcat(data.opr2ptr, "es");
                    break;
                case 1:
                    strcat(data.opr2ptr, "cs");
                    break;
                case 2:
                    strcat(data.opr2ptr, "ss");
                    break;
                case 3:
                    strcat(data.opr2ptr, "ds");
                    break;
                case 4:
                    strcat(data.opr2ptr, "fs");
                    break;
                case 5:
                    strcat(data.opr2ptr, "gs");
                    break;
                case 6:
                    data.malformed = 1;
                    return;
                case 7:
                    data.malformed = 1;
                    return;
            }
            break;
        case 0x8D:
            strcat(data.opcptr, "lea");
            data.reg32 = data.opr1ptr;
            data.rm32 = data.opr2ptr;
            break;
        case 0x8E:
            strcat(data.opcptr, "mov");
            data.rm32 = data.opr2ptr;
            adr = ((char*)data.adr)+data.length;
            byte = *(unsigned char*)adr;
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                    strcat(data.opr1ptr, "es");
                    break;
                case 1:
                    data.malformed = 1;
                    return;
                case 2:
                    strcat(data.opr1ptr, "ss");
                    break;
                case 3:
                    strcat(data.opr1ptr, "ds");
                    break;
                case 4:
                    strcat(data.opr1ptr, "fs");
                    break;
                case 5:
                    strcat(data.opr1ptr, "gs");
                    break;
                case 6:
                    data.malformed = 1;
                    return;
                case 7:
                    data.malformed = 1;
                    return;
            }
            break;
        case 0x8F:
            strcat(data.opcptr, "pop");
            data.rm32 = data.opr1ptr;
            adr = ((char*)data.adr)+data.length;
            byte = *(unsigned char*)adr;
            if(byte&0x38)
            {
                data.malformed = 1;
                return;
            }
            break;
        case 0x90:
            if(data.prefixes&0x8000)
            {
                strcat(data.opcptr, "pause");
                break;
            }
            if(data.prefixes&1)
            {
                strcat(data.opcptr, "xchg");
                strcat(data.opr2ptr, (char*)&r32map[((data.prefixes & 0x20)>>2)+(2*(data.prefixes&0x8))][0]);
                strcat(data.opr1ptr, (char*)&r32map[(24*(data.prefixes&0x1)+((data.prefixes & 0x20)>>2)+(2*(data.prefixes&0x8)))][0]);
            }
            else
                strcat(data.opcptr, "nop");
            break;
        case 0x91:
        case 0x92:
        case 0x93:
        case 0x94:
        case 0x95:
        case 0x96:
        case 0x97:
            byte = *(unsigned char*)(((char*)data.adr)+data.length-1);
            strcat(data.opcptr, "xchg");
            strcat(data.opr2ptr, (char*)&r32map[((data.prefixes & 0x20)>>2)+(2*(data.prefixes&0x8))][0]);
            strcat(data.opr1ptr, (char*)&r32map[(byte&7)+(24*(data.prefixes&0x1)+((data.prefixes & 0x20)>>2)+(2*(data.prefixes&0x8)))][0]);
            break;
        case 0x98:
            strcat(data.opcptr, "cwde");
            break;
        case 0x99:
            strcat(data.opcptr, "cdq");
            break;
        case 0x9A:
            data.malformed = 1;
            return;
        case 0x9B:
            strcat(data.opcptr, "fwait");
            break;
        case 0x9C:
            if(data.prefixes&0x20)
                strcat(data.opcptr, "pushf");
            else
                strcat(data.opcptr, "pushfq");
            break;
        case 0x9D:
            if(data.prefixes&0x20)
                strcat(data.opcptr, "popf");
            else
                strcat(data.opcptr, "popfq");
            break;
        case 0x9E:
            strcat(data.opcptr, "sahf");
            break;
        case 0x9F:
            strcat(data.opcptr, "lahf");
            break;
        case 0xA0:
            strcat(data.opcptr, "mov");
            strcat(data.opr1ptr, "al");
            strcat(data.opr2ptr, "[");
            adr = ((char*)data.adr)+data.length;
            if(data.prefixes&0x40)
            {
                uint32_t buffer = *(uint32_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr2ptr, strbuf);
                strcat(data.opr2ptr, "]");
                data.length+=4;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            else
            {
                uint64_t buffer = *(uint64_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr2ptr, strbuf);
                strcat(data.opr2ptr, "]");
                data.length+=8;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            break;
        case 0xA1:
            strcat(data.opcptr, "mov");
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            strcat(data.opr2ptr, "[");
            adr = ((char*)data.adr)+data.length;
            if(data.prefixes&0x40)
            {
                uint32_t buffer = *(uint32_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr2ptr, strbuf);
                strcat(data.opr2ptr, "]");
                data.length+=4;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            else
            {
                uint64_t buffer = *(uint64_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr2ptr, strbuf);
                strcat(data.opr2ptr, "]");
                data.length+=8;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            break;
        case 0xA2:
            strcat(data.opcptr, "mov");
            strcat(data.opr2ptr, "al");
            strcat(data.opr1ptr, "[");
            adr = ((char*)data.adr)+data.length;
            if(data.prefixes&0x40)
            {
                uint32_t buffer = *(uint32_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr1ptr, strbuf);
                strcat(data.opr1ptr, "]");
                data.length+=4;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            else
            {
                uint64_t buffer = *(uint64_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr1ptr, strbuf);
                strcat(data.opr1ptr, "]");
                data.length+=8;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            break;
        case 0xA3:
            strcat(data.opcptr, "mov");
            if(data.prefixes&0x8)
                strcat(data.opr2ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr2ptr, "ax");
            else
                strcat(data.opr2ptr, "eax");
            strcat(data.opr1ptr, "[");
            adr = ((char*)data.adr)+data.length;
            if(data.prefixes&0x40)
            {
                uint32_t buffer = *(uint32_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr1ptr, strbuf);
                strcat(data.opr1ptr, "]");
                data.length+=4;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            else
            {
                uint64_t buffer = *(uint64_t*)adr;
                digits = getdigits(buffer);
                char* strbuf = new char[digits+1];
                ntohs(buffer, digits, strbuf);
                strcat(data.opr1ptr, strbuf);
                strcat(data.opr1ptr, "]");
                data.length+=8;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete strbuf;
            }
            break;
        case 0xA4:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            strcat(data.opcptr, "movsb");
            break;
        case 0xA5:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            if(data.prefixes&0x8)
                strcat(data.opcptr, "movsq");
            else if(data.prefixes&0x20)
                strcat(data.opcptr, "movsw");
            else
                strcat(data.opcptr, "movsd");
            break;
        case 0xA6:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            strcat(data.opcptr, "cmpsb");
            break;
        case 0xA7:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            if(data.prefixes&0x8)
                strcat(data.opcptr, "cmpsq");
            else if(data.prefixes&0x20)
                strcat(data.opcptr, "cmpsw");
            else
                strcat(data.opcptr, "cmpsd");
            break;
        case 0xA8:
            strcat(data.opcptr, "test");
            data.imm8 = data.opr2ptr;
            strcat(data.opr1ptr, "al");
            break;
        case 0xA9:
            strcat(data.opcptr, "test");
            data.imm32 = data.opr2ptr;
            if(data.prefixes&0x8)
                strcat(data.opr1ptr, "rax");
            else if(data.prefixes&0x20)
                strcat(data.opr1ptr, "ax");
            else
                strcat(data.opr1ptr, "eax");
            break;
        case 0xAA:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            strcat(data.opcptr, "stosb");
            break;
        case 0xAB:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            if(data.prefixes&0x8)
                strcat(data.opcptr, "stosq");
            else if(data.prefixes&0x20)
                strcat(data.opcptr, "stosw");
            else
                strcat(data.opcptr, "stosd");
            break;
        case 0xAC:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            strcat(data.opcptr, "lodsb");
            break;
        case 0xAD:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            if(data.prefixes&0x8)
                strcat(data.opcptr, "lodsq");
            else if(data.prefixes&0x20)
                strcat(data.opcptr, "lodsw");
            else
                strcat(data.opcptr, "lodsd");
            break;
        case 0xAE:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            strcat(data.opcptr, "scasb");
            break;
        case 0xAF:
            if(data.prefixes&0x8000)
                strcat(data.opcptr, "rep ");
            else if(data.prefixes&0x4000)
                strcat(data.opcptr, "repne ");
            if(data.prefixes&0x8)
                strcat(data.opcptr, "scasq");
            else if(data.prefixes&0x20)
                strcat(data.opcptr, "scasw");
            else
                strcat(data.opcptr, "scasd");
            break;
        case 0xB0:
        case 0xB1:
        case 0xB2:
        case 0xB3:
        case 0xB4:
        case 0xB5:
        case 0xB6:
        case 0xB7:
            strcat(data.opcptr, "mov");
            adr = ((char*)data.adr)+data.length-1;
            byte = *(unsigned char*)adr;
            if(data.prefixes & 0x1F)
                rex = 1;
            strcat(data.opr1ptr, (char*)&r8map[(byte&0x7)+(8*rex)+(2*(data.prefixes&0x4))][0]);
            data.imm8 = data.opr2ptr;
            break;
        case 0xB8:
        case 0xB9:
        case 0xBA:
        case 0xBB:
        case 0xBC:
        case 0xBD:
        case 0xBE:
        case 0xBF:
            strcat(data.opcptr, "mov");
            adr = ((char*)data.adr)+data.length-1;
            byte = *(unsigned char*)adr;
            if(data.prefixes & 0x1F)
                rex = 1;
            strcat(data.opr1ptr, (char*)&r32map[(byte&0x7)+(24*(data.prefixes&0x1))+(2*(data.prefixes&0x8))+((data.prefixes&0x20)>>2)][0]);
            if(data.prefixes&0x8)
            {
                uint64_t imm64 = *(uint64_t*)(((char*)data.adr)+data.length);
                digits = getdigits(imm64);
                char* tempstr = new char[digits+1];
                ntohs(imm64, digits, tempstr);
                strcat(data.opr2ptr, tempstr);
                data.length+=8;
                if(data.length > 15)
                {
                    data.malformed = 1;
                    return;
                }
                delete tempstr;
            }
            else
                data.imm32 = data.opr2ptr;
            break;
        case 0xC0:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "rol");
                    break;
                case 1:
                    strcat(data.opcptr, "ror");
                    return;
                case 2:
                    strcat(data.opcptr, "rcl");
                    break;
                case 3:
                    strcat(data.opcptr, "rcr");
                    break;
                case 4:
                    strcat(data.opcptr, "shl");
                    break;
                case 5:
                    strcat(data.opcptr, "shr");
                    break;
                case 6:
                    strcat(data.opcptr, "sal");
                    break;
                case 7:
                    strcat(data.opcptr, "sar");
                    break;
            }
            data.rm8 = data.opr1ptr;
            data.imm8 = data.opr2ptr;
            break;
        case 0xC1:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "rol");
                    break;
                case 1:
                    strcat(data.opcptr, "ror");
                    return;
                case 2:
                    strcat(data.opcptr, "rcl");
                    break;
                case 3:
                    strcat(data.opcptr, "rcr");
                    break;
                case 4:
                    strcat(data.opcptr, "shl");
                    break;
                case 5:
                    strcat(data.opcptr, "shr");
                    break;
                case 6:
                    strcat(data.opcptr, "sal");
                    break;
                case 7:
                    strcat(data.opcptr, "sar");
                    break;
            }
            data.rm32 = data.opr1ptr;
            data.imm8 = data.opr2ptr;
            break;
        case 0xC2:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "ret");
            data.imm32 = data.opr1ptr;
            data.prefixes = data.prefixes|0x20;
            data.prefixes = data.prefixes&0xFFF7;
            break;
        case 0xC3:
            if(data.prefixes&0x4000)
                strcat(data.opcptr, "bnd ");
            strcat(data.opcptr, "ret");
            break;
        case 0xC4:
            data.malformed = 1;
            return;
        case 0xC5:
            data.malformed = 1;
            return;
        case 0xC6:
            strcat(data.opcptr, "mov");
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.rm8 = data.opr1ptr;
            data.imm8 = data.opr2ptr;
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "mov");
                    break;
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    data.malformed = 1;
                    return;
            }
            break;
        case 0xC7:
            strcat(data.opcptr, "mov");
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.rm32 = data.opr1ptr;
            data.imm32 = data.opr2ptr;
            switch(byte)
            {
                case 0:
                    break;
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    data.malformed = 1;
                    return;
            }
            break;
        case 0xC8:
        {
            strcat(data.opcptr, "enter");
            uint16_t byte = *(uint16_t*)(((char*)data.adr)+data.length+1);
            digits = getdigits(byte);
            char* tempbuf = new char[digits+1];
            ntohs(byte, digits, tempbuf);
            strcat(data.opr1ptr, tempbuf);
            uint8_t byte2 = *(uint8_t*)(((char*)data.adr)+data.length+3);
            digits = getdigits(byte);
            char* tempbuf2 = new char[digits+1];
            ntohs(byte2, digits, tempbuf2);
            strcat(data.opr2ptr, tempbuf2);
            data.length+=3;
            if(data.length > 15)
            {
                data.malformed = 1;
                return;
            }
            delete tempbuf;
            delete tempbuf2;
            break;
        }
        case 0xC9:
            strcat(data.opcptr, "leave");
            break;
        case 0xCA:
            strcat(data.opcptr, "retf");
            data.prefixes = data.prefixes&0xFFF7;
            data.prefixes = data.prefixes|0x20;
            data.imm32 = data.opr1ptr;
            break;
        case 0xCB:
            strcat(data.opcptr, "retf");
            break;
        case 0xCC:
            strcat(data.opcptr, "int3");
            break;
        case 0xCD:
            strcat(data.opcptr, "int");
            data.imm8 = data.opr1ptr;
            break;
        case 0xCE:
            data.malformed = 1;
            return;
        case 0xCF:
            if(data.prefixes&0x8)
                strcat(data.opcptr, "iretq");
            else if(data.prefixes&0x20)
                strcat(data.opcptr, "iret");
            else
                strcat(data.opcptr, "iretd");
            break;
        case 0xD0: //here check
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.rm8 = data.opr1ptr;
            strcat(data.opr2ptr, "1");
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "rol");
                    break;
                case 1:
                    strcat(data.opcptr, "ror");
                    break;
                case 2:
                    strcat(data.opcptr, "rcl");
                    break;
                case 3:
                    strcat(data.opcptr, "rcr");
                    break;
                case 4:
                    strcat(data.opcptr, "shl");
                    break;
                case 5:
                    strcat(data.opcptr, "shr");
                    break;
                case 6:
                    strcat(data.opcptr, "sal");
                    break;
                case 7:
                    strcat(data.opcptr, "sar");
                    break;
            }
            break;
        case 0xD1:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.rm32 = data.opr1ptr;
            strcat(data.opr2ptr, "1");
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "rol");
                    break;
                case 1:
                    strcat(data.opcptr, "ror");
                    break;
                case 2:
                    strcat(data.opcptr, "rcl");
                    break;
                case 3:
                    strcat(data.opcptr, "rcr");
                    break;
                case 4:
                    strcat(data.opcptr, "shl");
                    break;
                case 5:
                    strcat(data.opcptr, "shr");
                    break;
                case 6:
                    strcat(data.opcptr, "sal");
                    break;
                case 7:
                    strcat(data.opcptr, "sar");
                    break;
            }
            break;
        case 0xD2:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.rm8 = data.opr1ptr;
            strcat(data.opr2ptr, "cl");
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "rol");
                    break;
                case 1:
                    strcat(data.opcptr, "ror");
                    break;
                case 2:
                    strcat(data.opcptr, "rcl");
                    break;
                case 3:
                    strcat(data.opcptr, "rcr");
                    break;
                case 4:
                    strcat(data.opcptr, "shl");
                    break;
                case 5:
                    strcat(data.opcptr, "shr");
                    break;
                case 6:
                    strcat(data.opcptr, "sal");
                    break;
                case 7:
                    strcat(data.opcptr, "sar");
                    break;
            }
            break;
        case 0xD3:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.rm32 = data.opr1ptr;
            strcat(data.opr2ptr, "cl");
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "rol");
                    break;
                case 1:
                    strcat(data.opcptr, "ror");
                    break;
                case 2:
                    strcat(data.opcptr, "rcl");
                    break;
                case 3:
                    strcat(data.opcptr, "rcr");
                    break;
                case 4:
                    strcat(data.opcptr, "shl");
                    break;
                case 5:
                    strcat(data.opcptr, "shr");
                    break;
                case 6:
                    strcat(data.opcptr, "sal");
                    break;
                case 7:
                    strcat(data.opcptr, "sar");
                    break;
            }
            break;
        case 0xD4:
        case 0xD5:
        case 0xD6:
            data.malformed = 1;
            return;
        case 0xD7:
            strcat(data.opcptr, "xlat");
            break;
        case 0xD8:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            data.st = 1;
            data.rm32 = data.opr2ptr;
            strcat(data.opr1ptr, "st(0)");
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "fadd");
                    break;
                case 1:
                    strcat(data.opcptr, "fmul");
                    break;
                case 2:
                    strcat(data.opcptr, "fcom");
                    break;
                case 3:
                    strcat(data.opcptr, "fcomp");
                    break;
                case 4:
                    strcat(data.opcptr, "fsub");
                    break;
                case 5:
                    strcat(data.opcptr, "fsubr");
                    break;
                case 6:
                    strcat(data.opcptr, "fdiv");
                    break;
                case 7:
                    strcat(data.opcptr, "fdivr");
                    break;
            }
            break;
        case 0xD9:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte3 = ((byte&0x38)>>3);
            data.st = 1;
            switch(byte3)
            {
                case 0:
                    strcat(data.opr1ptr, "st(0)");
                    data.rm32 = data.opr2ptr;
                    strcat(data.opcptr, "fld");
                    break;
                case 1:
                    if(byte < 0xc0)
                    {
                        data.malformed = 1;
                        return;
                    }
                    strcat(data.opr1ptr, "st(0)");
                    data.rm8 = data.opr2ptr;
                    strcat(data.opcptr, "fxch");
                    break;
                case 2:
                    if(byte > 0xc0)
                    {
                        if(byte == 0xd0)
                        {
                            strcat(data.opcptr, "fnop");
                            data.length++;
                            break;
                        }
                        else
                        {
                            data.malformed = 1;
                            return;
                        }
                    }
                    else
                    {
                        strcat(data.opcptr, "fst");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr2ptr, "st(0)");
                    }
                    break;
                case 3:
                    if(byte < 0xc0)
                        strcat(data.opcptr, "fstp");
                    else
                        strcat(data.opcptr, "fstpnce");
                    data.rm8 = data.opr1ptr;
                    strcat(data.opr2ptr, "st(0)");
                    break;
                case 4:
                    if(byte < 0xc0)
                    {
                        data.rm8 = data.opr1ptr;
                        strcat(data.opcptr, "fldenv");
                    }
                    else
                    {
                        data.length++;
                        switch(byte)
                        {
                            case 0xE0:
                                strcat(data.opcptr, "fchs");
                                break;
                            case 0xE1:
                                strcat(data.opcptr, "fabs");
                                break;
                            case 0xE4:
                                strcat(data.opcptr, "ftst");
                                break;
                            case 0xE5:
                                strcat(data.opcptr, "fxam");
                                break;
                            default:
                                data.malformed = 1;
                                return;
                        }
                    }
                    break;
                case 5:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fldcw");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        data.length++;
                        switch(byte)
                        {
                            case 0xE8:
                                strcat(data.opcptr, "fld1");
                                break;
                            case 0xE9:
                                strcat(data.opcptr, "fldl2t");
                                break;
                            case 0xEA:
                                strcat(data.opcptr, "fldl2e");
                                break;
                            case 0xEB:
                                strcat(data.opcptr, "fldpi");
                                break;
                            case 0xEC:
                                strcat(data.opcptr, "fldlg2");
                                break;
                            case 0xED:
                                strcat(data.opcptr, "fldln2");
                                break;
                            case 0xEE:
                                strcat(data.opcptr, "fldz");
                                break;
                            case 0xEF:
                                data.malformed = 1;
                                return;
                        }
                    }
                    break;
                case 6:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fnstenv");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        data.length++;
                        switch(byte)
                        {
                            case 0xF0:
                                strcat(data.opcptr, "f2xm1");
                                break;
                            case 0xF1:
                                strcat(data.opcptr, "fyl2x");
                                break;
                            case 0xF2:
                                strcat(data.opcptr, "fptan");
                                break;
                            case 0xF3:
                                strcat(data.opcptr, "fpatan");
                                break;
                            case 0xF4:
                                strcat(data.opcptr, "fxtract");
                                break;
                            case 0xF5:
                                strcat(data.opcptr, "fprem1");
                                break;
                            case 0xF6:
                                strcat(data.opcptr, "fdecstp");
                                break;
                            case 0xF7:
                                strcat(data.opcptr, "fincstp");
                                break;
                        }
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fnstcw");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        data.length++;
                        switch(byte)
                        {
                            case 0xF8:
                                strcat(data.opcptr, "fprem");
                                break;
                            case 0xF9:
                                strcat(data.opcptr, "fyl2xp1");
                                break;
                            case 0xFA:
                                strcat(data.opcptr, "fsqrt");
                                break;
                            case 0xFB:
                                strcat(data.opcptr, "fsincos");
                                break;
                            case 0xFC:
                                strcat(data.opcptr, "frndint");
                                break;
                            case 0xFD:
                                strcat(data.opcptr, "fscale");
                                break;
                            case 0xFE:
                                strcat(data.opcptr, "fsin");
                                break;
                            case 0xFF:
                                strcat(data.opcptr, "fcos");
                                break;
                        }
                    }
                    break;
            }
            break;
        }
        case 0xDA:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte4 = ((byte&0x38)>>3);
            data.st = 1;
            strcat(data.opr1ptr, "st(0)");
            switch(byte4)
            {
                case 0:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fiadd");
                        data.prefixes = data.prefixes&0xFFC0;
                        data.rm32 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmovb");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 1:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fimul");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "dword ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmove");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 2:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "ficom");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmovbe");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 3:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "ficmop");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmovu");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 4:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisub");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
                case 5:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisubr");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        if(byte == 0xE9)
                        {
                            strcat(data.opcptr, "fucompp");
                            data.rm8 = data.opr2ptr;
                        }
                        else
                        {
                            data.malformed = 1;
                            return;
                        }
                    }
                    break;
                case 6:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fidiv");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fidivr");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
            }
            break;
        }
        case 0xDB:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte5 = ((byte&0x38)>>3);
            data.st = 1;
            switch(byte5)
            {
                case 0:
                    strcat(data.opr1ptr, "st(0)");
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fild");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmovnb");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 1:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisttp");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr2ptr, "st(0)");
                    }
                    else
                    {
                        strcat(data.opr1ptr, "st(0)");
                        strcat(data.opcptr, "fcmovne");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 2:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fist");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr2ptr, "st(0)");
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmovnbe");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 3:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fistp");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr2ptr, "st(0)");
                    }
                    else
                    {
                        strcat(data.opcptr, "fcmovnu");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 4:
                    data.length++;
                    switch(byte)
                    {
                        case 0xE0:
                            strcat(data.opcptr, "fneni8087_nop");
                            break;
                        case 0xE1:
                            strcat(data.opcptr, "fdisi8087_nop");
                            break;
                        case 0xE2:
                            strcat(data.opcptr, "fnclex");
                            break;
                        case 0xE3:
                            strcat(data.opcptr, "fninit");
                            break;
                        case 0xE4:
                            strcat(data.opcptr, "fsetpm287_nop");
                            break;
                        default:
                            data.malformed = 1;
                            return;
                    }
                    break;
                case 5:
                    strcat(data.opr1ptr, "st(0)");
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fld");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fucomi");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 6:
                    if(byte > 0xbf)
                    {
                        strcat(data.opr1ptr, "st(0)");
                        strcat(data.opcptr, "fcomi");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opr2ptr, "st(0)");
                        strcat(data.opcptr, "fidivr");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
            }
            break;
        }
        case 0xDC:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte6 = ((byte&0x38)>>3);
            data.st = 1;
            switch(byte6)
            {
                case 0:
                    strcat(data.opcptr, "fadd");
                    if(byte < 0xc0)
                    {
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 1:
                    strcat(data.opcptr, "fmul");
                    if(byte < 0xc0)
                    {
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 2:
                    strcat(data.opcptr, "fcom");
                    strcat(data.opr1ptr, "st(0)");
                    data.rm8 = data.opr2ptr;
                    break;
                case 3:
                    strcat(data.opcptr, "fcomp");
                    strcat(data.opr1ptr, "st(0)");
                    data.rm8 = data.opr2ptr;
                    break;
                case 4:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fsub");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fsubr");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 5:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fsubr");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fsub");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 6:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fdiv");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fdivr");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fdivr");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fdiv");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
            }
            break;
        }
        case 0xDD:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte7 = ((byte&0x38)>>3);
            data.st = 1;
            switch(byte7)
            {
                case 0:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fld");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr1ptr, "st(0)");
                    }
                    else
                    {
                        strcat(data.opcptr, "ffree");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 1:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisttp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fxch");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 2:
                    strcat(data.opcptr, "fst");
                    data.rm8 = data.opr1ptr;
                    strcat(data.opr2ptr, "st(0)");
                    break;
                case 3:
                    strcat(data.opcptr, "fstp");
                    data.rm8 = data.opr1ptr;
                    strcat(data.opr2ptr, "st(0)");
                    break;
                case 4:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "frstor");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fucom");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 5:
                    if(byte < 0xc0)
                    {
                        data.malformed = 1;
                        return;
                    }
                    else
                    {
                        strcat(data.opcptr, "fucomp");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 6:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fnsave");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fnstsw");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
            }
            break;
        }
        case 0xDE:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte8 = ((byte&0x38)>>3);
            data.st = 1;
            switch(byte8)
            {
                case 0:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fiadd");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr1ptr, "st(0)");
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "faddp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 1:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fimul");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fmulp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 2:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "ficom");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fcomp");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 3:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "ficomp");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        if(byte == 0xD9)
                        {
                            strcat(data.opcptr, "fcompp");
                            data.length++;
                        }
                        else
                        {
                            data.malformed = 1;
                            return;
                        }
                    }
                    break;
                case 4:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisub");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fsubrp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr1ptr, "word ");
                    }
                    break;
                case 5:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisubr");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fsubp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 6:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fidiv");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fdivrp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fidivr");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fdivp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
            }
            break;
        }
        case 0xDF:
        {
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte9 = ((byte&0x38)>>3);
            data.st = 1;
            switch(byte9)
            {
                case 0:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fild");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "ffreep");
                        data.rm8 = data.opr1ptr;
                    }
                    break;
                case 1:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fisttp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr1ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opcptr, "fxch");
                    }
                    break;
                case 2:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fist");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr1ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fstp");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr2ptr, "st(0)");
                    }
                    break;
                case 3:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fistp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr1ptr, "word ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fstp");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr2ptr, "st(0)");
                    }
                    break;
                case 4:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fbld");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr1ptr, "st(0)");
                    }
                    else
                    {
                        if(byte == 0xE0)
                        {
                            data.length++;
                            strcat(data.opcptr, "fnstsw ax");
                        }
                        else
                        {
                            data.malformed = 1;
                            return;
                        }
                    }
                    break;
                case 5:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fild");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                        strcat(data.opr2ptr, "qword ");
                    }
                    else
                    {
                        strcat(data.opcptr, "fucomip");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 6:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fbstp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                    }
                    else
                    {
                        strcat(data.opcptr, "fbstp");
                        strcat(data.opr1ptr, "st(0)");
                        data.rm8 = data.opr2ptr;
                    }
                    break;
                case 7:
                    if(byte < 0xc0)
                    {
                        strcat(data.opcptr, "fistp");
                        strcat(data.opr2ptr, "st(0)");
                        data.rm8 = data.opr1ptr;
                        strcat(data.opr1ptr, "qword ");
                    }
                    else
                    {
                        data.malformed = 1;
                        return;
                    }
                    break;
            }
            break;
        }
        case 0xE0:
            strcat(data.opcptr, "loopne");
            data.rel8 = data.opr1ptr;
            break;
        case 0xE1:
            strcat(data.opcptr, "loope");
            data.rel8 = data.opr1ptr;
            break;
        case 0xE2:
            strcat(data.opcptr, "loop");
            data.rel8 = data.opr1ptr;
            break;
        case 0xE3:
            strcat(data.opcptr, "jecxz");
            data.rel8 = data.opr1ptr;
            break;
        case 0xE4:
            strcat(data.opcptr, "in");
            strcat(data.opr1ptr, "al");
            data.imm8 = data.opr2ptr;
            break;
        case 0xE5:
            strcat(data.opcptr, "in");
            strcat(data.opr1ptr, "eax");
            data.imm8 = data.opr2ptr;
            break;
        case 0xE6:
            strcat(data.opcptr, "out");
            strcat(data.opr2ptr, "al");
            data.imm8 = data.opr1ptr;
            break;
        case 0xE7:
            strcat(data.opcptr, "out");
            strcat(data.opr2ptr, "eax");
            data.imm8 = data.opr1ptr;
            break;
        case 0xE8:
            strcat(data.opcptr, "call");
            data.rel32 = data.opr1ptr;
            break;
        case 0xE9:
            strcat(data.opcptr, "jmp");
            data.rel32 = data.opr1ptr;
            break;
        case 0xEA:
            data.malformed = 1;
            return;
        case 0xEB:
            strcat(data.opcptr, "jmp");
            data.rel8 = data.opr1ptr;
            break;
        case 0xEC:
            strcat(data.opcptr, "in");
            strcat(data.opr1ptr, "al");
            strcat(data.opr2ptr, "dx");
            break;
        case 0xED:
            strcat(data.opcptr, "in");
            strcat(data.opr1ptr, "eax");
            strcat(data.opr2ptr, "dx");
            break;
        case 0xEE:
            strcat(data.opcptr, "out");
            strcat(data.opr1ptr, "dx");
            strcat(data.opr2ptr, "al");
            break;
        case 0xEF:
            strcat(data.opcptr, "out");
            strcat(data.opr1ptr, "dx");
            strcat(data.opr2ptr, "eax");
            break;
        case 0xF0:
            data.prefixes = (data.prefixes&0xFFE0);
            data.prefixes = (data.prefixes|0x2000);
            data.length++;
            parseins(data);
            break;
        case 0xF1:
            strcat(data.opcptr, "int1");
            break;
        case 0xF2:
            data.prefixes = (data.prefixes&0x7FE0);
            data.prefixes = (data.prefixes|0x4000);
            data.length++;
            parseins(data);
            break;
        case 0xF3:
            data.prefixes = (data.prefixes&0xBFE0);
            data.prefixes = (data.prefixes|0x8000);
            data.length++;
            parseins(data);
            break;
        case 0xF4:
            strcat(data.opcptr, "hlt");
            break;
        case 0xF5:
            strcat(data.opcptr, "cmc");
            break;
        case 0xF6:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                case 1:
                    strcat(data.opcptr, "test");
                    data.rm8 = data.opr1ptr;
                    data.imm8 = data.opr2ptr;
                    break;
                case 2:
                    strcat(data.opcptr, "not");
                    data.rm8 = data.opr1ptr;
                    break;
                case 3:
                    strcat(data.opcptr, "neg");
                    data.rm8 = data.opr1ptr;
                    break;
                case 4:
                    strcat(data.opcptr, "mul");
                    strcat (data.opr1ptr, "ax");
                    strcat (data.opr2ptr, "al");
                    data.rm8 = data.opr3ptr;
                    break;
                case 5:
                    strcat(data.opcptr, "imul");
                    strcat (data.opr1ptr, "ax");
                    strcat (data.opr2ptr, "al");
                    data.rm8 = data.opr3ptr;
                    break;
                case 6:
                    strcat(data.opcptr, "div");
                    strcat(data.opr1ptr, "al");
                    strcat (data.opr2ptr, "ah");
                    strcat (data.opr3ptr, "ax");
                    data.rm8 = data.opr4ptr;
                    break;
                case 7:
                    strcat(data.opcptr, "idiv");
                    strcat(data.opr1ptr, "al");
                    strcat (data.opr2ptr, "ah");
                    strcat (data.opr3ptr, "ax");
                    data.rm8 = data.opr4ptr;
                    break;
            }
            break;
        case 0xF7:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                case 1:
                    strcat(data.opcptr, "test");
                    data.rm32 = data.opr1ptr;
                    data.imm32 = data.opr2ptr;
                    break;
                case 2:
                    strcat(data.opcptr, "not");
                    data.rm32 = data.opr1ptr;
                    break;
                case 3:
                    strcat(data.opcptr, "neg");
                    data.rm32 = data.opr1ptr;
                    break;
                case 4:
                    strcat(data.opcptr, "mul");
                    strcat (data.opr1ptr, "rdx");
                    strcat (data.opr2ptr, "rax");
                    data.rm32 = data.opr3ptr;
                    break;
                case 5:
                    strcat(data.opcptr, "imul");
                    strcat (data.opr1ptr, "rdx");
                    strcat (data.opr2ptr, "rax");
                    data.rm32 = data.opr3ptr;
                    break;
                case 6:
                    strcat(data.opcptr, "div");
                    strcat(data.opr1ptr, "rdx");
                    strcat (data.opr2ptr, "rax");
                    data.rm32 = data.opr3ptr;
                    break;
                case 7:
                    strcat(data.opcptr, "idiv");
                    strcat(data.opr1ptr, "rdx");
                    strcat (data.opr2ptr, "rax");
                    data.rm32 = data.opr3ptr;
                    break;
            }
            break;
        case 0xF8:
            strcat(data.opcptr, "clc");
            break;
        case 0xF9:
            strcat(data.opcptr, "stc");
            break;
        case 0xFA:
            strcat(data.opcptr, "cli");
            break;
        case 0xFB:
            strcat(data.opcptr, "sti");
            break;
        case 0xFC:
            strcat(data.opcptr, "cld");
            break;
        case 0xFD:
            strcat(data.opcptr, "std");
            break;
        case 0xFE:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            byte = ((byte&0x38)>>3);
            switch(byte)
            {
                case 0:
                    strcat(data.opcptr, "inc");
                    data.rm8 = data.opr1ptr;
                    break;
                case 1:
                    strcat(data.opcptr, "dec");
                    data.rm8 = data.opr1ptr;
                    break;
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    data.malformed = 1;
                    return;
            }
            break;
        case 0xFF:
            byte = *(unsigned char*)(((char*)data.adr)+data.length);
            unsigned char byte2 = ((byte&0x38)>>3);
            switch((byte&0x38)>>3)
            {
                case 0:
                    strcat(data.opcptr, "inc");
                    data.rm32 = data.opr1ptr;
                    break;
                case 1:
                    strcat(data.opcptr, "dec");
                    data.rm32 = data.opr1ptr;
                    break;
                case 2:
                    data.prefixes = (data.prefixes&0xFFDF);
                    data.prefixes = (data.prefixes|0x8);
                    strcat(data.opcptr, "call");
                    data.rm32 = data.opr1ptr;
                    break;
                case 3:
                    if(byte > 0xc0)
                    {
                        data.malformed = 1;
                        return;
                    }
                    data.prefixes = (data.prefixes&0xFFDF);
                    data.prefixes = (data.prefixes|0x8);
                    strcat(data.opcptr, "callf");
                    data.rm32 = data.opr1ptr;
                    break;
                case 4:
                    data.prefixes = (data.prefixes&0xFFDF);
                    data.prefixes = (data.prefixes|0x8);
                    strcat(data.opcptr, "jmp");
                    data.rm32 = data.opr1ptr;
                    break;
                case 5:
                    if(byte > 0xc0)
                    {
                        data.malformed = 1;
                        return;
                    }
                    data.prefixes = (data.prefixes&0xFFDF);
                    data.prefixes = (data.prefixes|0x8);
                    strcat(data.opcptr, "jmpf");
                    data.rm32 = data.opr1ptr;
                    break;
                case 6:
                    if(!(data.prefixes&0x20))
                    {
                        data.prefixes = (data.prefixes|0x8);
                    }
                    strcat(data.opcptr, "push");
                    data.rm32 = data.opr1ptr;
                    break;
                case 7:
                    data.malformed = 1;
                    return;
            }
            break;
    }
    if(data.parsed == 0)
    {
        parsedata(data);
    }
    return;
}

INSTRUCTION disassemble(void* insadr)
{
    INSTRUCTIONDATA ins;
    ins.adr = insadr;
    parseins(ins);
    INSTRUCTION ins2;
    ins2.adr = insadr;
    if(ins.malformed == 1)
    {
        ins2.length = 1;
        memset(ins2.disasmstr, 0, sizeof(ins2.disasmstr));
        ins2.disasmstr[0] = 0x3F;
        ins2.disasmstr[1] = 0x3F;
        ins2.disasmstr[2] = 0x3F;
        ins2.byteseq[0] = *(unsigned char*)insadr;
        goto enddisassemble;
    }
    ins2.length = ins.length;
    for(int i = 0;i<ins2.length;i++)
    {
        ins2.byteseq[i] = *(unsigned char*)(((char*)insadr)+i);
    }
    strcat(ins2.disasmstr, ins.opc);
    if(ins.opr1val[0] != 0)
    {
        strcat(ins2.disasmstr, " ");
        strcat(ins2.disasmstr, ins.opr1val);
    }
    if(ins.opr2val[0] != 0)
    {
        strcat(ins2.disasmstr, ", ");
        strcat(ins2.disasmstr, ins.opr2val);
    }
    if(ins.opr3val[0] != 0)
    {
        strcat(ins2.disasmstr, ", ");
        strcat(ins2.disasmstr, ins.opr3val);
    }
    if(ins.opr4val[0] != 0)
    {
        strcat(ins2.disasmstr, ", ");
        strcat(ins2.disasmstr, ins.opr4val);
    }
    enddisassemble:
    return ins2;
}

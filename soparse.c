#include <stdio.h>
#include "dataType.h"

struct DataOffest{
    Elf32_Off programheadoffset;
    Elf32_Half programsize;
    Elf32_Off sectionheadoffest;
    Elf32_Half sectionsize;
    Elf32_Off dynameicoff;
    Elf32_Word dynameicsize;
    Elf32_Off stroffset;
    Elf32_Word strsize;
    Elf32_Off str1offset;
    Elf32_Word str1size;
    Elf32_Off str2offset;
    Elf32_Word str2size;
    Elf32_Half shstrtabindex;
    Elf32_Off symtaboff;
    Elf32_Word symtabsize;
};

struct ShstrtabTable
{
  int index;
  char str[50];
};

struct DataOffest parseSoHeader(FILE *fp,struct DataOffest off)
{
    Elf32_Ehdr header;
    int i = 0;

    fseek(fp,0,SEEK_SET);
    fread(&header,1,sizeof(header),fp);
    printf("ELF Header:\n");
    printf("    Header Magic: ");
    for (i = 0; i < 16; i++)
    {
        printf("%02x ",header.e_ident[i]);
    }
    printf("\n");
    printf("    So File Type: 0x%02x",header.e_type);
    switch (header.e_type)
    {
    case 0x00:
        printf("(No file type)\n");
        break;
    case 0x01:
        printf("(Relocatable file)\n");
        break;
    case 0x02:
        printf("(Executable file)\n");
        break;
    case 0x03:
        printf("(Shared object file)\n");
        break;
    case 0x04:
        printf("(Core file)\n");
        break;
    case 0xff00:
        printf("(Beginning of processor-specific codes)\n");
        break;
    case 0xffff:
        printf("(Processor-specific)\n");
        break;
    default:
        printf("\n");
        break;
    }
    printf("    Required Architecture: 0x%04x",header.e_machine);
    if (header.e_machine == 0x28)
    {
        printf("(ARM)\n");
    }
    else
    {
        printf("\n");
    }
    printf("    Version: 0x%02x\n",header.e_version);
    printf("    Start Program Address: 0x%08x\n",header.e_entry);
    printf("    Program Header Offest: 0x%08x\n",header.e_phoff);
    off.programheadoffset = header.e_phoff;
    printf("    Section Header Offest: 0x%08x\n",header.e_shoff);
    off.sectionheadoffest = header.e_shoff;
    printf("    Processor-specific Flags: 0x%08x\n",header.e_flags);
    printf("    ELF Header Size: 0x%04x\n",header.e_ehsize);
    printf("    Size of an entry in the program header table: 0x%04x\n",header.e_phentsize);
    printf("    Program Header Size: 0x%04x\n",header.e_phnum);
    off.programsize = header.e_phnum;
    printf("    Size of an entry in the section header table: 0x%04x\n",header.e_shentsize);
    printf("    Section Header Size: 0x%04x\n",header.e_shnum);
    off.sectionsize = header.e_shnum;
    printf("    String Section Index: 0x%04x\n",header.e_shstrndx);
    off.shstrtabindex = header.e_shstrndx;
    return off;
}

struct ShstrtabTable* getShstrtabTable(FILE *fp,struct DataOffest off,struct ShstrtabTable str[100])
{
    Elf32_Half init;
    Elf32_Half addr;
    Elf32_Shdr sectionHeader;
    Elf32_Off stroff;
    Elf32_Half stringoff;
    Elf32_Word count;
    int i,k=0,n,m,v;
    char ch;
    
    m = 0;
    v = off.shstrtabindex;
    init = off.sectionheadoffest;
    for (i = 0; i < off.sectionsize; i++)
    {
        addr = init + (i * 0x28);
        if (i == v)
        {
            fseek(fp,addr,SEEK_SET);
            fread(&sectionHeader,1,40,fp);
            stroff = sectionHeader.sh_offset;
            count = sectionHeader.sh_size;
            str[0].index = 0;
            for (n = 0; n < count; n++)
            {
                stringoff = stroff + (n * 1);

                fseek(fp,stringoff,SEEK_SET);
                fread(&ch,1,1,fp);

                if (n == 0 && ch == 0)
                {
                    continue;
                }
                else if (ch != 0)
                {
                    str[k].str[m] = ch;
                    m++;
                }
                else if (ch == 0 && n !=0)
                {
                    k = k + 1;
                    m = 0;
                    str[k].index = k;
                }
            }
            
        }
        
    }
    return str;
}

struct DataOffest parseSoPargramHeader(FILE *fp,struct DataOffest off)
{
    Elf32_Half init;
    Elf32_Half addr;
    int i;
    Elf32_Phdr programHeader;
    
    init = off.programheadoffset;
    for (i = 0; i < off.programsize; i++)
    {
        addr = init + (i * 0x20);
        fseek(fp,addr,SEEK_SET);
        fread(&programHeader,1,32,fp);
        switch (programHeader.p_type)
        {
        case 2:
            off.dynameicoff = programHeader.p_offset;
            off.dynameicsize = programHeader.p_filesz;
            break;
        default:
            break;
        }
        printf("\n\nSegment Header %d:\n",(i + 1));
        printf("    Type of segment: 0x%08x\n",programHeader.p_type);
        printf("    Segment Offset: 0x%08x\n",programHeader.p_offset);
        printf("    Virtual address of beginning of segment: 0x%08x\n",programHeader.p_vaddr);
        printf("    Physical address of beginning of segment: 0x%08x\n",programHeader.p_paddr);
        printf("    Num. of bytes in file image of segment: 0x%08x\n",programHeader.p_filesz);
        printf("    Num. of bytes in mem image of segment (may be zero): 0x%08x\n",programHeader.p_memsz);
        printf("    Segment flags: 0x%08x\n",programHeader.p_flags);
        printf("    Segment alignment constraint: 0x%08x\n",programHeader.p_align);
    }
    return off;
}

struct DataOffest parseSoSectionHeader(FILE *fp,struct DataOffest off,struct ShstrtabTable StrList[100])
{
    Elf32_Half init;
    Elf32_Half addr;
    Elf32_Shdr sectionHeader;
    int i,id,n;
    char ch;
    int k = 0;

    init = off.sectionheadoffest;
    for (i = 0; i < off.sectionsize; i++)
    {
        addr = init + (i * 0x28);
        fseek(fp,addr,SEEK_SET);
        fread(&sectionHeader,1,40,fp); 
        switch (sectionHeader.sh_type)
        {
        case 3:
            if(k == 0)
            {
                off.stroffset = sectionHeader.sh_offset;
                off.strsize = sectionHeader.sh_size;
                k++;
            }
            else if (k == 1)
            {
                off.str1offset = sectionHeader.sh_offset;
                off.str1size = sectionHeader.sh_size;
                k++;
            }
            else
            {
                off.str2offset = sectionHeader.sh_offset;
                off.str2size = sectionHeader.sh_size;
                k++;
            }
            break;
        default:
            break;
        }
        id = sectionHeader.sh_name;
        printf("\n\nSection Header %d\n",(i + 1));
        printf("    Section Name Index: 0x%x\n",id);
        /*for (n = 0; n < 50; n++)
        {
            ch = StrList[id].str[n];
            if (ch == 0)
            {
                printf("\n");
                break;
            }
            else
            {
                printf("%c",ch);
            }
        }*/
        printf("    Section Type: 0x%08x\n",sectionHeader.sh_type);
        printf("    Section Flag: 0x%08x\n",sectionHeader.sh_flags);
        printf("    Address where section is to be loaded: 0x%08x\n",sectionHeader.sh_addr);
        printf("    Offset: 0x%x\n",sectionHeader.sh_offset);
        printf("    Size of section, in bytes: 0x%08x\n",sectionHeader.sh_size);
        printf("    Section type-specific header table index link: 0x%08x\n",sectionHeader.sh_link);
        printf("    Section type-specific extra information: 0x%08x\n",sectionHeader.sh_info);
        printf("    Section address alignment: 0x%08x\n",sectionHeader.sh_addralign);
        printf("    Size of records contained within the section: 0x%08x\n",sectionHeader.sh_entsize);
    }
    return off;
}

void parseStrSection(FILE *fp,struct DataOffest off,int flag)
{
    int total = 0;
    int i;
    int ch;
    int mark;
    Elf32_Off init;
    Elf32_Off addr;
    Elf32_Word count;

    mark = 1;


    if (flag == 1)
    {
        count = off.strsize;
        init = off.stroffset;
    }
    else if (flag == 2)
    {
        count = off.str1size;
        init = off.str1offset;
    }
    else
    {
        count = off.str2size;
        init = off.str2offset;
    }
    
    
    printf("String Address==>0x%x\n",init);
    printf("String List %d:\n\t[1]==>",flag);

    for (i = 0; i < count; i++)
    {

        addr = init + (i * 1);

        fseek(fp,addr,SEEK_SET);
        fread(&ch,1,1,fp);

        if (i == 0 && ch == 0)
        {
            continue;
        }
        else if (ch != 0)
        {
            printf("%c",ch);
        }
        else if (ch == 0 && i !=0)
        {
            printf("\n\t[%d]==>",(++mark));
        }
    }
    printf("\n");
    
}

void parseSoDynamicSection(FILE *fp,struct DataOffest off)
{
    int dynamicnum;
    Elf32_Off init;
    Elf32_Off addr;
    Elf32_Dyn dynamicData;
    int i;

    init = off.dynameicoff;
    dynamicnum = (off.dynameicsize / 8);

    printf("Dynamic:\n");
    printf("\t\tTag\t\t\tType\t\t\tName/Value\n");

    for (i = 0; i < dynamicnum; i++)
    {
        addr = init + (i * 8);
        fseek(fp,addr,SEEK_SET);
        fread(&dynamicData,1,8,fp);
        printf("\t\t0x%08x\t\tNOPRINTF\t\t0x%x\n",dynamicData.d_tag,dynamicData.d_un);
    }
    
}

void parseSymtabSection(FILE *fp,struct DataOffest off)
{
    Elf32_Off init;
    Elf32_Off addr;
    Elf32_Word count;
    Elf32_Sym symtabSection;
    int k,i;

    init = off.symtaboff;
    count = off.symtabsize;

    printf("SymTable:\n");

    for (i = 0; i < count; i++)
    {
        addr = init + (i * 16);
        fseek(fp,addr,SEEK_SET);
        fread(&symtabSection,1,16,fp);
        printf("Symbol Name Index: 0x%x\n",symtabSection.st_name);
        printf("Value or address associated with the symbol: 0x%08x\n",symtabSection.st_value);
        printf("Size of the symbol: 0x%x\n",symtabSection.st_size);
        printf("Symbol's type and binding attributes: %c\n",symtabSection.st_info);
        printf("Must be zero; reserved: 0x%x\n",symtabSection.st_other);
        printf("Which section (header table index) it's defined in: 0x%x\n",symtabSection.st_shndx);
    }
    
}


int main()
{
    FILE *fp;
    char buffer[4];
    int i = 0;
    Elf64_Addr buff[1];
    struct DataOffest test = {0};
    struct DataOffest off = {0};
    struct ShstrtabTable StrList[100];
    struct ShstrtabTable *p;

    for (i = 0; i < 100; i++)
    {
        StrList[i].index = -1;
    }
    p = StrList;
    fp = fopen("E:\\blog\\soParse\\libfridaso.so","rb");
    off = parseSoHeader(fp,off);
    p = getShstrtabTable(fp,off,StrList);

    printf("\n\nshstrtab Table:\n");
    for (i = 0; i < 100; i++)
    {
        if (p->index == -1)
        {
            break;
        }
        else
        {
            printf("    [%d]==>%s\n",p->index,p->str);
        }
        p++;
    }
    
    off = parseSoPargramHeader(fp,off);
    off = parseSoSectionHeader(fp,off,StrList);
    parseSoDynamicSection(fp,off);
    parseStrSection(fp,off,1);
    parseStrSection(fp,off,2);
    parseStrSection(fp,off,3);
    /*parseSymtabSection(fp,off);*/
    fclose(fp);
    return 0;
}

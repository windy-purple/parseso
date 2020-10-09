/*
 * @Author: windy_ll
 * @Date: 2020-10-02 22:22:50
 * @LastEditors: windy_ll
 * @LastEditTime: 2020-10-09 19:13:48
 * @Description: file content
 */
#include <stdint.h>
#include <string.h>

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

typedef struct{
  unsigned char e_ident[16];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
}Elf32_Ehdr;

enum {
  ET_NONE   = 0,
  ET_REL    = 1,
  ET_EXEC   = 2,
  ET_DYN    = 3,
  ET_CORE   = 4,
  ET_LOPROC = 0xff00,
  ET_HIPROC = 0xffff
};

typedef struct{
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
}Elf32_Phdr;

typedef struct{
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off  sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
}Elf32_Shdr;

typedef struct
{
  Elf32_Sword d_tag;
  union
  {
      Elf32_Word d_val;
      Elf32_Addr d_ptr;
  } d_un;
}Elf32_Dyn;

typedef struct{
  Elf32_Word    st_name;
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half    st_shndx;
}Elf32_Sym;

using System;
using System.IO;
using System.Runtime.InteropServices;

// The objective is to port this to C
// It's written in a C-like style
namespace Nm
{
    class Program
    {
        static int int32reverse(int inp) {
            int b1 = (inp >> 24) & 0xff;
            int b2 = (inp >> 16) & 0xff;
            int b3 = (inp >> 8) & 0xff;
            int b4 = inp & 0xff;
            return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
        }
        
        static int elfMagic = int32reverse(0x7f454c46);
        static int SHT_SYMTAB = 2;
        static int SHT_STRTAB = 3;

        static int STT_OBJECT = 1;
        static int STT_FUNC = 2;
        static int STT_SECTION = 3;

        // Thanks: https://wiki.osdev.org/ELF
        struct Elf32Header {
            public int magic;
            public byte size;
            public byte endian;
            public byte version;
            public byte abi;
            public int padding1;
            public int padding2;
            public ushort type;
            public ushort iset;
            public int elfVersion;
            public int entryPoint;
            public int programHeaderTablePosition;
            public int sectionHeaderTablePosition;
            public int flags;
            public ushort headerSize;
            public ushort pheaderSize;
            public ushort pheaderEntries;
            public ushort sheaderSize;
            public ushort sheaderEntries;
            public ushort symbolSectionNumber;
        }

        struct Elf32SectionHeader {
            public int sh_name;
            public int sh_type;
            public int sh_flags;
            public int sh_addr;
            public int sh_offset;
            public int sh_size;
            public int sh_link;
            public int sh_info;
            public int sh_addralign;
            public int sh_entsize;
        }

        struct Elf32Symbol {
            public int st_name;
            public int st_value;
            public int st_size;
            public byte st_info;
            public byte st_other;
            public ushort st_shndx;
        }

        // C style strings are NUL ( '\0' ) terminated.
        private static void writeOutString(IntPtr str) {
            byte b = Marshal.ReadByte(str);
            while (b != 0) {
                char ch = (char)b;
                Console.Write("{0}", ch);
                str = IntPtr.Add(str, 1);
                b = Marshal.ReadByte(str);
            }
        }

        private static int doNM(string file) {
            byte []result = File.ReadAllBytes(file); // Throws ... detect error in C
            GCHandle pinnedArray = GCHandle.Alloc(result, GCHandleType.Pinned);
            IntPtr readBuffer = pinnedArray.AddrOfPinnedObject(); // char * in C
            Elf32Header hdr = Marshal.PtrToStructure<Elf32Header>(readBuffer);

            if (hdr.magic != elfMagic) { // Only real elf files, please
                Console.WriteLine("Wrong elf magic");
                return -1;
            }
            if (hdr.endian != 1) { // Only LE for now
                Console.WriteLine("Wrong endian");
                return -1;
            }

            // The rest is unsafe ... see if you can make it crash by editing the
            // elf input :-)
            // Also see if you can make the C code more robust
            IntPtr addressOfSectionHeaders =
                IntPtr.Add(readBuffer, hdr.sectionHeaderTablePosition);

            Elf32SectionHeader stringTableHeader =
                new Elf32SectionHeader(); // C: { 0 }
            // Find the string table
            for (int i = 0; i < hdr.sheaderEntries; i++) {
                IntPtr checkSectionAddr =
                    IntPtr.Add
                    (addressOfSectionHeaders,
                     hdr.sheaderSize * i);
                Elf32SectionHeader strSH =
                    Marshal.PtrToStructure<Elf32SectionHeader>(checkSectionAddr);
                if (strSH.sh_type == SHT_STRTAB) {
                    stringTableHeader = strSH;
                }
            }

            if (stringTableHeader.sh_type == 0) {
                Console.WriteLine("Can't find string table");
                return -1;
            }

            IntPtr stringTableData =
                IntPtr.Add(readBuffer, stringTableHeader.sh_offset);

            for (int i = 0; i < hdr.sheaderEntries; i++) {
                IntPtr checkSectionAddr =
                    IntPtr.Add
                    (addressOfSectionHeaders,
                     hdr.sheaderSize * i);
                
                Elf32SectionHeader sh =
                    Marshal.PtrToStructure<Elf32SectionHeader>(checkSectionAddr);

                if (sh.sh_type != SHT_SYMTAB) {
                    continue;
                }
                
                IntPtr symbolsPtr =
                    IntPtr.Add(readBuffer, sh.sh_offset);
                int numSymbols = sh.sh_size / sh.sh_entsize;
                
                for (int j = 0; j < numSymbols; j++) {
                    IntPtr symbolPtr =
                        IntPtr.Add(symbolsPtr, sh.sh_entsize * j);
                    Elf32Symbol sym = Marshal.PtrToStructure<Elf32Symbol>(symbolPtr);
                    if (sym.st_info != STT_SECTION) {
                        Console.Write
                            ("section {0} + {0:X8}: ",
                             sym.st_shndx, sym.st_value);
                        IntPtr stringPtr = IntPtr.Add(stringTableData, sym.st_name);
                        writeOutString(stringPtr);
                        Console.Write("\n");
                    }
                }
            }

            return 0;
        }

        static void Main(string[] argv)
        {
            if (argv.Length == 0) {
                Console.WriteLine("usage: nm.exe [foo.elf]");
                return;
            }
            for (int i = 0; i < argv.Length; i++) {
                if (doNM(argv[i]) < 0) { // The way to detect errors in C generally
                    Console.WriteLine("error handling {0}", argv[i]);
                }
            }
        }
    }
}

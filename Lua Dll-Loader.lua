local ffi = require("ffi")
local bit = require("bit")

ffi.cdef
([[
    typedef unsigned char uchar;
    typedef unsigned short ushort;
    typedef unsigned int uint;
    typedef unsigned long ulong;
    typedef const char* pcstr;
    
    typedef int (__stdcall* FARPROC)();    
    typedef void (__stdcall* PIMAGE_TLS_CALLBACK)(void*, ulong, void*);

    typedef struct   
    {
        ushort Machine;
        ushort NumberOfSections;
        ulong TimeDateStamp;
        ulong PointerToSymbolTable;
        ulong NumberOfSymbols;
        ushort SizeOfOptionalHeader;
        ushort Characteristics;
    } IMAGE_FILE_HEADER;

    typedef struct
    {
        ulong VirtualAddress;
        ulong Size;
    } IMAGE_DATA_DIRECTORY;

    typedef struct
    {    
        ushort Magic;
        uchar MajorLinkerVersion;
        uchar MinorLinkerVersion;
        ulong SizeOfCode;
        ulong SizeOfInitializedData;
        ulong SizeOfUninitializedData;
        ulong AddressOfEntryPoint;
        ulong BaseOfCode;
        ulong BaseOfData;
        
        ulong ImageBase;
        ulong SectionAlignment;
        ulong FileAlignment;
        ushort MajorOperatingSystemVersion;
        ushort MinorOperatingSystemVersion;
        ushort MajorImageVersion;
        ushort MinorImageVersion;
        ushort MajorSubsystemVersion;
        ushort MinorSubsystemVersion;
        ulong Win32VersionValue;
        ulong SizeOfImage;
        ulong SizeOfHeaders;
        ulong CheckSum;
        ushort Subsystem;
        ushort DllCharacteristics;
        ulong SizeOfStackReserve;
        ulong SizeOfStackCommit;
        ulong SizeOfHeapReserve;
        ulong SizeOfHeapCommit;
        ulong LoaderFlags;
        ulong NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    } IMAGE_OPTIONAL_HEADER32;

    typedef struct 
    {
        uchar Name[8];
        union 
        {
            ulong PhysicalAddress;
            ulong VirtualSize;
        } Misc;
        ulong VirtualAddress;
        ulong SizeOfRawData;
        ulong PointerToRawData;
        ulong PointerToRelocations;
        ulong PointerToLinenumbers;
        ushort NumberOfRelocations;
        ushort NumberOfLinenumbers;
        ulong Characteristics;
    } IMAGE_SECTION_HEADER;

    typedef struct 
    {
        union 
        {
            ulong Characteristics;           
            ulong OriginalFirstThunk;        
        } DUMMYUNIONNAME;
        ulong TimeDateStamp;                  
        ulong ForwarderChain;                 
        ulong Name;
        ulong FirstThunk;                    
    } IMAGE_IMPORT_DESCRIPTOR;

    typedef struct 
    {
        ulong VirtualAddress;
        ulong SizeOfBlock;
    } IMAGE_BASE_RELOCATION;

    typedef struct 
    {
        ulong StartAddressOfRawData;
        ulong EndAddressOfRawData;
        ulong AddressOfIndex;             
        ulong AddressOfCallBacks;         
        ulong SizeOfZeroFill;
        union 
        {
            ulong Characteristics;
            struct 
            {
                ulong Reserved0 : 20;
                ulong Alignment : 4;
                ulong Reserved1 : 8;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
    
    } IMAGE_TLS_DIRECTORY32;
    typedef IMAGE_TLS_DIRECTORY32* PIMAGE_TLS_DIRECTORY32;
    
    bool __stdcall VirtualProtect(void*, size_t, ulong, ulong*);
    void* __stdcall VirtualAlloc(void*, size_t, ulong, ulong);
    bool __stdcall VirtualFree(void*, size_t, ulong);    

    void __stdcall  RtlMoveMemory(void*, const void*, size_t);
    void __stdcall RtlZeroMemory(void*, size_t);

    void* __stdcall LoadLibraryA(pcstr);
    FARPROC __stdcall GetProcAddress(void*, pcstr);

    int __stdcall MultiByteToWideChar(ulong, ulong, pcstr, int, wchar_t*, int);

    void* __stdcall CreateMutexA(void*, bool, pcstr);
    ulong __stdcall GetLastError();
]])

--[[
    -- 1-st argument: the size of your dll in bytes
    -- 2-nd - your dll in hex
    For example:
    local dll = ffi.new("uchar[100000]", { 0x5A, 0xFF, 0x00 ... }) 
--]]

local dll = ffi.new("uchar[size]", { })



local IMAGE_SIZEOF_FILE_HEADER = 20

local IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B

local PAGE_NOACCESS = 0x01
local PAGE_READONLY = 0x02
local PAGE_READWRITE = 0x04
local PAGE_WRITECOPY = 0x08
local PAGE_EXECUTE = 0x10
local PAGE_EXECUTE_READ = 0x20
local PAGE_EXECUTE_READWRITE = 0x40
local PAGE_EXECUTE_WRITECOPY = 0x80
local PAGE_NOCACHE = 0x200

local MEM_COMMIT = 0x00001000
local MEM_RESERVE = 0x00002000  
local MEM_RELEASE = 0x00008000

local IMAGE_REL_BASED_ABSOLUTE = 0 

local IMAGE_DIRECTORY_ENTRY_IMPORT = 1
local IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
local IMAGE_DIRECTORY_ENTRY_TLS = 9

local IMAGE_ORDINAL_FLAG32 = 0x80000000

local IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
local IMAGE_SCN_MEM_EXECUTE = 0x20000000
local IMAGE_SCN_MEM_READ = 0x40000000
local IMAGE_SCN_MEM_WRITE = 0x80000000

local DLL_PROCESS_ATTACH = 1


local function strToWstr(str)
    local wlen = ffi.C.MultiByteToWideChar(0, 0, str, #str, nil, 0)
    local wstr = ffi.new("wchar_t[?]", wlen + 1)
    ffi.C.MultiByteToWideChar(0, 0, str, #str, wstr, wlen)
    return wstr
end

local function free(ImageBase)
    if ImageBase ~= nil then
        ffi.C.VirtualFree(ImageBase, 0, MEM_RELEASE)
    end
    return nil
end

local function inject(data)
    local e_lfanew = ffi.cast("ushort*", data + 0x3C)[0]

    local pFileHeader = ffi.cast("IMAGE_FILE_HEADER*", data + e_lfanew + 4)
    
    local pOptionalHeader = ffi.cast("IMAGE_OPTIONAL_HEADER32*", data + e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER) 
        
    if pOptionalHeader.Magic ~= IMAGE_NT_OPTIONAL_HDR32_MAGIC then 
        return nil
    end

    ---------------

    local ImageBase = ffi.cast("char*", ffi.C.VirtualAlloc(ffi.cast("void*", pOptionalHeader.ImageBase), pOptionalHeader.SizeOfImage, bit.bor(MEM_RESERVE, MEM_COMMIT), PAGE_READWRITE))

    if ImageBase == nil then
        ImageBase = ffi.cast("char*", ffi.C.VirtualAlloc(nil, pOptionalHeader.SizeOfImage, bit.bor(MEM_RESERVE, MEM_COMMIT), PAGE_READWRITE))
    end
    if ImageBase == nil then
        return free(ImageBase)
    end

    ---------------

    local dwOldProt = ffi.new("ulong[1]")

    local SectionBase = ffi.cast("char*", ffi.C.VirtualAlloc(ImageBase, pOptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE))

    ffi.C.RtlMoveMemory(SectionBase, data, pOptionalHeader.SizeOfHeaders)
    
    ffi.C.VirtualProtect(SectionBase, pOptionalHeader.SizeOfHeaders, PAGE_READONLY, dwOldProt)

    ---------------
    
    local pSectionHeader = ffi.cast("IMAGE_SECTION_HEADER*", pOptionalHeader + 1)
    
    for i = 0, pFileHeader.NumberOfSections - 1 do
        local dwSize = ffi.new("ulong")

        if pSectionHeader[i].SizeOfRawData ~= 0 then
            dwSize = pSectionHeader[i].Misc.VirtualSize
        else
            dwSize = pOptionalHeader.SectionAlignment
        end

        SectionBase = ffi.cast("char*", ffi.C.VirtualAlloc(ImageBase + pSectionHeader[i].VirtualAddress, dwSize, MEM_COMMIT, PAGE_READWRITE))

        if SectionBase == nil then 
            return free(ImageBase)
        end

        SectionBase = ImageBase + pSectionHeader[i].VirtualAddress
        if dwSize ~= 0 then 
            ffi.C.RtlMoveMemory(SectionBase, data + pSectionHeader[i].PointerToRawData, dwSize)
        else 
            ffi.C.RtlZeroMemory(SectionBase, dwSize) 
        end

        pSectionHeader[i].Misc.PhysicalAddress = ffi.cast("ulong", SectionBase)
    end

    ---------------

    local ImageBaseDelta = ffi.cast("ulong", ImageBase) - pOptionalHeader.ImageBase
    
    if ImageBaseDelta ~= 0 and pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ~= 0 then 
        local pBaseReloc = ffi.cast("IMAGE_BASE_RELOCATION*", ImageBase + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)

        while pBaseReloc.VirtualAddress ~= 0 do
            local dwModCount = ffi.new("ulong", (pBaseReloc.SizeOfBlock - ffi.sizeof("IMAGE_BASE_RELOCATION")) / 2)
            local wPointer = ffi.cast("ushort*", ffi.cast("char*", pBaseReloc) + ffi.sizeof("IMAGE_BASE_RELOCATION"))

            for i = 0, tonumber(dwModCount) - 1 do
                if bit.rshift(wPointer[0], 12) ~= IMAGE_REL_BASED_ABSOLUTE then
                    ffi.cast("ulong*", ImageBase + pBaseReloc.VirtualAddress + bit.band(wPointer[0], 0xFFF))[0] = 
                    ffi.cast("ulong*", ImageBase + pBaseReloc.VirtualAddress + bit.band(wPointer[0], 0xFFF))[0] + ImageBaseDelta
                end
                wPointer = wPointer + 1
            end
            pBaseReloc = ffi.cast("IMAGE_BASE_RELOCATION*", ffi.cast("char*", pBaseReloc) + pBaseReloc.SizeOfBlock)
        end

    elseif ImageBaseDelta ~= 0 then 
        return free(ImageBase)
    end
    
    ---------------

    local pImportDscrtr = ffi.cast("IMAGE_IMPORT_DESCRIPTOR*", ImageBase + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)

    while pImportDscrtr.Name ~= 0 do
        local hLibModule = ffi.C.LoadLibraryA(ffi.cast("char*", ImageBase + pImportDscrtr.Name))
        local pAddress = ffi.cast("ulong*", ImageBase + pImportDscrtr.FirstThunk)
        local pImport = ffi.new("ulong*")

        if pImportDscrtr.TimeDateStamp == 0 then
            pImport = ffi.cast("ulong*", ImageBase + pImportDscrtr.FirstThunk)
        else
            pImport = ffi.cast("ulong*", ImageBase + pImportDscrtr.OriginalFirstThunk)
        end

        local i = 0
        while pImport[i] ~= 0 do
            if bit.band(pImport[i], IMAGE_ORDINAL_FLAG32) ~= 0 then
                pAddress[i] = ffi.cast("ulong", ffi.C.GetProcAddress(hLibModule, ffi.cast("char*", bit.band(pImport[i], 0xFFFF))))
            else
                pAddress[i] = ffi.cast("ulong", ffi.C.GetProcAddress(hLibModule, ffi.cast("char*", ImageBase + pImport[i] + 2)))
            end
            i = i + 1
        end
        pImportDscrtr = pImportDscrtr + 1
    end

    ---------------

    for i = 0, pFileHeader.NumberOfSections - 1 do
        local sc = ffi.new("ulong", pSectionHeader[i].Characteristics)
        local dwResult = ffi.new("ulong")

        if bit.band(sc, IMAGE_SCN_MEM_NOT_CACHED) ~= 0 then
            dwResult = bit.bor(dwResult, PAGE_NOCACHE)
        end

        if bit.band(sc, IMAGE_SCN_MEM_EXECUTE) ~= 0 then
            if bit.band(sc, IMAGE_SCN_MEM_READ) ~= 0 then
                if bit.band(sc, IMAGE_SCN_MEM_WRITE) ~= 0 then
                    dwResult = PAGE_EXECUTE_READWRITE
                else
                    dwResult = PAGE_EXECUTE_READ;
                end
            elseif bit.band(sc, IMAGE_SCN_MEM_WRITE) ~= 0 then
                dwResult = PAGE_EXECUTE_WRITECOPY
            else
                dwResult = PAGE_EXECUTE
            end
        elseif bit.band(sc, IMAGE_SCN_MEM_READ) ~= 0 then
            if bit.band(sc, IMAGE_SCN_MEM_WRITE) ~= 0 then
                dwResult = PAGE_READWRITE
            else
                dwResult = PAGE_READONLY
            end
        elseif bit.band(sc, IMAGE_SCN_MEM_WRITE) ~= 0 then
            dwResult = PAGE_WRITECOPY
        else
            dwResult = PAGE_NOACCESS
        end

        ffi.C.VirtualProtect(ffi.cast("void*", ImageBase + pSectionHeader[i].VirtualAddress), pSectionHeader[i].Misc.VirtualSize, dwResult, dwOldProt)
    end

    ---------------

    if pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress ~= 0 then
        local callback = ffi.cast("PIMAGE_TLS_CALLBACK*", 
            ffi.cast("PIMAGE_TLS_DIRECTORY32", ImageBase + pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress).AddressOfCallBacks)

        if callback ~= nil then
            while callback[0] do
                callback[0](ffi.cast("void*", ImageBase), DLL_PROCESS_ATTACH, nil)
                callback = callback + 1
            end
        end
    end

   ---------------
    
    if pOptionalHeader.AddressOfEntryPoint ~= 0 then
        if ffi.cast("int (__stdcall*)(void*, ulong, void*)", ImageBase + pOptionalHeader.AddressOfEntryPoint)(ffi.cast("void*", ImageBase), DLL_PROCESS_ATTACH, nil) == 0 then
            return free(ImageBase)
        end
    end
    
	return ffi.cast("void*", ImageBase)
end

local function main()
    local base = inject(dll)
end


main()  -- entry point
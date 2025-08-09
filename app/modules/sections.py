import lief
from . import colors

lief.logging.disable()

MEM_READ = 0x40000000
MEM_WRITE = 0x80000000
MEM_EXECUTE = 0x20000000
CNT_CODE = 0x00000020

def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "SECTIONS", " -------------------------------") + colors.DEFAULT))
    
    sec = 0
    susp_sec = 0
    format_str = "{:<35} {:<35}"
    
    binary = lief.parse(malware)
    
    for section in binary.sections:
        sec += 1
        print((colors.YELLOW + section.name + colors.DEFAULT))
        print(format_str.format(colors.WHITE + "\tVirtual Address: " + colors.DEFAULT, str(section.virtual_address)))
        print(format_str.format(colors.WHITE + "\tVirtual Size: " + colors.DEFAULT, str(section.virtual_size)))
        print(format_str.format(colors.WHITE + "\tRaw Size: " + colors.DEFAULT, str(section.sizeof_raw_data)))
        print(format_str.format(colors.WHITE + "\tEntropy: " + colors.DEFAULT, f"{section.entropy:.4f}"))

        if (section.characteristics & MEM_READ) != 0:
            print(format_str.format(colors.WHITE + "\tReadable: " + colors.GREEN, "[" + '\u2713' + "]"))
        else:
            print(format_str.format(colors.WHITE + "\tReadable: " + colors.RED, "[X]"))

        if (section.characteristics & MEM_WRITE) != 0:
            print(format_str.format(colors.WHITE + "\tWritable: " + colors.GREEN, "[" + '\u2713' + "]"))
        else:
            print(format_str.format(colors.WHITE + "\tWritable: " + colors.RED, "[X]"))

        if (section.characteristics & MEM_EXECUTE) != 0:
            print(format_str.format(colors.WHITE + "\tExecutable: " + colors.GREEN, "[" + '\u2713' + "]"))
        else:
            print(format_str.format(colors.WHITE + "\tExecutable: " + colors.RED, "[X]"))

        # Entropy-based suspicion
        if section.size == 0 or (0 < section.entropy < 1) or section.entropy > 7:
            print(format_str.format(colors.WHITE + "\tSuspicious: " + colors.GREEN, "[" + '\u2713' + "]"))
            susp_sec += 1
        else:
            print(format_str.format(colors.WHITE + "\tSuspicious: " + colors.RED, "[X]"))

    # Suspicious section ratio based on entropy
    print(colors.RED + "\n[-]" + colors.WHITE + " Suspicious section (entropy) ratio: " + colors.DEFAULT + f"{susp_sec}/{sec}")
    csv.write(f"{susp_sec/sec:.2%},")

    # Suspicious section names detection
    standardSectionNames = [".text", ".bss", ".rdata", ".data", ".idata", ".reloc", ".rsrc"]
    suspiciousSections = 0
    for section in binary.sections:
        if section.name not in standardSectionNames:
            suspiciousSections += 1
    print(colors.RED + "[-]" + colors.WHITE + " Suspicious section (name) ratio: " + colors.DEFAULT + f"{suspiciousSections}/{sec}")
    csv.write(f"{suspiciousSections/sec:.2%},")

    # Check if size of code in optional header > sum of code sections size
    code_sec_size = 0
    for section in binary.sections:
        if (section.characteristics & CNT_CODE) != 0:
            code_sec_size += section.size

    if binary.optional_header.sizeof_code > code_sec_size:
        print(colors.RED + "[X]" + colors.DEFAULT + f" The size of code ({binary.optional_header.sizeof_code} bytes) is bigger than the sum of code sections ({code_sec_size} bytes)")
        csv.write("1,")
    else:
        print(colors.GREEN + "[" + '\u2713' + "]" + colors.DEFAULT + f" The size of code ({binary.optional_header.sizeof_code} bytes) matches the sum of code sections")
        csv.write("0,")

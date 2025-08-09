import lief
from . import colors

lief.logging.disable()

# check if PE file supports control flow guard


GUARD_CF = 0x4000  # from PE spec: IMAGE_DLLCHARACTERISTICS_GUARD_CF (bit 14)

def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "CFG", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    dll_char = binary.optional_header.dll_characteristics
    if (dll_char & GUARD_CF) != 0:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Control Flow Guard (CFG)"))
        csv.write("1,")
    else:
        print((
            colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Control Flow Guard (CFG)"))
        csv.write("0,")

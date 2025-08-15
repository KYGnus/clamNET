import lief
from . import colors

lief.logging.disable()

# Check if PE supports Data Execution Prevention (DEP)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "DEP", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    NX_COMPAT = 0x0100  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT

    dll_char = binary.optional_header.dll_characteristics
    if (dll_char & NX_COMPAT) != 0:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Data Execution Prevention (DEP)"))
        csv.write("1,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT +
               " The file doesn't support Data Execution Prevention (DEP)"))
        csv.write("0,")

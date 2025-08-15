import lief
from . import colors

lief.logging.disable()

# Check if PE file uses Structured Exception Handling (SEH)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "SEH", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    NO_SEH = 0x0400  # IMAGE_DLLCHARACTERISTICS_NO_SEH

    dll_char = binary.optional_header.dll_characteristics
    if (dll_char & NO_SEH) != 0:
        print((colors.RED + "[X]" + colors.DEFAULT +
               " The file doesn't support Structured Exception Handling (SEH)"))
        csv.write("0,")
    else:
        print((colors.GREEN + "[" + '\u2713' + "]" + colors.DEFAULT +
               " The file supports Structured Exception Handling (SEH)"))
        csv.write("1,")

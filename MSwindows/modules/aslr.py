import lief
from . import colors

lief.logging.disable()

# Check if PE supports Address Space Layout Randomization (ASLR)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "ASLR", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    DYNAMIC_BASE = 0x0040  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

    dll_char = binary.optional_header.dll_characteristics
    if (dll_char & DYNAMIC_BASE) != 0:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Address Space Layout Randomization (ASLR)"))
        csv.write("1,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT +
               " The file doesn't support Address Space Layout Randomization (ASLR)"))
        csv.write("0,")

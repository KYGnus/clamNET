import yara
import os
import sys
from . import colors
import string

# Returns the absolute path to yara rules relative to the main module
def get_yara(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'rules', path)

def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "YARA RULES", " -------------------------------") + colors.DEFAULT))
    
    # Compile all your yara rules under namespaces
    rules = yara.compile(filepaths={
        'AntiVM/DB': get_yara('Antidebug_AntiVM_index.yar'),
        'Crypto': get_yara('Crypto_index.yar'),
        'CVE': get_yara('CVE_Rules_index.yar'),
        'Exploit': get_yara('Exploit-Kits_index.yar'),
        'Document': get_yara('Malicious_Documents_index.yar'),
        'Malware': get_yara('malware_index.yar'),
        'Packers': get_yara('Packers_index.yar'),
        'Webshell': get_yara('Webshells_index.yar')
    })

    strings_list = []
    format_str = "{:<35} {:<15} {:<12}"

    with open(malware, 'rb') as f:
        matches = rules.match(data=f.read())

    if matches:
        for match in matches:
            print((colors.YELLOW + str(match.rule) + colors.DEFAULT))
            print((colors.WHITE + "\tType: " + colors.RED + str(match.namespace)))
            print((colors.WHITE + "\tTags: " + colors.DEFAULT + ("".join(match.tags) if match.tags else "None")))
            print((colors.WHITE + "\tMeta:"))
            print((colors.WHITE + "\t\tDate: " + colors.DEFAULT + str(match.meta.get('date'))))
            print((colors.WHITE + "\t\tVersion: " + colors.DEFAULT + str(match.meta.get('version'))))
            print((colors.WHITE + "\t\tDescription: " + colors.DEFAULT + str(match.meta.get('description'))))
            print((colors.WHITE + "\t\tAuthor: " + colors.DEFAULT + str(match.meta.get('author'))))

            if not match.strings:
                print((colors.WHITE + "\tStrings: " + colors.DEFAULT + "None"))
            else:
                for s in match.strings:
                    matched_bytes = None
                    if hasattr(s, 'data'):
                        matched_bytes = s.data
                    elif hasattr(s, 'match'):
                        matched_bytes = s.match
                    else:
                        matched_bytes = str(s).encode('utf-8')

                    matched_str = matched_bytes.decode('utf-8', errors='replace')
                    strings_list.append(matched_str)


                print((colors.WHITE + "\tStrings:"))
                non_printable_count = 0
                for unique_str in sorted(set(strings_list)):
                    if all(c in string.printable for c in unique_str):
                        print("\t\t" + format_str.format(
                            unique_str,
                            colors.WHITE + "| Occurrences:" + colors.DEFAULT,
                            str(strings_list.count(unique_str))
                        ))
                    else:
                        non_printable_count += 1

                if non_printable_count > 0:
                    print("\t\t[X] " + str(non_printable_count) + " string(s) not printable")
                
                strings_list.clear()  # clear list for next rule

            print("\n")
        
        csv.write(str(len(matches)))
    else:
        print((colors.RED + "[X] No matches found" + colors.DEFAULT))
        csv.write("0")

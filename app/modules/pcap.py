# modules/pcap.py
import os
from lupa import LuaRuntime

lua = LuaRuntime(unpack_returned_tuples=True)

# Recursive conversion: Lua table → Python dict/list
def lua_table_to_python(obj):
    if hasattr(obj, "items"):  # It's a Lua table
        # Check if table is array-like
        keys = list(obj.keys())
        if all(isinstance(k, int) for k in keys):
            # Sort by numeric index for lists
            return [lua_table_to_python(obj[i]) for i in sorted(keys)]
        else:
            return {k: lua_table_to_python(v) for k, v in obj.items()}
    else:
        return obj

lua_file_path = os.path.join(os.path.dirname(__file__), "pcap_analyzer.lua")
with open(lua_file_path, "r") as f:
    pcap_module = lua.execute(f.read())

def analyze_pcap(file_path):
    """
    Call the Lua pcap analyzer and return Python-native data.
    """
    result = pcap_module.analyze_pcap(file_path)
    return lua_table_to_python(result)

if __name__ == "__main__":
    data = analyze_pcap("/home/koosha/Downloads/hart_ip.pcap")
    print("Protocol counts:", data["protocol_count"])
    for pkt in data["packets"]:
        print(pkt["timestamp"], pkt["src"], "->", pkt["dst"], pkt["protocol"])

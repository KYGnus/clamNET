-- modules/pcap_analyzer.lua
local pcap = {}

function pcap.analyze_pcap(filename)
    local data = {
        protocol_count = {},
        packets = {}
    }

    -- Example (replace with real parsing logic later)
    data.protocol_count["TCP"] = 10
    data.protocol_count["UDP"] = 5

    table.insert(data.packets, {
        timestamp = "1624973824.000001",
        src = "192.168.1.10",
        dst = "192.168.1.1",
        protocol = "TCP"
    })

    table.insert(data.packets, {
        timestamp = "1624973825.000002",
        src = "192.168.1.11",
        dst = "192.168.1.2",
        protocol = "UDP"
    })

    return data
end

return pcap

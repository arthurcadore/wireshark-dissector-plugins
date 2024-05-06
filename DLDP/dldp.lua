-- Author: ArthurCadore 
-- DLDP for Intelbras's switches

-- Defining the protocol description
local dldp = Proto("dldp", "Device Link Detection Protocol")

local fields = dldp.fields
fields.sequence = ProtoField.uint16("dldp.sequence", "Sequence Number")
fields.mac_src = ProtoField.bytes("dldp.mac_src", "Source MAC")
fields.interval = ProtoField.uint16("dldp.interval", "DLDP Interval")
fields.password = ProtoField.string("dldp.password", "DLDP Password")
fields.flags = ProtoField.bytes("dldp.flags", "DLDP Config Flags")

function dldp.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = dldp.name

    local subtree = tree:add(dldp, buffer(), "DLDP Protocol Data")
    if buffer(0, 1):uint() == 0x00 then
        local password_end = buffer:len() - 4
        local password_length = 0
        for i=6, password_end do
            if buffer(i, 1):uint() == 0x00 and buffer(i+1, 1):uint() == 0x00
               and buffer(i+2, 1):uint() == 0x00 and buffer(i+3, 1):uint() == 0x00 then
                password_length = i - 6
                break
            end
        end

        subtree:add(fields.flags, buffer(2,4))
        subtree:add(fields.password, buffer(6, password_length):string())
        subtree:add(fields.interval, buffer(6 + password_length + 4,2):uint())
        subtree:add(fields.mac_src, buffer(6 + password_length + 8,6))
        subtree:add(fields.sequence, buffer(6 + password_length + 14,2):uint())
        pinfo.cols.info:set("DLDP Packet")
    else
        pinfo.cols.info:set("General-Slow-Protocol-Packet")
    end
end

local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x8809, dldp)

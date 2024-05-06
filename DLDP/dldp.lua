-- Author: ArthurCadore
-- DLDP for Intelbras's switches

-- Defining the protocol description
local dldp = Proto("dldp", "Device Link Detection Protocol")

-- Defining the fields of the protocol
local fields = dldp.fields
fields.sequence = ProtoField.uint16("dldp.sequence", "Sequence Number")
fields.mac_src = ProtoField.bytes("dldp.mac_src", "Source Interface MAC")
fields.interval = ProtoField.uint16("dldp.interval", "DLDP Interval (seconds)")
fields.password = ProtoField.string("dldp.password", "DLDP Password")
fields.flags = ProtoField.bytes("dldp.flags", "DLDP Config Flags")

-- Defining individual flags
fields.flag1 = ProtoField.uint8("dldp.flag1", "Flag 1", base.HEX)
fields.flag2 = ProtoField.uint8("dldp.flag2", "Flag 2", base.HEX)
fields.flag3 = ProtoField.uint8("dldp.flag3", "Flag 3", base.HEX)
fields.flag4 = ProtoField.uint8("dldp.flag4", "Flag 4", base.HEX)

-- Defining the dissector function
function dldp.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- Setting the protocol name in the packet details
    pinfo.cols.protocol = dldp.name

    -- Setting the DLDP Protocol data field
    local subtree = tree:add(dldp, buffer(), "DLDP Protocol Data")

    -- checking if the slow protocol subtype is equal to 0x00
    if buffer(0, 1):uint() == 0x00 then

        -- Calculating the password lenght looking for 0x00000000 array on packet. 
        local password_end = buffer:len() - 4
        local password_length = 0
        for i=6, password_end do
            if buffer(i, 1):uint() == 0x00 and buffer(i+1, 1):uint() == 0x00
               and buffer(i+2, 1):uint() == 0x00 and buffer(i+3, 1):uint() == 0x00 then
                password_length = i - 6
                break
            end
        end

        -- Adding subfields to DLDP data flags 
        local flags = buffer(2, 4):le_uint()
        subtree:add(fields.flag1, buffer(2, 1))
        subtree:add(fields.flag2, buffer(3, 1))
        subtree:add(fields.flag3, buffer(4, 1))
        subtree:add(fields.flag4, buffer(5, 1))

        -- Adding field for password 
        subtree:add(fields.password, buffer(6, password_length):string())

        -- Adding field for DLDP interval 
        subtree:add(fields.interval, buffer(6 + password_length + 4, 2):uint())

        -- Adding field for source interface mac address. 
        subtree:add(fields.mac_src, buffer(6 + password_length + 8, 6))

        -- Adding field for DLDP sequence number 
        subtree:add(fields.sequence, buffer(6 + password_length + 14, 2):uint())
        pinfo.cols.info:set("DLDP Packet")
    else
        pinfo.cols.info:set("General-Slow-Protocol-Packet")
    end
end

-- Adding the dissector to the Ethernet dissector table
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x8809, dldp)

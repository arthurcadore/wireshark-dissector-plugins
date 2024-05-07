-- Author: ArthurCadore
-- DLDP for Intelbras's switches

-- Defining the protocol description
local dldp = Proto("dldp", "Device Link Detection Protocol")

-- Defining the fields of the protocol
local fields = dldp.fields
fields.sequence = ProtoField.uint16("dldp.sequence", "Source Interface Index")
fields.mac_src = ProtoField.bytes("dldp.mac_src", "Source Interface MAC")
fields.interval = ProtoField.uint16("dldp.interval", "Interval (seconds)")
fields.password = ProtoField.string("dldp.password", "Password")
fields.id = ProtoField.bytes("dldp.id", "DLDP ID")
fields.version = ProtoField.bytes("dldp.version", "DLDP Version")
fields.packet_type = ProtoField.bytes("dldp.packet_type", "DLDP Packet Type")
fields.flags = ProtoField.bytes("dldp.flags", "Flags")
fields.neighbour1 = ProtoField.bytes("dldp.neighbour1", "Source Neighbour MAC")
fields.neighbour2 = ProtoField.bytes("dldp.neighbour2", "Destination Neighbour MAC")

-- Mapping for packet_type values to their corresponding strings
local packet_type_map = {
    [0x01] = "ADVERTISEMENT",
    [0x02] = "RECOVER-PROBE",
    [0x03] = "PROBE",
    [0x08] = "ECHO",
    [0x09] = "RECOVER-ECHO",
    [0x06] = "ECHO"
}

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
        -- Add a subtree for DLDP header
        local dldp_subtree = subtree:add(dldp, buffer(), "DLDP Header")
        dldp_subtree:add(fields.id, buffer(1, 1))
        dldp_subtree:add(fields.version, buffer(2, 1))
        local packet_type_value = buffer(3, 1):uint()
        local packet_type_str = packet_type_map[packet_type_value] or tostring(packet_type_value)
        local packet_type = dldp_subtree:add(fields.packet_type, buffer(3, 1))
        packet_type:append_text(" (" .. packet_type_str .. ")")
        dldp_subtree:add(fields.flags, buffer(4, 1))

        -- Calculating the password length looking for 0x00000000 array on packet. 
        local password_end = buffer:len() - 4
        local password_length = 0
        for i=6, password_end do
            if buffer(i, 1):uint() == 0x00 and buffer(i+1, 1):uint() == 0x00
               and buffer(i+2, 1):uint() == 0x00 and buffer(i+3, 1):uint() == 0x00 then
                password_length = i - 6
                break
            end
        end

        -- Adding field for password 
        subtree:add(fields.password, buffer(6, password_length):string())

        -- Adding field for DLDP interval 
        subtree:add(fields.interval, buffer(6 + password_length + 4, 2):uint())

        -- Adding field for source interface mac address. 
        subtree:add(fields.mac_src, buffer(6 + password_length + 8, 6))

        -- Adding field for DLDP sequence number 
        subtree:add(fields.sequence, buffer(6 + password_length + 14, 2):uint())

        -- Add neighbour fields for packet_type 0x03 and 0x09
        if packet_type_value == 0x03 then
            subtree:add(fields.neighbour1, buffer(34, 6))
            subtree:add(fields.neighbour2, buffer(42, 6))
        elseif packet_type_value == 0x09 then
            subtree:add(fields.neighbour1, buffer(34, 6))
            subtree:add(fields.neighbour2, buffer(42, 6))
        end

        pinfo.cols.info:set("DLDP, SRC_IF_MAC: " .. tostring(buffer(6 + password_length + 8, 6)) .. ", Type: " .. packet_type_str)
    else
        pinfo.cols.info:set("General-Slow-Protocol-Packet")
    end
end

-- Adding the dissector to the Ethernet dissector table
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x8809, dldp)

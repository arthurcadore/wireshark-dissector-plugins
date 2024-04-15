-- Author: ArthurCadore 
-- Loopback Detection Dissector for SG MR L2+ Intelbras's switches

-- Defining the protocol description
LoopbackDetection = Proto("loopback_detection", "Loopback Detection Protocol")

-- Defining the protocol sections
local MagicNumber = ProtoField.uint16("loopback_detection.magic_number", "Magic Number", base.HEX)
local SequenceNumber = ProtoField.uint16("loopback_detection.sequence_number", "Sequence Number", base.DEC)
local LoopbackHash = ProtoField.bytes("loopback_detection.loopback_hash", "Loopback Hash", base.NONE)

LoopbackDetection.fields = { MagicNumber, SequenceNumber, LoopbackHash }

-- Function to LD dissector
function LoopbackDetection.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "LOOPBACK"
    local subtree = tree:add(LoopbackDetection, buffer())
    subtree:add(MagicNumber, buffer(0, 8))
    subtree:add(SequenceNumber, buffer(8, 4))
    subtree:add(LoopbackHash, buffer(12, 16))
end

-- Protocol association for Ethertype 0x9900
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x9900, LoopbackDetection)

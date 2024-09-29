-- Declaration of the new protocol ACF-VSS
acf_vss = Proto.new("ACF-VSS", "VSS over AVTP Control Format", "acf-vss")

local ENUM_VSS_ADDR_MODE    = {[0] = "INTEROP_MODE", [1] = "STATIC_ID_MODE"}
local ENUM_VSS_OPCODE       = {[0] = "TARGET_VALUE", [1] = "CURRENT_VALUE"}
local ENUM_VSS_DATATYPE     = {[0] = "UINT8", [1] = "INT8", [2] = "UINT16", [3] = "INT16", [4] = "UINT32",
                               [5] = "INT32", [6] = "UINT64", [7] = "INT64", [8] = "BOOL", [9] = "FLOAT",
                               [10] = "DOUBLE", [11] = "UTF8-STRING", [0x80] = "UINT8[]", [0x81] = "INT8[]",
                               [0x82] = "UINT16[]", [0x83] = "INT16[]", [0x84] = "UINT32[]", [0x85] = "INT32[]",
                               [0x86] = "UINT64[]", [0x87] = "INT64[]", [0x88] = "BOOL[]", [0x89] = "FLOAT[]",
                               [0x8A] = "DOUBLE[]", [0x8B] = "UTF8-STRING[]"}

acf_vss_padding = ProtoField.uint8("acf.vss.padding", "VSS Padding", base.HEX, NULL, 0xC0)
acf_vss_mtv = ProtoField.uint8("acf.vss.mtv", "VSS Timestamp Valid", base.HEX, NULL, 0x20)
acf_vss_addr_mode = ProtoField.uint8("acf.vss.addr_mode", "VSS Addressing Mode", base.HEX, ENUM_VSS_ADDR_MODE, 0x18)
acf_vss_opcode = ProtoField.uint8("acf.vss.opcode", "VSS Opcode", base.HEX, ENUM_VSS_OPCODE, 0x7)
acf_vss_datatype = ProtoField.uint8("acf.vss.datatype", "VSS Datatype", base.HEX, ENUM_VSS_DATATYPE)
acf_vss_timestamp = ProtoField.uint64("acf.vss.timestamp", "VSS Timestamp", base.HEX)
acf_vss_path_static_id = ProtoField.uint32("acf.vss.path_staticid", "VSS Path Static ID", base.HEX)
acf_vss_path_length = ProtoField.uint16("acf.vss.path_len", "VSS Path Length", base.HEX)
acf_vss_path = ProtoField.string("acf.vss.path", "VSS Path", base.ASCII)

acf_vss_data_uint8 = ProtoField.uint8("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_int8 = ProtoField.int8("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_uint16 = ProtoField.uint16("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_int16 = ProtoField.int16("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_uint32 = ProtoField.uint32("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_int32 = ProtoField.int32("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_uint64 = ProtoField.uint64("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_int64 = ProtoField.int64("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_bool = ProtoField.bool("acf.vss.data", "VSS Data", base.NONE)
acf_vss_data_float = ProtoField.float("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_double = ProtoField.double("acf.vss.data", "VSS Data", base.DEC)
acf_vss_data_string = ProtoField.string("acf.vss.data", "VSS Data", base.ASCII)

acf_vss_payload_padding = ProtoField.bytes("acf.vss.padding", "Padding", base.NONE)

acf_vss.fields = {acf_vss_padding, acf_vss_mtv, acf_vss_addr_mode, acf_vss_opcode, acf_vss_datatype, acf_vss_timestamp,
                    acf_vss_path_static_id, acf_vss_path_length, acf_vss_path, acf_vss_data_uint8, acf_vss_data_int8,
                    acf_vss_data_uint16, acf_vss_data_int16, acf_vss_data_uint32, acf_vss_data_int32, acf_vss_data_uint64,
                    acf_vss_data_int64, acf_vss_data_bool, acf_vss_data_float, acf_vss_data_double, acf_vss_data_string,
                    acf_vss_payload_padding}

function acf_vss.dissector(buffer, pinfo, tree)

    local byte_count = 0
    local buffer_start = 0
    local length = buffer:len()
    local info_string = "ACF-VSS"

    if length == 0 then return end
    pinfo.cols.protocol = acf_vss.name


    subtree = tree:add(acf_vss, buffer(buffer_start, length), "ACF VSS Header")
    byte_count = buffer_start
    subtree:add(acf_vss_padding, buffer(byte_count,1))
    local padding =  buffer(byte_count,1):bitfield(0, 2)
    subtree:add(acf_vss_mtv, buffer(byte_count,1))
    subtree:add(acf_vss_addr_mode, buffer(byte_count,1))
    local addr_mode =  buffer(byte_count,1):bitfield(3, 2)
    subtree:add(acf_vss_opcode, buffer(byte_count,1))
    byte_count = byte_count + 1
    subtree:add(acf_vss_datatype, buffer(byte_count,1))
    local datatype =  buffer(byte_count,1):uint()
    byte_count = byte_count + 1
    subtree:add(acf_vss_timestamp, buffer(byte_count,8))
    byte_count = byte_count + 8

    -- Check for the VSS addressing mode
    subtree = tree:add(acf_vss, buffer(byte_count, length-byte_count), "VSS Path")
    if ENUM_VSS_ADDR_MODE[addr_mode] == "STATIC_ID_MODE" then
        subtree:add(acf_vss_path_static_id, buffer(byte_count,4))
        local vss_path_static_id =  buffer(byte_count,4):uint()
        info_string = info_string .. "(" .. tostring(vss_path_static_id) .. ")"
        byte_count = byte_count + 4
    elseif ENUM_VSS_ADDR_MODE[addr_mode] == "INTEROP_MODE" then
        -- subtree:add(acf_vss_path_length, buffer(byte_count,2))
        local vss_path_length =  buffer(byte_count,2):uint()
        byte_count = byte_count + 2

        subtree:add(acf_vss_path, buffer(byte_count,vss_path_length))
        local vss_path = buffer(byte_count,vss_path_length):string()
        info_string = info_string .. "(" .. vss_path .. ")"
        byte_count = byte_count + vss_path_length
    end

    -- Check for the VSS Datatype
    subtree = tree:add(acf_vss, buffer(byte_count, length-byte_count), "VSS Data")
    if ENUM_VSS_DATATYPE[datatype] == "UINT8" then
        if byte_count + 1 <= length then
            subtree:add(acf_vss_data_uint8, buffer(byte_count,1))
            local vss_data_uint8 = buffer(byte_count,1):uint()
            info_string = info_string .. " = " .. tostring(vss_data_uint8)
            byte_count = byte_count + 1
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT8" then
        if byte_count + 1 <= length then
            subtree:add(acf_vss_data_int8, buffer(byte_count,1))
            local vss_data_int8 = buffer(byte_count,1):int()
            info_string = info_string .. " = " .. tostring(vss_data_int8)
            byte_count = byte_count + 1
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT16" then
        if byte_count + 2 <= length then
            subtree:add(acf_vss_data_uint16, buffer(byte_count,2))
            local vss_data_uint16 = buffer(byte_count,2):uint()
            info_string = info_string .. " = " .. tostring(vss_data_uint16)
            byte_count = byte_count + 2
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT16" then
        if byte_count + 2 <= length then
            subtree:add(acf_vss_data_int16, buffer(byte_count,2))
            local vss_data_int16 = buffer(byte_count,2):int()
            info_string = info_string .. " = " .. tostring(vss_data_int16)
            byte_count = byte_count + 2
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT32" then
        if byte_count + 4 <= length then
            subtree:add(acf_vss_data_uint32, buffer(byte_count,4))
            local vss_data_uint32 = buffer(byte_count,4):uint()
            info_string = info_string .. " = " .. tostring(vss_data_uint32)
            byte_count = byte_count + 4
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT32" then
        if byte_count + 4 <= length then
            subtree:add(acf_vss_data_int32, buffer(byte_count,4))
            local vss_data_int32 = buffer(byte_count,4):int()
            info_string = info_string .. " = " .. tostring(vss_data_int32)
            byte_count = byte_count + 4
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT64" then
        if byte_count + 8 <= length then
            subtree:add(acf_vss_data_uint64, buffer(byte_count,8))
            local vss_data_uint64 = buffer(byte_count,8):uint()
            info_string = info_string .. " = " .. tostring(vss_data_uint64)
            byte_count = byte_count + 8
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT64" then
        if byte_count + 8 <= length then
            subtree:add(acf_vss_data_int64, buffer(byte_count,8))
            local vss_data_int64 = buffer(byte_count,8):int()
            info_string = info_string .. " = " .. tostring(vss_data_int64)
            byte_count = byte_count + 8
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "BOOL" then
        if byte_count + 1 <= length then
            subtree:add(acf_vss_data_bool, buffer(byte_count,1))
            local vss_data_bool = (buffer(byte_count,1):uint() == 1)
            info_string = info_string .. " = " .. tostring(vss_data_bool)
            byte_count = byte_count + 1
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "FLOAT" then
        if byte_count + 4 <= length then
            subtree:add(acf_vss_data_float, buffer(byte_count,4))
            local vss_data_float = buffer(byte_count,4):float()
            info_string = info_string .. " = " .. tostring(vss_data_float)
            byte_count = byte_count + 4
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "DOUBLE" then
        if byte_count + 8 <= length then
            subtree:add(acf_vss_data_double, buffer(byte_count,8))
            local vss_data_double = buffer(byte_count,8):float()
            info_string = info_string .. " = " .. tostring(vss_data_double)
            byte_count = byte_count + 8
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UTF8-STRING" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            if byte_count + data_length <= length then
                subtree:add(acf_vss_data_string, buffer(byte_count,data_length))
                local vss_data_string = buffer(byte_count,data_length):string()
                info_string = info_string .. " = " .. vss_data_string
                byte_count = byte_count + data_length
            end
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT8[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length, 1
            do
                if byte_count + 1 <= length then
                    subtree:add(acf_vss_data_uint8, buffer(byte_count,1))
                    local vss_data_uint8 = buffer(byte_count,1):uint()
                    info_string = info_string .. tostring(vss_data_uint8) .. " "
                    byte_count = byte_count + 1
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT8[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length, 1
            do
                if byte_count + 1 <= length then
                    subtree:add(acf_vss_data_int8, buffer(byte_count,1))
                    local vss_data_int8 = buffer(byte_count,1):int()
                    info_string = info_string .. tostring(vss_data_int8) .. " "
                    byte_count = byte_count + 1
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT16[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/2, 1
            do
                if byte_count + 2 <= length then
                    subtree:add(acf_vss_data_uint16, buffer(byte_count,2))
                    local vss_data_uint16 = buffer(byte_count,2):uint()
                    info_string = info_string .. tostring(vss_data_uint16) .. " "
                    byte_count = byte_count + 2
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT16[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/2, 1
            do
                if byte_count + 2 <= length then
                    subtree:add(acf_vss_data_int16, buffer(byte_count,2))
                    local vss_data_int16 = buffer(byte_count,2):int()
                    info_string = info_string .. tostring(vss_data_int16) .. " "
                    byte_count = byte_count + 2
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT32[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/4, 1
            do
                if byte_count + 4 <= length then
                    subtree:add(acf_vss_data_uint32, buffer(byte_count,4))
                    local vss_data_uint32 = buffer(byte_count,4):uint()
                    info_string = info_string .. tostring(vss_data_uint32) .. " "
                    byte_count = byte_count + 4
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT32[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/4, 1
            do
                if byte_count + 8 <= length then
                    subtree:add(acf_vss_data_int32, buffer(byte_count,8))
                    local vss_data_int32 = buffer(byte_count,8):int()
                    info_string = info_string .. tostring(vss_data_int32) .. " "
                    byte_count = byte_count + 8
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UINT64[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/8, 1
            do
                if byte_count + 8 <= length then
                    subtree:add(acf_vss_data_uint64, buffer(byte_count,8))
                    local vss_data_uint64 = buffer(byte_count,8):uint()
                    info_string = info_string .. tostring(vss_data_uint64) .. " "
                    byte_count = byte_count + 8
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "INT64[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/8, 1
            do
                if byte_count + 8 <= length then
                    subtree:add(acf_vss_data_int64, buffer(byte_count,8))
                    local vss_data_int64 = buffer(byte_count,8):int()
                    info_string = info_string .. tostring(vss_data_int64) .. " "
                    byte_count = byte_count + 8
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "BOOL[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length, 1
            do
                if byte_count + 1 <= length then
                    subtree:add(acf_vss_data_bool, buffer(byte_count,1))
                    local vss_data_bool = (buffer(byte_count,1):uint() == 1)
                    info_string = info_string .. tostring(vss_data_bool) .. " "
                    byte_count = byte_count + 1
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "FLOAT[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/4, 1
            do
                if byte_count + 4 <= length then
                    subtree:add(acf_vss_data_float, buffer(byte_count,4))
                    local vss_data_float = buffer(byte_count,4):float()
                    info_string = info_string .. tostring(vss_data_float) .. " "
                    byte_count = byte_count + 4
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "DOUBLE[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            for i = 1, data_length/8, 1
            do
                if byte_count + 8 <= length then
                    subtree:add(acf_vss_data_double, buffer(byte_count,8))
                    local vss_data_double = buffer(byte_count,8):float()
                    info_string = info_string .. tostring(vss_data_double) .. " "
                    byte_count = byte_count + 8
                end
            end
            info_string = info_string .. "] "
        end
    elseif ENUM_VSS_DATATYPE[datatype] == "UTF8-STRING[]" then
        if byte_count + 2 < length then
            local data_length = buffer(byte_count,2):uint()
            byte_count = byte_count + 2

            info_string = info_string .. " = [ "
            i = 0
            while i < data_length
            do
                local str_len = 0
                if byte_count + 2 < length then
                    str_len = buffer(byte_count,2):uint()
                    byte_count = byte_count + 2
                end
                if byte_count + str_len <= length then
                    subtree:add(acf_vss_data_string, buffer(byte_count,str_len))
                    local vss_data_string = buffer(byte_count,str_len):string()
                    if i ~= 0 then
                        info_string = info_string .. ", "
                    end
                    info_string = info_string .. vss_data_string
                    byte_count = byte_count + str_len
                end
                i = i + str_len + 2
            end
            info_string = info_string .. " ]"
        end
    end

    if (byte_count + padding <= length)  and (padding > 0) then
        subtree:add(acf_vss_payload_padding, buffer(byte_count,padding))
    end

    pinfo.cols.info = info_string

end

local acfDissectorTable = DissectorTable.get("acf.msg_type")
acfDissectorTable:add(0x42, acf_vss)
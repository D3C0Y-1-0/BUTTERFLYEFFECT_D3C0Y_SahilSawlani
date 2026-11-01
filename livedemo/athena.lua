-- Wireshark dissector so ATHENA events read as a protocol column.
-- Install: copy to the Personal Lua Plugins folder (Help > About Wireshark > Folders), or start with: wireshark -X lua_script:athena.lua
local p = Proto("athena", "ATHENA decision")
local f_msg = ProtoField.string("athena.msg", "Event")
p.fields = { f_msg }
function p.dissector(buf, pinfo, tree)
  pinfo.cols.protocol = "ATHENA"
  pinfo.cols.info = buf():string()
  tree:add(p, buf()):add(f_msg, buf())
end
DissectorTable.get("udp.port"):add(47474, p)

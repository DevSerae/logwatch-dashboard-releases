-- Logwatch Dashboard: keep only what the board uses, add the fields the board queries.
-- Return -1 drops the record, 1 keeps it modified.

local keep_security = {
  [1102]=true, [4625]=true, [4719]=true, [4720]=true, [4722]=true, [4725]=true, [4726]=true,
  [4728]=true, [4729]=true, [4732]=true, [4733]=true, [4739]=true, [4740]=true, [4756]=true,
  [4757]=true, [4767]=true, [4771]=true,
}

local function short_host(computer)
  return (string.match(computer or "", "^([^%.]+)") or computer or "")
end

function winevt(tag, ts, r)
  if r["lw_heartbeat"] then
    return 1, ts, {type = "heartbeat", hostname = os.getenv("COMPUTERNAME") or "?", Message = "fluent-bit alive"}
  end
  local id = tonumber(r["EventID"]) or 0
  local msg = r["Message"] or ""
  if r["Channel"] == "Security" then
    if id == 4624 then
      local lt = string.match(msg, "Logon Type:%s+(%d+)")
      if lt ~= "10" then return -1, ts, r end
      r["LogonType"] = lt
      r["TargetUserName"] = string.match(msg, "New Logon:.-Account Name:%s+([^\r\n]+)")
    elseif keep_security[id] then
      r["TargetUserName"] = string.match(msg, "Account For Which Logon Failed:.-Account Name:%s+([^\r\n]+)")
        or string.match(msg, "Target Account:.-Account Name:%s+([^\r\n]+)")
        or string.match(msg, "New Account:.-Account Name:%s+([^\r\n]+)")
    else
      return -1, ts, r
    end
  else
    -- System/Application: critical, error, warning only (Level 1-3).
    local lvl = tonumber(r["Level"]) or 4
    if lvl > 3 then return -1, ts, r end
  end
  r["type"] = "winevt"
  r["hostname"] = short_host(r["Computer"])
  return 1, ts, r
end

-- DNS debug log line, e.g.
-- 11/19/2026 3:57:27 PM 0E5C PACKET  000001F3D3C2B0D0 UDP Rcv 192.0.2.21       9f3e   Q [0001   D   NOERROR] A      (3)www(6)google(3)com(0)
function dns(tag, ts, r)
  local line = r["log"] or ""
  local client, qtype, qname = string.match(line, " Rcv (%S+)%s+%x+%s+Q %[.-%]%s+(%S+)%s+(%S+)%s*$")
  if not client then return -1, ts, r end
  qname = string.gsub(qname, "%(%d+%)", ".")
  qname = string.gsub(string.gsub(qname, "^%.", ""), "%.$", "")
  return 1, ts, {type = "dns", hostname = os.getenv("COMPUTERNAME") or "?", client = client, qtype = qtype, qname = qname}
end

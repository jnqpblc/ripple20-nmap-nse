local bin = require "bin"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local ipOps = require "ipOps"
local string = require "string"

local openssl = stdnse.silent_require "openssl"

local hIndex = openssl.md5(SCRIPT_NAME)
local try = nmap.new_try()
local pTimeout, ICMP_MS_SYNC_REQ, ICMP_MS_SYNC_RESP = 3, 165, 166

description = [[
Simple Ripple20 Detection Helper. 
Sends ICMP MS_SYNC_REQ and awaits for a ICMP MS_SYNC_RESP reponse. If positive, it will flag a possible Treck TCP/IP stack.

Cheers to Julio Fort (Blaze Security) for helping out.
Cheers also from CONVISO AppSecurity team for testing (conviso.com.br).

Sample packet:
        0x0000:  4500 0022 beef 0000 ff01 833e ac1e 116f  E..".......>...o
        0x0010:  ac1e 1001 a500 6e22 dead beef 7269 7070  ......n"....ripp
        0x0020:  6c65                                     le
]]

-- @usage
-- nmap -sn -T4 --script ripple20-icmp.nse -e eth0 [--script-args timeout=<secs>,retries=<n>]
--
-- @args ripple20-icmp.anonymize number should we randomize icmp payload (otherwise we will mark packets with 0xdeadbeef for diagnose purposes - default will anonymize)
-- @args ripple20-icmp.timeout number total time budget (in secs) to wait for icmp packets across retries (default 3 secs)
-- @args ripple20-icmp.retries number how many probe attempts to send per host (default 3)
--
-- @output
-- |_ripple20-icmp: Received ICMP MS_SYNC RESP for IP 172.30.16.1 -- possible Treck TCP/IP stack.
--
--

author = "Thiago Zaninotti (nstalker.com)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}

local print_table = function(t)
	for k,v in pairs(t) do
		stdnse.print_debug ( 1, " print_table() -> %s : %s", k,v)
	end
end

prerule = function()
	nmap.registry[hIndex] = nmap.is_privileged() and true or false
	stdnse.print_debug ( 1, " RIPPLE20 ICMP test ENABLED.")
	return false
end

hostrule = function(host)
	stdnse.print_debug ( 1, " Running RIPPLE20 ICMP test for %s", host.name)
	return true
end

action = function(host)
	-- sanity check (do I have root permission?)
	if ( host == nil or host.interface == nil or nmap.registry[hIndex] ~= true) then
		return false
	end

	local anon = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".anonymize")) or 1
	local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or pTimeout
	local retries = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".retries")) or 3
	timeout = timeout * 1000
	if (retries < 1) then retries = 1 end
	local perTryTimeout = math.floor(timeout / retries)
	if (perTryTimeout < 300) then perTryTimeout = 300 end

	local iInfo, output = nmap.get_interface_info(host.interface), nil
	if (iInfo == nil) then
		return false
	end
	local routed = (host.mac_addr == nil)
	local icmp = packet.Packet:new()

	if (iInfo.mac_addr ~= nil) then
		icmp.mac_src = iInfo.mac_addr
	end
	if (host.mac_addr ~= nil) then
		icmp.mac_dst = host.mac_addr
	end
	icmp.ip_p = 1 -- IPPROTO_ICMP
	icmp.ip_bin_src = ipOps.ip_to_str(iInfo.address)
	icmp.ip_bin_dst = ipOps.ip_to_str(host.ip)

	icmp.icmp = true
	icmp.icmp_type = ICMP_MS_SYNC_REQ
	icmp.icmp_code = 0

	if ( anon == 0) then	
		icmp.icmp_payload = packet.numtostr16(0xdead) .. packet.numtostr16(0xbeef) .. "ripple"
	else
		icmp.icmp_payload = openssl.rand_bytes(2) .. openssl.rand_bytes(2) .. openssl.rand_bytes(8)
	end

	icmp:build_icmp_header()
	icmp:build_ip_packet()
	
	local dnet = nmap.new_dnet()
	dnet:ip_open()

	local pcap = nmap.new_socket()
	pcap:set_timeout(perTryTimeout)
	local pcapFilter = string.format("icmp and src %s and icmp[0] = %d", host.ip, ICMP_MS_SYNC_RESP)
	stdnse.print_debug ( 1, "(timeout %d / retries %d) -> (%s) filter: %s", perTryTimeout, retries, iInfo.device, pcapFilter)
	pcap:pcap_open ( iInfo.device, 104, false, pcapFilter)
	if (routed) then
		stdnse.print_debug ( 1, "Target %s appears routed/non-local (host.mac_addr unavailable). Reliability may be reduced.", host.ip)
	end

	for attempt=1,retries do
		dnet:ip_send ( icmp.buf, host)
		local status, len, _, respdata, _ = pcap:pcap_receive()
		if ( status) then
			local response = packet.Packet:new ( respdata, len, false)
			if ( response:ip_parse() and response:icmp_parse() and response.icmp_type == ICMP_MS_SYNC_RESP) then
				stdnse.print_debug ( 1, "Found ----> IP %s | ICMP Type %d", response.ip_src, response.icmp_type)
				output = string.format ( "Received ICMP MS_SYNC RESP for IP %s -- possible Treck TCP/IP stack.", host.ip)
				break
			end
		end
		if (attempt < retries) then
			stdnse.sleep(0.1)
		end
	end

	if (output == nil and routed) then
		output = string.format("No ICMP MS_SYNC RESP for IP %s. Inconclusive on routed/non-local target.", host.ip)
	end

	pcap:pcap_close()
	dnet:ip_close()

	return output
end

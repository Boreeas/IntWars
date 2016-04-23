
enet = Proto("enet", "ENet LoL UDP Protocol")

MAX_ITEM_LABEL_LENGTH = 240
MIN_PORT = 5000
MAX_PORT = 6000

b64key = ""
b64keyfile = ""

package.cpath = package.cpath .. ";" .. USER_DIR .. "plugins\\enet\\?.dll"

require "blowfish"

command2string = {
	[0] = "NONE",
	[1] = "ACKNOWLEDGE",
	[2] = "handshakeECT",
	[3] = "VERIFY_handshakeECT",
	[4] = "DIShandshakeECT",
	[5] = "PING",
	[6] = "SEND_RELIABLE",
	[7] = "SEND_UNRELIABLE",
	[8] = "SEND_FRAGMENT",
	[9] = "SEND_UNSEQUENCED",
	[10] = "BANDWIDTH_LIMIT",
	[11] = "THROTTLE_CONFIGURE",
	[99] = "UNKNOWN COMMAND (THIS IS AN ERROR)",
}
--[[
checksum = ProtoField.new("Checksum", "enet.checksum", ftypes.UINT32)
flag_has_sent_time = ProtoField.new("'Sent Time'-Flag", "enet.flag_sent_time", ftypes.BOOLEAN)
peer_id = ProtoField.new("Peer Id", "enet.peer_id", ftypes.UINT16)
sent_time = ProtoField.new("Sent Time", "enet.sent_time", ftypes.UINT16)
seqnumber = ProtoField.new("Sequence number", "enet.seqnumber", ftypes.UINT16)
command = ProtoField.new("Command", "enet.command", ftypes.UINT8, command2string, base.DEC, 0x0f)
channel = ProtoField.new("ChannelID", "enet.channel", ftypes.UINT8)
proto_header = ProtoField.new("ENET Protocol Header", "enet.proto_header", ftypes.BYTES, nil, base.NONE)
header = ProtoField.new("ENET Command Header", "enet.header", ftypes.BYTES, nil, base.NONE)
data_length = ProtoField.new("Data length", "enet.data_length", ftypes.UINT16)
data = ProtoField.new("LoL Data", "enet.data", ftypes.BYTES)
data_decrypted = ProtoField.new("Decrypted Payload", "enet.data.decrypted", ftypes.BYTES)
key = ProtoField.new("LoL Game Key", "enet.key", ftypes.STRING)

ack = ProtoField.new("Acknowledge", "enet.acknowledge", ftypes.BYTES, nil, base.NONE)
ack_seqnum = ProtoField.new("Sequence Number", "enet.acknowledge.seqnum", ftypes.UINT16)
ack_recvtime = ProtoField.new("Received Time", "enet.acknowledge.recvtime", ftypes.UINT16)

handshake = ProtoField.new("handshakeect", "enet.handshakeect", ftypes.BYTES, nil, base.NONE)
verify_handshake = ProtoField.new("Verify handshakeect", "enet.verify_handshakeect", ftypes.BYTES, nil, base.NONE)
handshake_peerid = ProtoField.new("Outgoing Peer Id", "enet.handshakeect.peerid", ftypes.UINT16)
handshake_mtu = ProtoField.new("MTU", "enet.handshakeect.mtu", ftypes.UINT16)
handshake_window_size = ProtoField.new("Window Size", "enet.handshakeect.window_size", ftypes.UINT32)
handshake_channels = ProtoField.new("Channel Count", "enet.handshakeect.channels", ftypes.UINT32)
handshake_session_id = ProtoField.new("Session Id", "enet.handshakeect.session_id", ftypes.UINT32)

dc = ProtoField.new("Dishandshakeect", "enet.dishandshakeect", ftypes.BYTES, nil, base.NONE)
dc_data = ProtoField.new("Ping", "enet.dishandshakeect.data", ftypes.UINT32)

ping = ProtoField.new("Ping", "enet.ping", ftypes.BYTES, nil, base.NONE)

reliable = ProtoField.new("Send Reliable", "enet.reliable", ftypes.BYTES, nil, base.NONE)
unreliable = ProtoField.new("Send Unreliable", "enet.unreliable", ftypes.BYTES, nil, base.NONE)
fragment = ProtoField.new("Send Fragment", "enet.fragment", ftypes.BYTES, nil, base.NONE)
unsequenced = ProtoField.new("Send Unsequenced", "enet.unsequenced", ftypes.BYTES, nil, base.NONE)
payload_length = ProtoField.new("Payload Length", "enet.payload.length", ftypes.UINT16)
payload = ProtoField.new("Payload", "enet.payload", ftypes.BYTES, nil, base.NONE)
unreliable_seqnum = ProtoField.new("Unreliable Sequence Number", "enet.unreliable.seqnum", ftypes.UINT16)

fragment_startseqnum = ProtoField.new("Fragment Start Number", "enet.fragment.startseqnum", ftypes.UINT16)
fragment_fragcount = ProtoField.new("Fragment Count", "enet.fragment.count", ftypes.UINT32)
fragment_fragnum = ProtoField.new("Fragment Number", "enet.fragment.num", ftypes.UINT32)
fragment_total_length = ProtoField.new("Total Length", "enet.fragment.length", ftypes.UINT32)
fragment_offset = ProtoField.new("Offset", "enet.fragment.offset", ftypes.UINT32)

unsequenced_group = ProtoField.new("Unsequenced Group", "enet.unsequenced.group", ftypes.UINT16)

bandwidth_limit = ProtoField.new("Bandwidth Limit", "enet.bandwidth_limit", ftypes.BYTES, nil, base.NONE)
bandwidth_incoming_bandwidth = ProtoField.new("Incoming Bandwidth", "enet.bandwidth_limit.incoming_bandwidth", ftypes.UINT32)
bandwidth_outgoing_bandwidth = ProtoField.new("Outgoing Bandwidth", "enet.bandwidth_limit.outgoing_bandwidth", ftypes.UINT32)

packet_throttle = ProtoField.new("Packet Throttle", "enet.packet_throttle", ftypes.BYTES, nil, base.NONE)
throttle_throttle_interval = ProtoField.new("Packet Throttle Interval", "enet.handshakeect.throttle_interval", ftypes.UINT32)
throttle_throttle_accel = ProtoField.new("Packet Throttle Acceleration", "enet.handshakeect.throttle_accel", ftypes.UINT32)
throttle_throttle_decel = ProtoField.new("Packet Throttle Deceleration", "enet.handshakeect.throttle_decel", ftypes.UINT32)


enet.fields = {
	checksum,
	flag_has_sent_time,
	peer_id,
	sent_time,
	seqnumber,
	command,
	channel,
	proto_header,
	header,
	data_length,
	data,
	data_decrypted,
	key,

	ack,
	ack_seqnum,
	ack_recvtime,

	handshake,
	verify_handshake,
	handshake_peerid,
	handshake_mtu,
	handshake_window_size,
	handshake_channels,
	bandwidth_incoming_bandwidth,
	bandwidth_outgoing_bandwidth,
	throttle_throttle_interval,
	throttle_throttle_accel,
	throttle_throttle_decel,
	handshake_session_id,

	dc,
	dc_data,

	ping,

	reliable,
	unreliable,
	fragment,
	unsequenced,

	payload_length,
	payload,

	unreliable_seqnum,

	fragment_startseqnum,
	fragment_fragcount,
	fragment_fragnum,
	fragment_total_length,
	fragment_offset,

	packet_throttle,
	bandwidth_limit,

	unsequenced_group
}
--]]

pkt_type_names = {
	[0x01] = "Acknowledge",
	[0x02] = "Connect",
	[0x03] = "Verify Connect",
	[0x04] = "Disconnect",
	[0x05] = "Ping",
	[0x06] = "Reliable Transmission",
	[0x07] = "Unreliable Transmission",
	[0x08] = "Transmission Fragment",
	[0x09] = "Unsequenced Transmission",
	[0x0a] = "Bandwidth Limit",
	[0x0b] = "Throttle Configure"
}

vs_truefalse = {
	[0] = "False",
	[1] = "True"
}

local fields = enet.fields
fields.header = ProtoField.new("ENet Header", "enet.header", ftypes.BYTES, nil, base.NONE)
fields.header_field1 = ProtoField.new("?Peer ID/Checksum?", "enet.header.1", ftypes.UINT32)
fields.header_field2 = ProtoField.new("Unknown Field 2 (???)", "enet.header.2", ftypes.UINT32)
fields.header_flags = ProtoField.new("Flags", "enet.header.flags", ftypes.UINT16, nil, base.HEX)
fields.header_flags_1 = ProtoField.new("Unknown Flag 1 (never)", "enet.header.flags.1", ftypes.UINT16, nil, base.DEC, 0x8000)
fields.header_flags_2 = ProtoField.new("Unknown Flag 2 (never)", "enet.header.flags.2", ftypes.UINT16, nil, base.DEC, 0x4000)
fields.header_flags_3 = ProtoField.new("Unknown Flag 3 (always)", "enet.header.flags.3", ftypes.UINT16, nil, base.DEC, 0x2000)
fields.header_flags_4 = ProtoField.new("Unknown Flag 4 (never)", "enet.header.flags.4", ftypes.UINT16, nil, base.DEC, 0x1000)
fields.header_flags_5 = ProtoField.new("Unknown Flag 5 (always)", "enet.header.flags.5", ftypes.UINT16, nil, base.DEC, 0x800)
fields.header_flags_6 = ProtoField.new("Unknown Flag 6 (never)", "enet.header.flags.6", ftypes.UINT16, nil, base.DEC, 0x400)
fields.header_flags_7 = ProtoField.new("Unknown Flag 7 (never)", "enet.header.flags.7", ftypes.UINT16, nil, base.DEC, 0x200)
fields.header_flags_8 = ProtoField.new("Unknown Flag 8 (always)", "enet.header.flags.8", ftypes.UINT16, nil, base.DEC, 0x100)
fields.header_flags_timestamped = ProtoField.new("Includes Timestamp", "enet.header.flags.timestamped", ftypes.UINT16, nil, base.DEC, 0x80)
fields.header_flags_10 = ProtoField.new("Unknown Flag 10 (handshake)", "enet.header.flags.10", ftypes.UINT16, nil, base.DEC, 0x40)
fields.header_flags_11 = ProtoField.new("Unknown Flag 11 (handshake)", "enet.header.flags.11", ftypes.UINT16, nil, base.DEC, 0x20)
fields.header_flags_12 = ProtoField.new("Unknown Flag 12 (handshake)", "enet.header.flags.12", ftypes.UINT16, nil, base.DEC, 0x10)
fields.header_flags_13 = ProtoField.new("Unknown Flag 13 (handshake)", "enet.header.flags.13", ftypes.UINT16, nil, base.DEC, 0x8)
fields.header_flags_14 = ProtoField.new("Unknown Flag 14 (handshake)", "enet.header.flags.14", ftypes.UINT16, nil, base.DEC, 0x4)
fields.header_flags_15 = ProtoField.new("Unknown Flag 15 (handshake)", "enet.header.flags.15", ftypes.UINT16, nil, base.DEC, 0x2)
fields.header_flags_16 = ProtoField.new("Unknown Flag 16 (handshake)", "enet.header.flags.16", ftypes.UINT16, nil, base.DEC, 0x1)
fields.header_time = ProtoField.new("Time", "enet.header.time", ftypes.UINT16)
fields.header_type_and_flags = ProtoField.new("Type / ACK flag", "enet.header.type_flags", ftypes.UINT8, nil, base.HEX)
fields.header_type = ProtoField.new("Type", "enet.type", ftypes.UINT8, pkt_type_names, base.DEC, 0x0f)
fields.header_flag_acknowledge = ProtoField.new("Acknowledge", "enet.header.flags.acknowledge", ftypes.UINT8, {"Required", "Not Required"}, base.DEC, 0x80)
fields.header_flag_17 = ProtoField.new("Unknown Flag 17", "enet.header.flags.17", ftypes.UINT8, nil, base.DEC, 0x40)
fields.header_flag_18 = ProtoField.new("Unknown Flag 18", "enet.header.flags.18", ftypes.UINT8, nil, base.DEC, 0x20)
fields.header_flag_19 = ProtoField.new("Unknown Flag 19", "enet.header.flags.19", ftypes.UINT8, nil, base.DEC, 0x10)
fields.header_field3 = ProtoField.new("Channel", "enet.channel", ftypes.UINT8, nil, base.HEX)
fields.header_field4 = ProtoField.new("Reliable Sequence Number", "enet.seqnum", ftypes.UINT16)

fields.handshake = ProtoField.new("Handshake", "enet.handshake", ftypes.BYTES, nil, base.NONE)
fields.handshake_field3 = ProtoField.new("?Outgoing Peer Id?", "enet.handshake.3", ftypes.BYTES)
fields.handshake_mtu = ProtoField.new("MTU", "enet.handshake.mtu", ftypes.UINT16)
fields.handshake_window_size = ProtoField.new("Window Size", "enet.handshake.winsize", ftypes.UINT32)
fields.handshake_channels = ProtoField.new("Channels", "enet.handshake.channels", ftypes.UINT32)
fields.handshake_incoming_bandwidth = ProtoField.new("Incoming Bandwidth", "enet.handshake.incoming_bandwidth", ftypes.UINT32)
fields.handshake_outgoing_bandwidth = ProtoField.new("Outgoing Bandwidth", "enet.handshake.outgoing_bandwidth", ftypes.UINT32)
fields.handshake_packet_loss_tracking_window = ProtoField.new("Packet loss tracking window", "enet.handshake.pktloss_tracking", ftypes.UINT32)
fields.handshake_throttle_accel = ProtoField.new("Throttle Acceleration", "enet.handshake.throttle_accel", ftypes.UINT32)
fields.handshake_throttle_decel = ProtoField.new("Throttle Deceleration", "enet.handshake.throttle_decel", ftypes.UINT32)
fields.handshake_field4 = ProtoField.new("?Session id?", "enet.handshake.4", ftypes.UINT32)

fields.ack = ProtoField.new("Acknowledge", "enet.ack", ftypes.BYTES, nil, base.NONE)
fields.ack_seqnum = ProtoField.new("Sequence Number", "enet.ack.seqnum", ftypes.UINT16)
fields.ack_recvtime = ProtoField.new("Time Received (Shifted by 2 seconds?)", "enet.ack.recvtime", ftypes.UINT16)

fields.verify_handshake = ProtoField.new("Verify Handshake", "enet.handshake", ftypes.BYTES, nil, base.NONE)

fields.dc = ProtoField.new("Disconnect", "enet.disconnect", ftypes.BYTES, nil, base.NONE)
fields.dc_data = ProtoField.new("Data", "enet.disconnect.data", ftypes.UINT32, nil, base.HEX)

fields.ping = ProtoField.new("Ping", "enet.ping", ftypes.BYTES, nil, base.NONE)

fields.reliable = ProtoField.new("Reliable Transmission", "enet.reliable", ftypes.BYTES, nil, base.NONE)
fields.payload_length = ProtoField.new("Payload Length", "enet.payload_length", ftypes.UINT16)

fields.unreliable = ProtoField.new("Unreliable Transmission", "enet.unreliable", ftypes.BYTES, nil, base.NONE)
fields.unreliable_seqnum = ProtoField.new("Unreliable Sequence Number", "enet.unreliable.seqnum", ftypes.UINT16)

fields.fragment = ProtoField.new("Transmission Fragment", "enet.fragment", ftypes.BYTES, nil, base.NONE)
fields.fragment_startseqnum = ProtoField.new("Initial Sequence Number", "enet.fragment.initseqnum", ftypes.UINT16)
fields.fragment_fragcount = ProtoField.new("Fragment Count", "enet.fragment.count", ftypes.UINT32)
fields.fragment_fragnum = ProtoField.new("Fragment Number", "enet.fragment.num", ftypes.UINT32)
fields.fragment_total_length = ProtoField.new("Total Length", "enet.fragment.length", ftypes.UINT32)
fields.fragment_offset = ProtoField.new("Offset Into Packet", "enet.fragment.offset", ftypes.UINT32)
fields.payload = ProtoField.new("Payload", "enet.payload", ftypes.BYTES, nil, base.NONE)

fields.unsequenced = ProtoField.new("Unsequenced Transmission", "enet.unsequenced", ftypes.BYTES, nil, base.NONE)
fields.unsequenced_group = ProtoField.new("Group", "enet.unsequenced.group", ftypes.UINT16)

fields.bandwidth_limit = ProtoField.new("Bandwidth Limit", "enet.bandwidth_limit", ftypes.BYTES, nil, base.NONE)
fields.packet_throttle = ProtoField.new("Throttle Configure", "enet.throttle", ftypes.BYTES, nil, base.NONE)

fields.unknown = ProtoField.new("Unknown Packet", "enet.debug.unknown", ftypes.BYTES, nil, base.NONE)
fields.potentially_decrypted = ProtoField.new("Unknown Packet (Maybe encrypted)", "enet.debug.decrypted", ftypes.BYTES, nil, base.NONE)
fields.potentially_decrypted_length = ProtoField.new("Length", "enet.debug.decrypted.length", ftypes.UINT32)
fields.potentially_decrypted_payload = ProtoField.new("Payload", "enet.debug.decrypted.payload", ftypes.BYTES, nil, base.NONE)
fields.keyinfo = ProtoField.new("Key", "enet.debug.key", ftypes.STRING)

lolcmds = {
	[0x00] = "KeyCheck",
	[0x0b] = "RemoveItem",
	
	[0x11] = "S2C_EndSpawn",
	[0x14] = "C2S_QueryStatusReq",
	[0x15] = "S2C_SkillUp",
	[0x16] = "C2S_Ping_Load_Info",
	[0x1A] = "S2C_AutoAttack",
	
	[0x20] = "C2S_SwapItems",
	[0x23] = "S2C_FogUpdate2",
	[0x2A] = "S2C_PlayerInfo",
	[0x2C] = "S2C_ViewAns",
	[0x2E] = "C2S_ViewReq",
	
	[0x39] = "C2S_SkillUp",
	[0x3B] = "S2C_SpawnProjectile",
	[0x3E] = "S2C_SwapItems",
	[0x3F] = "S2C_LevelUp",
	
	[0x40] = "S2C_AttentionPing",
	[0x42] = "S2C_Emotion",
	[0x48] = "C2S_Emotion",
	[0x4C] = "S2C_HeroSpawn",
	[0x4D] = "S2C_Announce",
	
	[0x52] = "C2S_StartGame",
	[0x54] = "S2C_SynchVersion",
	[0x56] = "C2S_ScoreBord",
	[0x57] = "C2S_AttentionPing",
	[0x5A] = "S2C_DestroyProjectile",
	[0x5C] = "C2S_StartGame",
	
	[0x62] = "S2C_StartSpawn",
	[0x64] = "C2S_ClientReady",
	[0x65] = "S2C_LoadHero",
	[0x66] = "S2C_LoadName",
	[0x67] = "S2C_LoadScreenInfo",
	[0x68] = "ChatBoxMessage",
	[0x6A] = "S2C_SetTarget",
	[0x6F] = "S2C_BuyItemAns",
	
	[0x72] = "C2S_MoveReq",
	[0x77] = "C2S_MoveConfirm",
	
	[0x81] = "C2S_LockCamera",
	[0x82] = "C2S_BuyItemReq",
	[0x87] = "S2C_SpawnParticle",
	[0x88] = "S2C_QueryStatusAns",
	[0x8F] = "C2S_Exit",
	
	[0x92] = "SendGameNumber",
	[0x95] = "S2C_Ping_Load_Info",
	[0x9A] = "C2S_CastSpell",
	[0x9D] = "S2C_TurretSpawn",
	
	[0xA4] = "C2S_Surrender",
	[0xA8] = "C2S_StatsConfirm",
	[0xAE] = "S2C_SetHealth",
	[0xAF] = "C2S_Click",
	
	[0xB5] = "S2C_CastSpellAns",
	[0xBA] = "S2C_MinionSpawn",
	[0xBD] = "C2S_SynchVersion",
	[0xBE] = "C2S_CharLoaded",
	
	[0xC0] = "S2C_GameTimer",
	[0xC1] = "S2C_GameTimerUpdate",
	[0xC4] = "S2C_CharStats",
	
	[0xD0] = "S2C_LevelPropSpawn",
	
	[0xFF] = "Batch"
}

--[[
	the core dissector:
	tvbuf -> Tvb object
	pktinfo -> Pinfo object
	root -> TreeItem object 
--]]
function enet.dissector(tvbuf, pktinfo, root)

	pktinfo.cols.protocol = "ENet"
	
	local pktlen = tvbuf:reported_length_remaining()
	local tree = root:add(enet, tvbuf:range(0,pktlen))
	
	local headerlen = 14
	local has_timestamp = tvbuf:range(8,2):bitfield(8,1) == 1
	if has_timestamp then
		headerlen = headerlen + 2
	end

	local pheader = tvbuf:range(0, headerlen)
	local pheader_buf = pheader:tvb()

	local proto_header = tree:add(fields.header, pheader)
	proto_header:set_text("ENet Header")
	proto_header:add(fields.header_field1, pheader_buf:range(0,4))
	proto_header:add(fields.header_field2, pheader_buf:range(4,4))
	
	local hflagsbuf = pheader_buf:range(8,2)
	local header_flags = proto_header:add(fields.header_flags, hflagsbuf)
	header_flags:add(fields.header_flags_1, hflagsbuf)
	header_flags:add(fields.header_flags_2, hflagsbuf)
	header_flags:add(fields.header_flags_3, hflagsbuf)
	header_flags:add(fields.header_flags_4, hflagsbuf)
	header_flags:add(fields.header_flags_5, hflagsbuf)
	header_flags:add(fields.header_flags_6, hflagsbuf)
	header_flags:add(fields.header_flags_7, hflagsbuf)
	header_flags:add(fields.header_flags_8, hflagsbuf)
	header_flags:add(fields.header_flags_timestamped, hflagsbuf)
	header_flags:add(fields.header_flags_10, hflagsbuf)
	header_flags:add(fields.header_flags_11, hflagsbuf)
	header_flags:add(fields.header_flags_12, hflagsbuf)
	header_flags:add(fields.header_flags_13, hflagsbuf)
	header_flags:add(fields.header_flags_14, hflagsbuf)
	header_flags:add(fields.header_flags_15, hflagsbuf)
	header_flags:add(fields.header_flags_16, hflagsbuf)

	local current_offset = 10

	if has_timestamp then
		proto_header:add(fields.header_time, pheader_buf:range(10,2))
		current_offset = current_offset + 2
	end

	local type_and_ack_flag = pheader_buf:range(current_offset,1)
	local tree_type_ack = proto_header:add(fields.header_type_and_flags, type_and_ack_flag)
	tree_type_ack:set_text("Type / ACK Flag")
	tree_type_ack:add(fields.header_flag_acknowledge, type_and_ack_flag)
	tree_type_ack:add(fields.header_flag_17, type_and_ack_flag)
	tree_type_ack:add(fields.header_flag_18, type_and_ack_flag)
	tree_type_ack:add(fields.header_flag_19, type_and_ack_flag)
	tree_type_ack:add(fields.header_type, type_and_ack_flag)

	local pkt_type = type_and_ack_flag:bitfield(1,7)
	if pkt_type_names[pkt_type] ~= nil then
		tree:set_text("ENet: " .. pkt_type_names[pkt_type])
		pktinfo.cols.info:set(pkt_type_names[pkt_type])
	else
		tree:set_text("ENet: Unknown Packet")
	end

	proto_header:add(fields.header_field3, pheader_buf:range(current_offset+1, 1))
	proto_header:add(fields.header_field4, pheader_buf:range(current_offset+2, 2))

	local pktbuf = tvbuf:range(headerlen)
	if pkt_type == 1 then
		parse_acknowledge(pktbuf, tree:add(fields.ack, pktbuf))
	elseif pkt_type == 2 then
		parse_connect(pktbuf, tree:add(fields.handshake, pktbuf))		
	elseif pkt_type == 3 then
		parse_verify_connect(pktbuf, tree:add(fields.verify_handshake, pktbuf))
	elseif pkt_type == 4 then
		parse_disconnect(pktbuf, tree:add(fields.disconnect, pktbuf))
	elseif pkt_type == 5 then
		--parse_ping(pktbuf, tree:add(fields.ping, pktbuf))
	elseif pkt_type == 6 then
		parse_reliable(pktbuf, tree:add(fields.reliable, pktbuf), pktinfo, root)
	elseif pkt_type == 7 then
		parse_unreliable(pktbuf, tree:add(fields.unreliable, pktbuf), pktinfo, root)
	elseif pkt_type == 8 then
		parse_fragment(pktbuf, tree:add(fields.fragment, pktbuf), pktinfo)
	elseif pkt_type == 9 then
		parse_unsequenced(pktbuf, tree:add(fields.unsequenced, pktbuf), pktinfo, root)	
	elseif pkt_type == 10 then
		parse_bandwidth_limit(pktbuf, tree:add(fields.bandwidth_limit, pktbuf))
	elseif pkt_type == 11 then
		parse_packet_throttle(pktbuf, tree:add(fields.packet_throttle, pkt_type))
	end
end


function decode_payload(tvrange, tree, pktinfo)
	local tvbuf = tvrange:tvb()

	local loltree = tree:add(fields.potentially_decrypted, tvrange)
	loltree:set_text("Decrypted Payload (Note that we might be decrypting too soon here)")
	
	if b64key == "" then
		loltree:add(keyinfo, "No key found" .. " (" .. b64keyfile .. ")")
		return
	end
	
	loltree:add(keyinfo, b64key .. " (" .. b64keyfile .. ")")

	local data_length = tvbuf:len()
	loltree:add(fields.potentially_decrypted_length, data_length)
	
	local data_tmp = {}
	for i=0, data_length-1 do
		data_tmp[i] = tvbuf:range(i, 1):uint()
	end
	
	local decryptedData = bf_Decrypt(data_tmp, data_length)
	
	local decryptedByteArray = ByteArray.new()
	decryptedByteArray:set_size(data_length)
	for i=0, data_length-1 do
		decryptedByteArray:set_index(i, decryptedData[i])
	end

	local decrypted_tvb = ByteArray.tvb(decryptedByteArray, "Decrypted tvb")
	loltree:add(fields.potentially_decrypted_payload, decrypted_tvb:range(0, decrypted_tvb:reported_length_remaining()))
end


function parse_acknowledge(tvbuf, tree)
	tree:set_text("Acknowledge")
	tree:add(fields.ack_seqnum, tvbuf:range(0, 2))
	tree:add(fields.ack_recvtime, tvbuf:range(2, 2))
end


function parse_connect(tvbuf, tree)
	tree:set_text("Connect")
	tree:add(fields.handshake_field3, tvbuf:range(0,2))
	tree:add(fields.handshake_mtu, tvbuf:range(2,2))
	tree:add(fields.handshake_window_size, tvbuf:range(4,4))
	tree:add(fields.handshake_channels, tvbuf:range(8,4))
	tree:add(fields.handshake_incoming_bandwidth, tvbuf:range(12,4))
	tree:add(fields.handshake_outgoing_bandwidth, tvbuf:range(16,4))
	tree:add(fields.handshake_packet_loss_tracking_window, tvbuf:range(20,4))
	tree:add(fields.handshake_throttle_accel, tvbuf:range(24,4))
	tree:add(fields.handshake_throttle_decel, tvbuf:range(28,4))
	tree:add(fields.handshake_field4, tvbuf:range(32,4))
end


function parse_verify_connect(tvbuf, tree)
	tree:set_text("Verify Connect")
	tree:add(fields.handshake_field3, tvbuf:range(0, 2))
	tree:add(fields.handshake_mtu, tvbuf:range(2, 2))
	tree:add(fields.handshake_window_size, tvbuf:range(4, 4))
	tree:add(fields.handshake_channels, tvbuf:range(8, 4))
	tree:add(fields.handshake_incoming_bandwidth, tvbuf:range(12, 4))
	tree:add(fields.handshake_outgoing_bandwidth, tvbuf:range(16, 4))
	tree:add(fields.handshake_packet_loss_tracking_window, tvbuf:range(20, 4))
	tree:add(fields.handshake_throttle_accel, tvbuf:range(24, 4))
	tree:add(fields.handshake_throttle_decel, tvbuf:range(28, 4))
end


function parse_disconnect(tvbuf, tree)
	tree:set_text("Disconnect")
	tree:add(fields.dc_data, tvbuf:range(0, 4))
end

function parse_ping(tvbuf, tree)
	tree:set_text("Ping")
end

function parse_reliable(tvbuf, tree, pktinfo, root)
	tree:set_text("Reliable Transmission")
	tree:add(fields.payload_length, tvbuf:range(0, 2))
	decode_payload(tvbuf:range(2), root, pktinfo)
end

function parse_unreliable(tvbuf, tree, pktinfo, root)
	tree:set_text("Unreliable Transmission")
	pktinfo.cols.info:append(" (#" .. tvbuf:range(0,2):uint() .. ")")
	tree:add(fields.unreliable_seqnum, tvbuf:range(0, 2))
	tree:add(fields.payload_length, tvbuf:range(2, 2))
	decode_payload(tvbuf:range(4), root, pktinfo)
end

function parse_fragment(tvbuf, tree, pktinfo)
	tree:set_text("Transmission Fragment")
	pktinfo.cols.info.append(" (" .. tvbuf:range(8,4):uint() .. " of " .. tvbuf:range(4,4) .. ")")
	tree:add(fields.fragment_startseqnum, tvbuf:range(0, 2))
	tree:add(fields.payload_length, tvbuf:range(2, 2))
	tree:add(fields.fragment_fragcount, tvbuf:range(4, 4))
	tree:add(fields.fragment_fragnum, tvbuf:range(8, 4))
	tree:add(fields.fragment_total_length, tvbuf:range(12, 4))
	tree:add(fields.fragment_offset, tvbuf:range(16, 4))
	tree:add(fields.fragment_payload, tvbuf:range(20))
end

function parse_unsequenced(tvbuf, tree, pktinfo, root)
	tree:set_text("Unsequenced Transmission")
	pktinfo.cols.info.append(" (Group: " .. tvbuf:range(0,2):uint() .. ")")
	tree:add(fields.unsequenced_group, tvbuf:range(0, 2))
	tree:add(fields.payload_length, tvbuf:range(2, 2))
	tree:add(fields.payload, tvbuf:range(4))
	decode_payload(tvbuf.range(4), root, pktinfo)
end

function parse_bandwidth_limit(tvbuf, tree)
	tree:set_text("Bandwidth Limit")
	tree:add(fields.handshake_incoming_bandwidth, tvbuf:range(0, 4))
	tree:add(fields.handshake_outgoing_bandwidth, tvbuf:range(4, 4))
end

function parse_packet_throttle(tvbuf, tree)
	tree:set_text("Packet Throttle")
	tree:add(fields.handshake_packet_loss_tracking_window, tvbuf:range(0, 4))
	tree:add(fields.handshake_throttle_accel, tvbuf:range(4, 4))
	tree:add(fields.handshake_throttle_decel, tvbuf:range(8, 4))
end



-- load the udp.port table
-- udp_table = DissectorTable.get("udp.port")

-- register our protocol to handle one specific udp port
-- udp_table:add(5100, enet)

--[[
	a heuristic to decide if the ENET dissector should handle the data
	sadly its broken, u cannot return true here (wireshark.exe crashes, tshark.exe is doing fine!)
	but if you set the enet protocol for the rest of the conversation and return false,
	somehow it works as intended
--]]
function heur_dissect_enet(tvbuf, pktinfo, root)
	print("heur_dissect_enet")
	
	tvbr = tvbuf:range(0,1)
	if tvbr:uint() == 41 then
		print("found the first byte to be 0x29 (dec: 41), its ENET")
	else
		if pktinfo.src_port > MIN_PORT and pktinfo.src_port < MAX_PORT then

		else
			if pktinfo.dst_port > MIN_PORT and pktinfo.dst_port < MAX_PORT then

			else
				return false
			end
		end
	end
	
	-- generate a filename/identifier for this capture
	-- wireshark doesnt provide the .pcap filename in LUA (why?)
	-- one cannot add data to the capture file
	-- only other approach would be using Prefs :/
	
	-- data for id: absolute time of capture, server port, server adress
	
	--print(pktinfo.abs_ts)
	--print(pktinfo.src)
	--print(pktinfo.dst)
	
	id_port = 0
	if pktinfo.src_port > MIN_PORT and pktinfo.src_port < MAX_PORT then
		id_port = pktinfo.src_port
	end
	if pktinfo.dst_port > MIN_PORT and pktinfo.dst_port < MAX_PORT then
		id_port = pktinfo.dst_port
	end
	print("id_port ".. id_port)
	
	
	-- YYYY_MM_DD-hh_mm
	id_date = os.date("%Y_%m_%d-%H_%M", math.floor(pktinfo.abs_ts))
	print("id_date" .. id_date)
	
	filename = USER_DIR .. "plugins\\lolkeys\\" .. id_date .. "-" .. id_port .. ".txt"
	
	b64key = ""
	b64keyfile = ""
	content = ""
	file = io.open(filename, "r")
	if file~=nil then
		content = file:read("*all")
		print("Content: " .. content)
		io.close(file)
		b64keyfile = filename
	else
		print("error opening file ".. filename)
		file = io.open(filename, "w")
		if file~=nil then
			file:write("")
			io.close(file)
			b64keyfile = filename
		else
			print("error creating file ".. filename)
			b64keyfile = "Error, could not create " .. filename
		end
	end
	
	if string.len(content) == 24 and string.match(content, "[a-zA-Z0-9%+/]+==") ~= nil then
		print("Valid Key found")
		b64key = content
		b64keyfile = filename
	else
		cmdstring = "cscript.exe /nologo " .. USER_DIR .. "plugins\\GetLoLGameHash.vbs"
		handle = io.popen(cmdstring , "r")
		output = handle:read('*all')
		handle:close()
		print("Output from " .. cmdstring .. ": " .. output)
		if string.len(output) == 24 and string.match(output, "[a-zA-Z0-9%+/]+==") ~= nil then
			print("Valid Key found")
			b64key = output
			b64keyfile = cmdstring
			file = io.open(filename, "w")
			if file~=nil then
				file:write(output)
				io.close(file)
			else
				print("error creating file ".. filename)
			end
		end
	end
	
	bf_Init(b64key)
	
	enet.dissector(tvbuf, pktinfo, root)
	pktinfo.conversation = enet
	
	return false -- yeah just return always false .....
end

-- register the heuristic for udp only:
enet:register_heuristic("udp", heur_dissect_enet)
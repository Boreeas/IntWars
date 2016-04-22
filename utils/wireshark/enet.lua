
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
pf_checksum = ProtoField.new("Checksum", "enet.checksum", ftypes.UINT32)
pf_flag_has_sent_time = ProtoField.new("'Sent Time'-Flag", "enet.flag_sent_time", ftypes.BOOLEAN)
pf_peer_id = ProtoField.new("Peer Id", "enet.peer_id", ftypes.UINT16)
pf_sent_time = ProtoField.new("Sent Time", "enet.sent_time", ftypes.UINT16)
pf_seqnumber = ProtoField.new("Sequence number", "enet.seqnumber", ftypes.UINT16)
pf_command = ProtoField.new("Command", "enet.command", ftypes.UINT8, command2string, base.DEC, 0x0f)
pf_channel = ProtoField.new("ChannelID", "enet.channel", ftypes.UINT8)
pf_proto_header = ProtoField.new("ENET Protocol Header", "enet.proto_header", ftypes.BYTES, nil, base.NONE)
pf_header = ProtoField.new("ENET Command Header", "enet.header", ftypes.BYTES, nil, base.NONE)
pf_data_length = ProtoField.new("Data length", "enet.data_length", ftypes.UINT16)
pf_data = ProtoField.new("LoL Data", "enet.data", ftypes.BYTES)
pf_data_decrypted = ProtoField.new("Decrypted Payload", "enet.data.decrypted", ftypes.BYTES)
pf_key = ProtoField.new("LoL Game Key", "enet.key", ftypes.STRING)

pf_ack = ProtoField.new("Acknowledge", "enet.acknowledge", ftypes.BYTES, nil, base.NONE)
pf_ack_seqnum = ProtoField.new("Sequence Number", "enet.acknowledge.seqnum", ftypes.UINT16)
pf_ack_recvtime = ProtoField.new("Received Time", "enet.acknowledge.recvtime", ftypes.UINT16)

pf_handshake = ProtoField.new("handshakeect", "enet.handshakeect", ftypes.BYTES, nil, base.NONE)
pf_verify_handshake = ProtoField.new("Verify handshakeect", "enet.verify_handshakeect", ftypes.BYTES, nil, base.NONE)
pf_handshake_peerid = ProtoField.new("Outgoing Peer Id", "enet.handshakeect.peerid", ftypes.UINT16)
pf_handshake_mtu = ProtoField.new("MTU", "enet.handshakeect.mtu", ftypes.UINT16)
pf_handshake_window_size = ProtoField.new("Window Size", "enet.handshakeect.window_size", ftypes.UINT32)
pf_handshake_channels = ProtoField.new("Channel Count", "enet.handshakeect.channels", ftypes.UINT32)
pf_handshake_session_id = ProtoField.new("Session Id", "enet.handshakeect.session_id", ftypes.UINT32)

pf_dc = ProtoField.new("Dishandshakeect", "enet.dishandshakeect", ftypes.BYTES, nil, base.NONE)
pf_dc_data = ProtoField.new("Ping", "enet.dishandshakeect.data", ftypes.UINT32)

pf_ping = ProtoField.new("Ping", "enet.ping", ftypes.BYTES, nil, base.NONE)

pf_reliable = ProtoField.new("Send Reliable", "enet.reliable", ftypes.BYTES, nil, base.NONE)
pf_unreliable = ProtoField.new("Send Unreliable", "enet.unreliable", ftypes.BYTES, nil, base.NONE)
pf_fragment = ProtoField.new("Send Fragment", "enet.fragment", ftypes.BYTES, nil, base.NONE)
pf_unsequenced = ProtoField.new("Send Unsequenced", "enet.unsequenced", ftypes.BYTES, nil, base.NONE)
pf_payload_length = ProtoField.new("Payload Length", "enet.payload.length", ftypes.UINT16)
pf_payload = ProtoField.new("Payload", "enet.payload", ftypes.BYTES, nil, base.NONE)
pf_unreliable_seqnum = ProtoField.new("Unreliable Sequence Number", "enet.unreliable.seqnum", ftypes.UINT16)

pf_fragment_startseqnum = ProtoField.new("Fragment Start Number", "enet.fragment.startseqnum", ftypes.UINT16)
pf_fragment_fragcount = ProtoField.new("Fragment Count", "enet.fragment.count", ftypes.UINT32)
pf_fragment_fragnum = ProtoField.new("Fragment Number", "enet.fragment.num", ftypes.UINT32)
pf_fragment_total_length = ProtoField.new("Total Length", "enet.fragment.length", ftypes.UINT32)
pf_fragment_offset = ProtoField.new("Offset", "enet.fragment.offset", ftypes.UINT32)

pf_unsequenced_group = ProtoField.new("Unsequenced Group", "enet.unsequenced.group", ftypes.UINT16)

pf_bandwidth_limit = ProtoField.new("Bandwidth Limit", "enet.bandwidth_limit", ftypes.BYTES, nil, base.NONE)
pf_bandwidth_incoming_bandwidth = ProtoField.new("Incoming Bandwidth", "enet.bandwidth_limit.incoming_bandwidth", ftypes.UINT32)
pf_bandwidth_outgoing_bandwidth = ProtoField.new("Outgoing Bandwidth", "enet.bandwidth_limit.outgoing_bandwidth", ftypes.UINT32)

pf_packet_throttle = ProtoField.new("Packet Throttle", "enet.packet_throttle", ftypes.BYTES, nil, base.NONE)
pf_throttle_throttle_interval = ProtoField.new("Packet Throttle Interval", "enet.handshakeect.throttle_interval", ftypes.UINT32)
pf_throttle_throttle_accel = ProtoField.new("Packet Throttle Acceleration", "enet.handshakeect.throttle_accel", ftypes.UINT32)
pf_throttle_throttle_decel = ProtoField.new("Packet Throttle Deceleration", "enet.handshakeect.throttle_decel", ftypes.UINT32)


enet.fields = {
	pf_checksum,
	pf_flag_has_sent_time,
	pf_peer_id,
	pf_sent_time,
	pf_seqnumber,
	pf_command,
	pf_channel,
	pf_proto_header,
	pf_header,
	pf_data_length,
	pf_data,
	pf_data_decrypted,
	pf_key,

	pf_ack,
	pf_ack_seqnum,
	pf_ack_recvtime,

	pf_handshake,
	pf_verify_handshake,
	pf_handshake_peerid,
	pf_handshake_mtu,
	pf_handshake_window_size,
	pf_handshake_channels,
	pf_bandwidth_incoming_bandwidth,
	pf_bandwidth_outgoing_bandwidth,
	pf_throttle_throttle_interval,
	pf_throttle_throttle_accel,
	pf_throttle_throttle_decel,
	pf_handshake_session_id,

	pf_dc,
	pf_dc_data,

	pf_ping,

	pf_reliable,
	pf_unreliable,
	pf_fragment,
	pf_unsequenced,

	pf_payload_length,
	pf_payload,

	pf_unreliable_seqnum,

	pf_fragment_startseqnum,
	pf_fragment_fragcount,
	pf_fragment_fragnum,
	pf_fragment_total_length,
	pf_fragment_offset,

	pf_packet_throttle,
	pf_bandwidth_limit,

	pf_unsequenced_group
}
--]]

pf_header = ProtoField.new("ENet Header", "enet.header", ftypes.BYTES, nil, base.NONE)
pf_header_field1 = ProtoField.new("Unknown Field 1 (Peer ID/Checksum?)", "enet.header.1", ftypes.UINT32)
pf_header_field2 = ProtoField.new("Unknown Field 2 (???)", "enet.header.2", ftypes.UINT32)
pf_header_flags = ProtoField.new("?Flags?", "enet.header.flags", ftypes.UINT16, base.BIN)
pf_header_flags_1 = ProtoField.new("Unknown Flag 1 (never)", "enet.header.flags.1", ftypes.BOOLEAN)
pf_header_flags_2 = ProtoField.new("Unknown Flag 2 (never)", "enet.header.flags.2", ftypes.BOOLEAN)
pf_header_flags_3 = ProtoField.new("Unknown Flag 3 (always)", "enet.header.flags.3", ftypes.BOOLEAN)
pf_header_flags_4 = ProtoField.new("Unknown Flag 4 (never)", "enet.header.flags.4", ftypes.BOOLEAN)
pf_header_flags_5 = ProtoField.new("Unknown Flag 5 (always)", "enet.header.flags.5", ftypes.BOOLEAN)
pf_header_flags_6 = ProtoField.new("Unknown Flag 6 (never)", "enet.header.flags.6", ftypes.BOOLEAN)
pf_header_flags_7 = ProtoField.new("Unknown Flag 7 (never)", "enet.header.flags.7", ftypes.BOOLEAN)
pf_header_flags_8 = ProtoField.new("Unknown Flag 8 (always)", "enet.header.flags.8", ftypes.BOOLEAN)
pf_header_flags_timestamped = ProtoField.new("Includes Timestamp", "enet.header.flags.timestamped", ftypes.BOOLEAN)
pf_header_flags_10 = ProtoField.new("Unknown Flag 10 (handshake)", "enet.header.flags.10", ftypes.BOOLEAN)
pf_header_flags_11 = ProtoField.new("Unknown Flag 11 (handshake)", "enet.header.flags.11", ftypes.BOOLEAN)
pf_header_flags_12 = ProtoField.new("Unknown Flag 12 (handshake)", "enet.header.flags.12", ftypes.BOOLEAN)
pf_header_flags_13 = ProtoField.new("Unknown Flag 13 (handshake)", "enet.header.flags.13", ftypes.BOOLEAN)
pf_header_flags_14 = ProtoField.new("Unknown Flag 14 (handshake)", "enet.header.flags.14", ftypes.BOOLEAN)
pf_header_flags_15 = ProtoField.new("Unknown Flag 15 (handshake)", "enet.header.flags.15", ftypes.BOOLEAN)
pf_header_flags_16 = ProtoField.new("Unknown Flag 16 (handshake)", "enet.header.flags.16", ftypes.BOOLEAN)
pf_header_time = ProtoField.new("Time", "enet.header.time", ftypes.UINT16)

pf_handshake = ProtoField.new("Handshake", "enet.handshake", ftypes.BYTES, nil, base.NONE)
pf_handshake_field2 = ProtoField.new("?Flags?", "enet.handshake.2", ftypes.BYTES)
pf_handshake_field3 = ProtoField.new("???", "enet.handshake.3", ftypes.BYTES)
pf_handshake_mtu = ProtoField.new("MTU", "enet.handshake.mtu", ftypes.UINT16)
pf_handshake_window_size = ProtoField.new("Window Size", "enet.handshake.winsize", ftypes.UINT32)
pf_handshake_channels = ProtoField.new("Channels", "enet.handshake.channels", ftypes.UINT32)
pf_handshake_incoming_bandwidth = ProtoField.new("Incoming Bandwidth", "enet.handshake.incoming_bandwidth", ftypes.UINT32)
pf_handshake_outgoing_bandwidth = ProtoField.new("Outgoing Bandwidth", "enet.handshake.outgoing_bandwidth", ftypes.UINT32)
pf_handshake_packet_loss_tracking_window = ProtoField.new("Packet loss tracking window", "enet.handshake.pktloss_tracking", ftypes.UINT32)
pf_handshake_throttle_accel = ProtoField.new("Throttle Acceleration", "enet.handshake.throttle_accel", ftypes.UINT32)
pf_handshake_throttle_decel = ProtoField.new("Throttle Deceleration", "enet.handshake.throttle_decel", ftypes.UINT32)
pf_handshake_field4 = ProtoField.new("?Session id?", "enet.handshake.4", ftypes.UINT32)

pf_unknown = ProtoField.new("Unknown Packet", "enet.debug.unknown", ftypes.BYTES, nil, base.NONE)
pf_potentially_decrypted = ProtoField.new("Unknown Packet (Maybe encrypted)", "enet.debug.decrypted", ftypes.BYTES, nil, base.NONE)
pf_potentially_decrypted_length = ProtoField.new("Length", "enet.debug.decrypted.length", ftypes.UINT32)
pf_potentially_decrypted_payload = ProtoField.new("Payload", "enet.debug.decrypted.payload", ftypes.BYTES, nil, base.NONE)
keyinfo = ProtoField.new("Key", "enet.debug.key", ftypes.STRING)

enet.fields = {
	pf_header,
	pf_header_field1,
	pf_header_field2,
	pf_header_flags,
	pf_header_flags_1,
	pf_header_flags_2,
	pf_header_flags_3,
	pf_header_flags_4,
	pf_header_flags_5,
	pf_header_flags_6,
	pf_header_flags_7,
	pf_header_flags_8,
	pf_header_flags_timestamped,
	pf_header_flags_10,
	pf_header_flags_11,
	pf_header_flags_12,
	pf_header_flags_13,
	pf_header_flags_14,
	pf_header_flags_15,
	pf_header_flags_16,

	pf_handshake,
	pf_header_time,
	pf_handshake_field2,
	pf_handshake_field3,
	pf_handshake_mtu,
	pf_handshake_window_size,
	pf_handshake_channels,
	pf_handshake_incoming_bandwidth,
	pf_handshake_outgoing_bandwidth,
	pf_handshake_packet_loss_tracking_window,
	pf_handshake_throttle_accel,
	pf_handshake_throttle_decel,
	pf_handshake_field4,

	pf_unknown,
	pf_potentially_decrypted,
	keyinfo,
	pf_potentially_decrypted_length,
	pf_potentially_decrypted_payload
}

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
	
	pktlen = tvbuf:reported_length_remaining()
	tree = root:add(enet, tvbuf:range(0,pktlen))
	
	headerlen = 10
	has_timestamp = tvbuf:range(8,2):bitfield(8,1) == 1
	if has_timestamp then
		headerlen = headerlen + 2
	end

	pheader = tvbuf:range(0, headerlen)
	pheader_buf = pheader:tvb()

	proto_header = tree:add(pf_header, pheader)
	proto_header:add(pf_header_field1, pheader_buf:range(0,4))
	proto_header:add(pf_header_field2, pheader_buf:range(4,4))
	
	hflagsbuf = pheader_buf:range(8,2)
	header_flags = proto_header:add(pf_header_flags, hflagsbuf)
	header_flags:add(pf_header_flags_1, hflagsbuf:bitfield(0,1))
	header_flags:add(pf_header_flags_2, hflagsbuf:bitfield(1,1))
	header_flags:add(pf_header_flags_3, hflagsbuf:bitfield(2,1))
	header_flags:add(pf_header_flags_4, hflagsbuf:bitfield(3,1))
	header_flags:add(pf_header_flags_5, hflagsbuf:bitfield(4,1))
	header_flags:add(pf_header_flags_6, hflagsbuf:bitfield(5,1))
	header_flags:add(pf_header_flags_7, hflagsbuf:bitfield(6,1))
	header_flags:add(pf_header_flags_8, hflagsbuf:bitfield(7,1))
	header_flags:add(pf_header_flags_timestamped, has_timestamp)
	header_flags:add(pf_header_flags_10, hflagsbuf:bitfield(9,1))
	header_flags:add(pf_header_flags_11, hflagsbuf:bitfield(10,1))
	header_flags:add(pf_header_flags_12, hflagsbuf:bitfield(11,1))
	header_flags:add(pf_header_flags_13, hflagsbuf:bitfield(12,1))
	header_flags:add(pf_header_flags_14, hflagsbuf:bitfield(13,1))
	header_flags:add(pf_header_flags_15, hflagsbuf:bitfield(14,1))
	header_flags:add(pf_header_flags_16, hflagsbuf:bitfield(15,1))

	if has_timestamp then
		proto_header:add(pf_header_time, pheader_buf:range(10,2))
	end

	if tvbuf:range(9, 1):uint() == 0xff then
		connect = tvbuf:range(headerlen, pktlen-headerlen)
		connect_buf = connect:tvb()

		tree_connect = tree:add(pf_handshake, connect)
		tree_connect:add(pf_handshake_field2, connect_buf:range(0,4))
		tree_connect:add(pf_handshake_field3, connect_buf:range(4,2))
		tree_connect:add(pf_handshake_mtu, connect_buf:range(6,2))
		tree_connect:add(pf_handshake_window_size, connect_buf:range(8,4))
		tree_connect:add(pf_handshake_channels, connect_buf:range(12,4))
		tree_connect:add(pf_handshake_incoming_bandwidth, connect_buf:range(16,4))
		tree_connect:add(pf_handshake_outgoing_bandwidth, connect_buf:range(20,4))
		tree_connect:add(pf_handshake_packet_loss_tracking_window, connect_buf:range(24,4))
		tree_connect:add(pf_handshake_throttle_accel, connect_buf:range(28,4))
		tree_connect:add(pf_handshake_throttle_decel, connect_buf:range(32,4))
		tree_connect:add(pf_handshake_field4, connect_buf:range(36,4))
	else
		tree:add(pf_unknown, tvbuf:range(headerlen, pktlen-headerlen))
		
		-- encryption doesn't happen here yet, probably
		decode_payload(tvbuf:range(headerlen, pktlen-headerlen), tree, pktinfo)
	end

	-- proto header

	-- Seems like sent_time is always included?
	--[[
	has_sent_time = tvbuf:range(4, 1):bitfield(0, 1) == 1
	if has_sent_time then
		header_length = 8
	else
		header_length = 6
	end

	header_length = 8
	pheader = tvbuf:range(0, header_length)
	pheader_buf = pheader:tvb()
	proto_header = tree:add(pf_proto_header, pheader)
	
	proto_header:add(pf_checksum, pheader_buf:range(0, 4))
	--proto_header:add(pf_flag_has_sent_time, pheader_buf:range(4,1), has_sent_time)
	proto_header:add(pf_peer_id, pheader_buf:range(4,2))
	--if has_sent_time then
		proto_header:add(pf_sent_time, pheader_buf:range(6, 2))
	--end

	-- command header
	tvbuf = tvbuf:range(header_length):tvb()
	header = tree:add(pf_header, tvbuf:range(0, 4))

	command = tvbuf:range(0,1):bitfield(4,4)
	if command >= 0 and command <= 11 then
		header:add(pf_command, tvbuf:range(0,1))
	else
		print("unknown command")
		command = 99
	end

	channel = tvbuf:range(1, 1)
	header:add(pf_channel, channel)

	seqnumber = tvbuf:range(2,2)
	header:add(pf_seqnumber, seqnumber)
	
	pktinfo.cols.info = command2string[command]

	
	-- command-based parsing
	tvbuf = tvbuf:range(4):tvb()

	if command == 1 then
		parse_acknowledge(tvbuf, tree)
	elseif command == 2 then
		parse_handshakeect(tvbuf, tree)
	elseif command == 3 then
		parse_verify_handshakeect(tvbuf, tree)
	elseif command == 4 then
		parse_dishandshakeect(tvbuf, tree)
	elseif command == 5 then
		parse_ping(tvbuf, tree)
	elseif command == 6 then
		parse_reliable(tvbuf, tree, pktinfo)
	elseif command == 7 then
		parse_unreliable(tvbuf, tree, pktinfo)
	elseif command == 8 then
		parse_fragment(tvbuf, tree, pktinfo)
	elseif command == 9 then
		parse_unsequenced(tvbuf, tree, pktinfo)
	elseif command == 10 then
		parse_bandwidth_limit(tvbuf, tree)
	elseif command == 11 then
		parse_packet_throttle(tvbuf, tree)
	end

	]]--
end

function decode_payload(tvrange, tree, pktinfo)
	tvbuf = tvrange:tvb()

	loltree = tree:add(pf_potentially_decrypted, tvrange)
	loltree:set_text("Decrypted Payload (Note that we might be decrypting too soon here)")
	
	if b64key == "" then
		loltree:add(keyinfo, "No key found" .. " (" .. b64keyfile .. ")")
		return
	end
	
	loltree:add(keyinfo, b64key .. " (" .. b64keyfile .. ")")

	data_length = tvbuf:len()
	loltree:add(pf_potentially_decrypted_length, data_length)
	
	data_tmp = {}
	for i=0, data_length-1 do
		data_tmp[i] = tvbuf:range(i, 1):uint()
	end
	
	decryptedData = bf_Decrypt(data_tmp, data_length)
	
	decryptedByteArray = ByteArray.new()
	decryptedByteArray:set_size(data_length)
	for i=0, data_length-1 do
		decryptedByteArray:set_index(i, decryptedData[i])
	end

	decrypted_tvb = ByteArray.tvb(decryptedByteArray, "Decrypted tvb")
	loltree:add(pf_potentially_decrypted_payload, decrypted_tvb:range(0, decrypted_tvb:reported_length_remaining()))
	
	--loltree:add(pf_payload, tvrange)
		-- Wireshark crashes for tvbufs where the source is not a child of the original tvbuf
		--loltree:add(pf_data_decrypted, decryptedByteArray:tvb():range(0))
		
		--[[ No longer needed
		coverage = coverage + data_length
		
		if coverage < pktlen and 
		( tvbuf:range(coverage, 1):uint() == 0x07 or tvbuf:range(coverage, 1):uint() == 0x49 ) then
			coverage = coverage + 8
		else
			coverage = coverage + 6
		end
		]]--
		
	--end
end

function parse_acknowledge(tvbuf, tree)
	ack_buf = tvbuf:range(0, 4)
	ack = tree:add(pf_ack, ack_buf)

	ack:add(pf_ack_seqnum, tvbuf:range(0, 2))
	ack:add(pf_ack_recvtime, tvbuf:range(2, 2))
end

function parse_handshakeect(tvbuf, tree)
	handshake_buf = tvbuf:range(0, 36)
	handshake = tree:add(pf_handshake, handshake_buf)

	handshake:add(pf_handshake_peerid, tvbuf:range(0, 2))
	handshake:add(pf_handshake_mtu, tvbuf:range(2, 2))
	handshake:add(pf_handshake_window_size, tvbuf:range(4, 4))
	handshake:add(pf_handshake_channels, tvbuf:range(8, 4))
	handshake:add(pf_bandwidth_incoming_bandwidth, tvbuf:range(12, 4))
	handshake:add(pf_bandwidth_outgoing_bandwidth, tvbuf:range(16, 4))
	handshake:add(pf_throttle_throttle_interval, tvbuf:range(20, 4))
	handshake:add(pf_throttle_throttle_accel, tvbuf:range(24, 4))
	handshake:add(pf_throttle_throttle_decel, tvbuf:range(28, 4))
	handshake:add(pf_handshake_session_id, tvbuf:range(32, 4))
end

function parse_verify_handshakeect(tvbuf, tree)
	handshake_buf = tvbuf:range(0, 32)
	handshake = tree:add(pf_verify_handshake, handshake_buf)

	handshake:add(pf_handshake_peerid, tvbuf:range(0, 2))
	handshake:add(pf_handshake_mtu, tvbuf:range(2, 2))
	handshake:add(pf_handshake_window_size, tvbuf:range(4, 4))
	handshake:add(pf_handshake_channels, tvbuf:range(8, 4))
	handshake:add(pf_bandwidth_incoming_bandwidth, tvbuf:range(12, 4))
	handshake:add(pf_bandwidth_outgoing_bandwidth, tvbuf:range(16, 4))
	handshake:add(pf_throttle_throttle_interval, tvbuf:range(20, 4))
	handshake:add(pf_throttle_throttle_accel, tvbuf:range(24, 4))
	handshake:add(pf_throttle_throttle_decel, tvbuf:range(28, 4))
end

function parse_dishandshakeect(tvbuf, tree)
	dc_buf = tvbuf:range(0, 4)
	dc = tree:add(pf_dc, dc_buf)

	dc:add(pf_dc_data, tvbuf:range(0, 4))
end

function parse_ping(tvbuf, tree)
	ping_buf = tvbuf:range(0)
	ping = tree:add(pf_ping, ping_buf)
end

function parse_reliable(tvbuf, tree, pktinfo)
	buf = tvbuf:range(0)
	reliable = tree:add(pf_reliable, buf)

	reliable:add(pf_payload_length, tvbuf:range(0, 2))
	decode_payload(tvbuf:range(2), reliable, pktinfo)
end

function parse_unreliable(tvbuf, tree, pktinfo)
	buf = tvbuf:range(0)
	unreliable = tree:add(pf_unreliable, buf)

	unreliable:add(pf_unreliable_seqnum, tvbuf:range(0, 2))
	unreliable:add(pf_payload_length, tvbuf:range(2, 2))
	decode_payload(tvbuf:range(4), reliable, pktinfo)
end

function parse_fragment(tvbuf, tree, pktinfo)
	buf = tvbuf:range(0)
	fragment = tree:add(pf_fragment, buf)

	fragment:add(pf_fragment_startseqnum, tvbuf:range(0, 2))
	fragment:add(pf_payload_length, tvbuf:range(2, 2))
	fragment:add(pf_fragment_fragcount, tvbuf:range(4, 4))
	fragment:add(pf_fragment_fragnum, tvbuf:range(8, 4))
	fragment:add(pf_fragment_total_length, tvbuf:range(12, 4))
	fragment:add(pf_fragment_offset, tvbuf:range(16, 4))
	fragment:add(pf_payload, tvbuf:range(20))
end

function parse_unsequenced(tvbuf, tree, pktinfo)
	buf = tvbuf:range(0)
	unsequenced = tree:add(pf_unsequenced, buf)

	unsequenced:add(pf_unsequenced_group, tvbuf:range(0, 2))
	unsequenced:add(pf_payload_length, tvbuf:range(2, 2))
	unsequenced:add(pf_payload, tvbuf:range(4))
end

function parse_bandwidth_limit(tvbuf, tree)
	buf = tvbuf:range(0)
	limit = tree:add(pf_bandwidth_limit)

	limit:add(pf_bandwidth_incoming_bandwidth, tvbuf:range(0, 4))
	limit:add(pf_bandwidth_outgoing_bandwidth, tvbuf:range(4, 4))
end

function parse_packet_throttle(tvbuf, tree)
	buf = tvbuf:range(0)
	throttle = tree:add(pf_packet_throttle)

	throttle:add(pf_throttle_throttle_interval, tvbuf:range(0, 4))
	throttle:add(pf_throttle_throttle_accel, tvbuf:range(4, 4))
	throttle:add(pf_throttle_throttle_decel, tvbuf:range(8, 4))
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
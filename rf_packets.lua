-- rf_packets.lua by Goober
-- Last updated Sept 8, 2025
-- Wireshark Lua dissector for Red Faction (RF) + Pure Faction (PF) + Alpine Faction (AF)

local rf_proto = Proto("rf", "Red Faction")

-- ========= ENUMS / NAMES =========
local RF_MainPacketType = {
  [0x00] = "Game",
  [0x01] = "Reliable",
  [0x02] = "Tracker",
}

local RF_GameTypeNames = {
  [0x00] = "GAME_INFO_REQUEST",
  [0x01] = "GAME_INFO",
  [0x02] = "JOIN_REQUEST",
  [0x03] = "JOIN_ACCEPT",
  [0x04] = "JOIN_DENY",
  [0x05] = "NEW_PLAYER",
  [0x06] = "PLAYERS",
  [0x07] = "LEFT_GAME",
  [0x08] = "END_GAME",
  [0x09] = "STATE_INFO_REQUEST",
  [0x0A] = "STATE_INFO_DONE",
  [0x0B] = "CLIENT_IN_GAME",
  [0x0C] = "CHAT_LINE",
  [0x0D] = "NAME_CHANGE",
  [0x0E] = "RESPAWN_REQUEST",
  [0x0F] = "TRIGGER_ACTIVATE",
  [0x10] = "USE_KEY_PRESSED",
  [0x11] = "PREGAME_BOOLEAN",
  [0x12] = "PREGAME_GLASS",
  [0x13] = "PREGAME_REMOTE_CHARGE",
  [0x14] = "SUICIDE",
  [0x15] = "ENTER_LIMBO",
  [0x16] = "LEAVE_LIMBO",
  [0x17] = "TEAM_CHANGE",
  [0x18] = "PING",
  [0x19] = "PONG",
  [0x1A] = "NETGAME_UPDATE",
  [0x1B] = "RATE_CHANGE",
  [0x1C] = "SELECT_WEAPON",
  [0x1D] = "CLUTTER_UPDATE",
  [0x1E] = "CLUTTER_KILL",
  [0x1F] = "CTF_FLAG_PICKED_UP",
  [0x20] = "CTF_FLAG_CAPTURED",
  [0x21] = "CTF_FLAG_UPDATE",
  [0x22] = "CTF_FLAG_RETURNED",
  [0x23] = "CTF_FLAG_DROPPED",
  [0x24] = "REMOTE_CHARGE_KILL",
  [0x25] = "ITEM_UPDATE",
  [0x26] = "OBJECT_UPDATE",
  [0x27] = "OBJECT_KILL",
  [0x28] = "ITEM_APPLY",
  [0x29] = "BOOLEAN",
  [0x2A] = "MOVER_UPDATE",
  [0x2B] = "RESPAWN",
  [0x2C] = "ENTITY_CREATE",
  [0x2D] = "ITEM_CREATE",
  [0x2E] = "RELOAD",
  [0x2F] = "RELOAD_REQUEST",
  [0x30] = "WEAPON_FIRE",
  [0x31] = "FALL_DAMAGE",
  [0x32] = "RCON_REQUEST",
  [0x33] = "RCON",
  [0x34] = "SOUND",
  [0x35] = "TEAM_SCORES",
  [0x36] = "GLASS_KILL",
  -- >= 0x50: Alpine, >= 0x2A & others: PF handled separately
}

-- Alpine (core packet types)
local AF_TypeNames = {
  [0x50] = "af_ping_location_req",
  [0x51] = "af_ping_location",
  [0x52] = "af_damage_notify",
  [0x53] = "af_obj_update",
  [0x55] = "af_client_req",
  [0x56] = "af_just_spawned_info",
}
local AF_ClientReqTypeNames = { [0x00] = "af_req_handicap" }
local AF_JustSpawnedInfoTypeNames = { [0x00] = "af_loadout" }

-- Alpine signatures / magics (LE on wire)
local ALPINE_FACTION_SIGNATURE = 0x4E4C5246 -- "FRLN" in memory (LE), defined by AF
local DASH_FACTION_SIGNATURE   = 0xDA58FAC7
local AFTR_MAGIC               = 0x52544641 -- 'AFTR' (LE)

-- Alpine JoinAccept flags
local AF_JoinAcceptFlags = {
  [0x00000001] = "saving_enabled",
  [0x00000002] = "max_fov",
  [0x00000004] = "allow_fb_mesh",
  [0x00000008] = "allow_lmap",
  [0x00000010] = "allow_no_ss",
  [0x00000020] = "no_player_collide",
  [0x00000040] = "allow_no_mf",
  [0x00000080] = "click_limit",
  [0x00000100] = "unlimited_fps",
  [0x00000200] = "gaussian_spread",
  [0x00000400] = "location_pinging",
}

-- Pure Faction
local PF_TypeNames = {
  [0x2A] = "player_stats",
  [0x3A] = "players_request",
  [0x3B] = "server_hash",
  [0x3C] = "client_hash",
  [0x3D] = "request_cheat_check",
  [0x3E] = "client_cheat_check",
  [0x40] = "announce_player",
  [0xA1] = "players",
}
local PF_PureStatus = {
  [0] = "none", [1] = "blue", [2] = "gold", [3] = "fail",
  [4] = "old_pure", [5] = "rfsb",
}
local PF_GAME_INFO_SIGNATURE = 0xEFBEADDE -- (DE AD BE EF on wire)

-- RF Flags & helpers
local RF_ServerFlags = { [0x01]="DEDICATED",[0x02]="NOT_LAN",[0x04]="PASSWORD" }
local RF_GameOptions = {
  [0x0402]="DEFAULT",[0x0240]="TEAM_DAMAGE",[0x0080]="FALL_DAMAGE",
  [0x0010]="WEAPONS_STAY",[0x0020]="FORCE_RESPAWN",[0x2000]="BALANCE_TEAMS",
}
local RF_PlayerFlags = { [0x80]="BLUE_TEAM" }

local RF_ObjectUpdateFlags = {
  [0x01]="POS_ROT_ANIM",
  [0x02]="UNKNOWN4",
  [0x04]="WEAPON_TYPE",
  [0x08]="UNKNOWN3",
  [0x10]="ALT_FIRE",
  [0x20]="HEALTH_ARMOR",
  [0x40]="FIRE",
  [0x80]="AMP_FLAGS",
}
local RF_EntityAmpFlags = { [0x01]="DAMAGE_AMP",[0x02]="INVULN" }
local RF_EntityStateFlags = {
  [0x01]="HIDDEN_WEAPON",[0x04]="CROUCH",[0x08]="ZOOM",[0x10]="WEAPON_FIRE",[0x20]="WEAPON_FIRE2"
}
local RF_WeaponFireFlags = { [0x01]="ALT_FIRE",[0x02]="UNKNOWN",[0x04]="NO_POS_ROT" }

-- (abbrev) weapon names (extend as you like)
local RF_WeaponNames = {
  [0x00]="REMOTE_CHARGE",[0x01]="DETONATOR",[0x02]="CONTROL_BATON",[0x03]="PISTOL",
  [0x05]="SHOTGUN",[0x06]="SNIPER_RIFLE",[0x07]="ROCKET_LAUNCHER",[0x08]="ASSAULT_RIFLE",
  [0x09]="SMG",[0x0B]="GRENADE",[0x0C]="FLAMETHROWER",[0x0D]="RIOT_SHIELD",
  [0x0E]="RAIL_GUN",[0x0F]="HMG",[0x10]="PRECISION_RIFLE",[0x11]="FUSION_RL",
  [0x12]="VAUSS",
}

-- bitwise-AND helper (compat across Lua builds)
local BAND
do
  if _G.bit32 and _G.bit32.band then
    BAND = _G.bit32.band
  elseif _G.bit and _G.bit.band then
    BAND = _G.bit.band
  else
    BAND = function(a,b)
      local res, bitv = 0, 1
      local va, vb = a, b
      while va > 0 or vb > 0 do
        if (va % 2 == 1) and (vb % 2 == 1) then res = res + bitv end
        va = math.floor(va / 2); vb = math.floor(vb / 2); bitv = bitv * 2
      end
      return res
    end
  end
end

-- ========= PROTOFIELDS =========
local f_main_type   = ProtoField.uint8 ("rf.main_type",   "Main Type", base.HEX, RF_MainPacketType)
local f_raw_len     = ProtoField.uint16("rf.raw_len",     "Datagram Length")

-- Game header
local f_game_type   = ProtoField.uint8 ("rf.game.type",   "Game Type", base.HEX, RF_GameTypeNames)
local f_game_size   = ProtoField.uint16("rf.game.size",   "Game Payload Size", base.DEC)

-- Reliable envelope
local f_rel_type    = ProtoField.uint8 ("rf.rel.type",    "Reliable Type", base.HEX)
local f_rel_unknown = ProtoField.uint8 ("rf.rel.unknown", "Unknown", base.HEX)
local f_rel_id      = ProtoField.uint16("rf.rel.id",      "Reliable ID", base.DEC)
local f_rel_len     = ProtoField.uint16("rf.rel.len",     "Reliable Data Length", base.DEC)
local f_rel_ticks   = ProtoField.uint32("rf.rel.ticks",   "Ticks (ms since start)", base.DEC)

-- Tracker (minimal)
local f_trk_u0      = ProtoField.uint8 ("rf.trk.u0",      "Unknown(0x06?)", base.HEX)
local f_trk_type    = ProtoField.uint16("rf.trk.type",    "Tracker Type", base.HEX)
local f_trk_seq     = ProtoField.uint32("rf.trk.seq",     "Sequence", base.DEC)
local f_trk_plen    = ProtoField.uint16("rf.trk.plen",    "Packet Length", base.DEC)

-- Alpine fields (core packets)
local f_af_type     = ProtoField.uint8 ("rf.af.type",     "Alpine Type", base.HEX, AF_TypeNames)
local f_af_pid      = ProtoField.uint8 ("rf.af.player_id","Player ID", base.DEC)
local f_vec_x       = ProtoField.float ("rf.vec.x",       "X")
local f_vec_y       = ProtoField.float ("rf.vec.y",       "Y")
local f_vec_z       = ProtoField.float ("rf.vec.z",       "Z")
local f_mat_cell    = ProtoField.float ("rf.mat.cell",    "m[i][j]")

local f_af_damage   = ProtoField.uint16("rf.af.damage",   "Damage", base.DEC)
local f_af_flags    = ProtoField.uint8 ("rf.af.flags",    "Flags", base.HEX)
local f_af_obj_count= ProtoField.uint16("rf.af.obj.count","Object Updates", base.DEC)
local f_af_obj_handle=ProtoField.uint32("rf.af.obj.handle","Object Handle", base.HEX)
local f_af_obj_curw = ProtoField.uint8 ("rf.af.obj.cur_primary","Current Primary Weapon", base.HEX, RF_WeaponNames)
local f_af_obj_ammo = ProtoField.uint8 ("rf.af.obj.ammo_type",  "Ammo Type", base.HEX)
local f_af_obj_clip = ProtoField.uint16("rf.af.obj.clip_ammo",  "Clip Ammo", base.DEC)
local f_af_obj_res  = ProtoField.uint16("rf.af.obj.reserve",    "Reserve Ammo", base.DEC)
local f_af_req_type = ProtoField.uint8 ("rf.af.req.type", "Client Request Type", base.HEX, AF_ClientReqTypeNames)
local f_af_req_hand = ProtoField.uint8 ("rf.af.req.handicap","Handicap Amount", base.DEC)
local f_af_jsi_type = ProtoField.uint8 ("rf.af.jsi.type", "Info Type", base.HEX, AF_JustSpawnedInfoTypeNames)
local f_af_load_wpn = ProtoField.uint8 ("rf.af.loadout.weapon_index","Weapon Index", base.DEC)
local f_af_load_ammo= ProtoField.uint32("rf.af.loadout.ammo",       "Ammo", base.DEC)

-- Alpine extended tails: GAME_INFO
local f_af_gi_sig   = ProtoField.uint32("rf.af.gi.signature","AF Signature", base.HEX)
local f_af_ver_maj  = ProtoField.uint8 ("rf.af.ver.major",  "Version Major", base.DEC)
local f_af_ver_min  = ProtoField.uint8 ("rf.af.ver.minor",  "Version Minor", base.DEC)
local f_af_ver_pat  = ProtoField.uint8 ("rf.af.ver.patch",  "Version Patch", base.DEC)
local f_af_ver_type = ProtoField.uint8 ("rf.af.ver.type",   "Version Type",  base.DEC)
local f_af_gi_flags = ProtoField.uint32("rf.af.gi.flags",   "AF GameInfo Flags", base.HEX)
local f_af_gi_level = ProtoField.string("rf.af.gi.level",   "AF Level Filename")

-- Alpine JOIN_REQUEST (any version)
local f_af_jr_sig     = ProtoField.uint32("rf.af.jr.signature","AF/DF Signature", base.HEX)
local f_af_jr_vermaj  = ProtoField.uint8 ("rf.af.jr.ver.major", "Version Major", base.DEC)
local f_af_jr_vermin  = ProtoField.uint8 ("rf.af.jr.ver.minor", "Version Minor", base.DEC)
local f_af_jr_verpat  = ProtoField.uint8 ("rf.af.jr.ver.patch", "Version Patch", base.DEC)
local f_af_jr_vertype = ProtoField.uint8 ("rf.af.jr.ver.type",  "Version Type", base.DEC)
local f_af_jr_maxrfl  = ProtoField.uint32("rf.af.jr.max_rfl",   "Max RFL Version", base.DEC)
local f_af_jr_flags   = ProtoField.uint32("rf.af.jr.flags",     "AF JoinReq Flags", base.HEX)
local f_af_jr_total   = ProtoField.uint16("rf.af.jr.total_len", "AF Block Length", base.DEC)
local f_af_jr_magic   = ProtoField.uint32("rf.af.jr.footer",    "Footer Magic", base.HEX)
local f_af_jr_tlvs    = ProtoField.bytes ("rf.af.jr.tlvs",      "AF TLVs")

-- Alpine JOIN_ACCEPT extension
local f_af_ja_sig     = ProtoField.uint32("rf.af.ja.signature","AF Signature", base.HEX)
local f_af_ja_vermaj  = ProtoField.uint8 ("rf.af.ja.ver.major","Version Major", base.DEC)
local f_af_ja_vermin  = ProtoField.uint8 ("rf.af.ja.ver.minor","Version Minor", base.DEC)
local f_af_ja_flags   = ProtoField.uint32("rf.af.ja.flags",    "JoinAccept Flags", base.HEX)
local f_af_ja_fov     = ProtoField.float ("rf.af.ja.max_fov",  "Max FOV")
local f_af_ja_cd      = ProtoField.int32 ("rf.af.ja.cooldown", "Semi-auto Cooldown (ms)")

-- PF fields
local f_pf_type       = ProtoField.uint8 ("rf.pf.type",       "PF Type", base.HEX, PF_TypeNames)
local f_pf_ver        = ProtoField.uint8 ("rf.pf.version",    "PF Version", base.DEC)
local f_pf_pcount     = ProtoField.uint8 ("rf.pf.player.count","Players", base.DEC)
local f_pf_pid        = ProtoField.uint8 ("rf.pf.player.id",  "Player ID", base.DEC)
local f_pf_is_pure    = ProtoField.uint8 ("rf.pf.player.is_pure","Pure Status", base.DEC, PF_PureStatus)
local f_pf_accuracy   = ProtoField.uint8 ("rf.pf.player.accuracy","Accuracy (%)", base.DEC)
local f_pf_streak_max = ProtoField.uint16("rf.pf.player.streak_max","Max Streak", base.DEC)
local f_pf_streak_cur = ProtoField.uint16("rf.pf.player.streak_cur","Current Streak", base.DEC)
local f_pf_kills      = ProtoField.uint16("rf.pf.player.kills","Kills", base.DEC)
local f_pf_deaths     = ProtoField.uint16("rf.pf.player.deaths","Deaths", base.DEC)
local f_pf_tk         = ProtoField.uint16("rf.pf.player.team_kills","Team Kills", base.DEC)
local f_pf_res3       = ProtoField.bytes ("rf.pf.reserved3",  "Reserved (3 bytes)")
local f_pf_show_ip    = ProtoField.uint8 ("rf.pf.players.show_ip","Show IP", base.DEC, {[0]="no",[1]="yes"})
local f_pf_ip         = ProtoField.ipv4 ("rf.pf.players.ip",  "IP")
local f_pf_name       = ProtoField.string("rf.pf.players.name","Name")
local f_pf_gi_sig     = ProtoField.uint32("rf.pf.gi.signature","PF Signature", base.HEX)
local f_pf_gi_ver     = ProtoField.uint16("rf.pf.gi.version",  "PF Version", base.HEX)

-- RF common fields
local f_rf_str        = ProtoField.string("rf.rf.str", "String")
local f_rf_u8         = ProtoField.uint8 ("rf.rf.u8", "U8", base.DEC)
local f_rf_u16        = ProtoField.uint16("rf.rf.u16","U16",base.DEC)
local f_rf_u32        = ProtoField.uint32("rf.rf.u32","U32",base.DEC)
local f_rf_i16        = ProtoField.int16 ("rf.rf.i16","I16",base.DEC)
local f_rf_i32        = ProtoField.int32 ("rf.rf.i32","I32",base.DEC)
local f_rf_f32        = ProtoField.float ("rf.rf.f32","F32")
local f_rf_flags8     = ProtoField.uint8 ("rf.rf.flags8","Flags", base.HEX)
local f_rf_flags16    = ProtoField.uint16("rf.rf.flags16","Flags16", base.HEX)
local f_rf_flags32    = ProtoField.uint32("rf.rf.flags32","Flags32", base.HEX)

-- RF specific
local f_rf_gameopt    = ProtoField.uint32("rf.rf.game_options","Game Options", base.HEX, RF_GameOptions)
local f_rf_srvflags   = ProtoField.uint8 ("rf.rf.server_flags","Server Flags", base.HEX, RF_ServerFlags)
local f_rf_pflags     = ProtoField.uint32("rf.rf.player_flags","Player Flags", base.HEX, RF_PlayerFlags)
local f_rf_team       = ProtoField.uint8 ("rf.rf.team","Team", base.DEC, {[0]="red",[1]="blue"})
local f_rf_weapon     = ProtoField.uint8 ("rf.rf.weapon","Weapon", base.HEX, RF_WeaponNames)
local f_rf_wfflags    = ProtoField.uint8 ("rf.rf.weapon_fire_flags","WeaponFire Flags", base.HEX, RF_WeaponFireFlags)

rf_proto.fields = {
  f_main_type, f_raw_len,
  f_game_type, f_game_size,
  f_rel_type, f_rel_unknown, f_rel_id, f_rel_len, f_rel_ticks,
  f_trk_u0, f_trk_type, f_trk_seq, f_trk_plen,

  -- Alpine core
  f_af_type, f_af_pid, f_vec_x, f_vec_y, f_vec_z, f_mat_cell,
  f_af_damage, f_af_flags, f_af_obj_count, f_af_obj_handle, f_af_obj_curw, f_af_obj_ammo,
  f_af_obj_clip, f_af_obj_res, f_af_req_type, f_af_req_hand, f_af_jsi_type, f_af_load_wpn, f_af_load_ammo,

  -- Alpine extended tails
  f_af_gi_sig, f_af_ver_maj, f_af_ver_min, f_af_ver_pat, f_af_ver_type, f_af_gi_flags, f_af_gi_level,
  f_af_jr_sig, f_af_jr_vermaj, f_af_jr_vermin, f_af_jr_verpat, f_af_jr_vertype, f_af_jr_maxrfl, f_af_jr_flags,
  f_af_jr_total, f_af_jr_magic, f_af_jr_tlvs,
  f_af_ja_sig, f_af_ja_vermaj, f_af_ja_vermin, f_af_ja_flags, f_af_ja_fov, f_af_ja_cd,

  -- PF
  f_pf_type, f_pf_ver, f_pf_pcount, f_pf_pid, f_pf_is_pure, f_pf_accuracy, f_pf_streak_max,
  f_pf_streak_cur, f_pf_kills, f_pf_deaths, f_pf_tk, f_pf_res3, f_pf_show_ip, f_pf_ip, f_pf_name,
  f_pf_gi_sig, f_pf_gi_ver,

  -- RF generic
  f_rf_str, f_rf_u8, f_rf_u16, f_rf_u32, f_rf_i16, f_rf_i32, f_rf_f32, f_rf_flags8, f_rf_flags16, f_rf_flags32,
  f_rf_gameopt, f_rf_srvflags, f_rf_pflags, f_rf_team, f_rf_weapon, f_rf_wfflags,
}

-- ========= HELPERS =========
local function add_vec3(tree, tvb, off, label)
  local t = tree:add(string.format("%s (Vector3)", label or "pos"))
  t:add(f_vec_x, tvb(off+0,4))
  t:add(f_vec_y, tvb(off+4,4))
  t:add(f_vec_z, tvb(off+8,4))
  return 12
end

local function add_matrix3(tree, tvb, off, label)
  local m = tree:add(string.format("%s (Matrix3)", label or "orient"))
  for r=0,2 do
    for c=0,2 do
      m:add(f_mat_cell, tvb(off + (r*3+c)*4, 4))
    end
  end
  return 36
end

local function read_cstr(tvb, start, max_end)
  local maxlen = max_end - start
  if maxlen <= 0 then return "", start end
  local s = tvb(start, maxlen):stringz()
  return s, start + #s + 1
end

local function add_reserved3(tree, tvb, start, payload_end, field)
  if payload_end - start >= 3 then
    tree:add(field or f_pf_res3, tvb(payload_end-3, 3))
  end
end

local function set_info(pinfo, s)
  if pinfo and pinfo.cols and pinfo.cols.info then
    pinfo.cols.info:append(" " .. s)
  end
end

-- replace existing versions of these three functions

local function add_flags8(tree, tvbr, dict)
  local t = tree:add(f_rf_flags8, tvbr)
  local v = tvbr:uint()
  for bit, val in pairs(dict) do
    if BAND(v, bit) ~= 0 then
      t:add_expert_info(PI_COMMENT, PI_NOTE, val)
    end
  end
end

local function add_flags16(tree, tvbr, dict)
  local t = tree:add(f_rf_flags16, tvbr)
  local v = tvbr:le_uint()
  for bit, val in pairs(dict) do
    if BAND(v, bit) ~= 0 then
      t:add_expert_info(PI_COMMENT, PI_NOTE, val)
    end
  end
end

local function add_flags32(tree, tvbr, dict)
  local t = tree:add(f_rf_flags32, tvbr)
  local v = tvbr:le_uint()
  for bit, val in pairs(dict) do
    if BAND(v, bit) ~= 0 then
      t:add_expert_info(PI_COMMENT, PI_NOTE, val)
    end
  end
end


-- ========= ALPINE (already supported core packets) =========
local function dissect_af_ping_location_req(tvb, pinfo, tree, off, len)
  if len < 12 then return end
  add_vec3(tree, tvb, off, "pos")
  set_info(pinfo, "(AF ping_location_req)")
end

local function dissect_af_ping_location(tvb, pinfo, tree, off, len)
  if len < 13 then return end
  tree:add(f_af_pid, tvb(off,1))
  add_vec3(tree, tvb, off+1, "pos")
  set_info(pinfo, "(AF ping_location)")
end

local function dissect_af_damage_notify(tvb, pinfo, tree, off, len)
  if len < 4 then return end
  tree:add(f_af_pid,    tvb(off+0,1))
  tree:add(f_af_damage, tvb(off+1,2))
  tree:add(f_af_flags,  tvb(off+3,1))
  set_info(pinfo, "(AF damage_notify)")
end

local function dissect_af_obj_update(tvb, pinfo, tree, off, len)
  local rec = 10
  if len < rec then set_info(pinfo,"(AF obj_update: empty)"); return end
  local count = math.floor(len / rec)
  tree:add(f_af_obj_count, tvb(off, math.min(2,len)), count)
  local cur = off
  for i=1,count do
    local st = tree:add(string.format("Object Update %d", i))
    st:add(f_af_obj_handle, tvb(cur+0,4))
    st:add(f_af_obj_curw,   tvb(cur+4,1))
    st:add(f_af_obj_ammo,   tvb(cur+5,1))
    st:add(f_af_obj_clip,   tvb(cur+6,2))
    st:add(f_af_obj_res,    tvb(cur+8,2))
    cur = cur + rec
  end
  set_info(pinfo, string.format("(AF obj_update x%d)", count))
end

local function dissect_af_client_req(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local t = tvb(off,1):uint()
  tree:add(f_af_req_type, tvb(off,1))
  if t == 0x00 and len >= 2 then
    tree:add(f_af_req_hand, tvb(off+1,1))
    set_info(pinfo, "(AF client_req: handicap)")
  else
    set_info(pinfo, string.format("(AF client_req: type=0x%02X)", t))
  end
end

local function dissect_af_just_spawned_info(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local tp = tvb(off,1):uint()
  tree:add(f_af_jsi_type, tvb(off,1))
  local cur = off + 1
  local left = len - 1
  if tp == 0x00 then
    local rec = 5
    local cnt = math.floor(left / rec)
    for i=1,cnt do
      local st = tree:add(string.format("Loadout %d", i))
      st:add(f_af_load_wpn,  tvb(cur+0,1))
      st:add(f_af_load_ammo, tvb(cur+1,4))
      cur = cur + rec
    end
    set_info(pinfo, string.format("(AF just_spawned_info: loadout x%d)", cnt))
  else
    set_info(pinfo, string.format("(AF just_spawned_info: type=0x%02X)", tp))
  end
end

local function dissect_af(gt, tvb, pinfo, tree, off_payload, len_payload, hdr_off)
  tree:add(f_af_type, tvb(hdr_off, 1))
  if     gt == 0x50 then dissect_af_ping_location_req(tvb, pinfo, tree, off_payload, len_payload)
  elseif gt == 0x51 then dissect_af_ping_location    (tvb, pinfo, tree, off_payload, len_payload)
  elseif gt == 0x52 then dissect_af_damage_notify    (tvb, pinfo, tree, off_payload, len_payload)
  elseif gt == 0x53 then dissect_af_obj_update       (tvb, pinfo, tree, off_payload, len_payload)
  elseif gt == 0x55 then dissect_af_client_req       (tvb, pinfo, tree, off_payload, len_payload)
  elseif gt == 0x56 then dissect_af_just_spawned_info(tvb, pinfo, tree, off_payload, len_payload)
  else set_info(pinfo, string.format("(AF 0x%02X)", gt))
  end
  pinfo.cols.protocol = "RF/AF"
  pinfo.cols.info = string.format("Game (AF %s)", AF_TypeNames[gt] or string.format("0x%02X", gt))
end

-- ========= PURE FACTION =========
local function dissect_pf_player_stats(tvb, pinfo, tree, off, len)
  if len < 2 then return end
  local cur = off
  local endpos = off + len
  tree:add(f_pf_ver, tvb(cur,1)); cur = cur + 1
  local n = tvb(cur,1):uint(); tree:add(f_pf_pcount, tvb(cur,1)); cur = cur + 1
  local rec = 13
  for i=1,n do
    if cur + rec > endpos then break end
    local st = tree:add(string.format("Player %d", i))
    st:add(f_pf_pid,        tvb(cur+0,1))
    st:add(f_pf_is_pure,    tvb(cur+1,1))
    st:add(f_pf_accuracy,   tvb(cur+2,1))
    st:add(f_pf_streak_max, tvb(cur+3,2))
    st:add(f_pf_streak_cur, tvb(cur+5,2))
    st:add(f_pf_kills,      tvb(cur+7,2))
    st:add(f_pf_deaths,     tvb(cur+9,2))
    st:add(f_pf_tk,         tvb(cur+11,2))
    cur = cur + rec
  end
  add_reserved3(tree, tvb, cur, endpos, f_pf_res3)
  set_info(pinfo, string.format("(PF player_stats N=%d)", n))
end

local function dissect_pf_announce_player(tvb, pinfo, tree, off, len)
  if len < 5 then return end
  local cur = off
  tree:add(f_pf_ver,     tvb(cur,1)); cur = cur + 1
  tree:add(f_pf_pid,     tvb(cur,1)); cur = cur + 1
  tree:add(f_pf_is_pure, tvb(cur,1)); cur = cur + 1
  add_reserved3(tree, tvb, cur, off + len, f_pf_res3)
  set_info(pinfo, "(PF announce_player)")
end

local function dissect_pf_players(tvb, pinfo, tree, off, len)
  if len < 2 then return end
  local cur = off
  local endpos = off + len
  tree:add(f_pf_ver, tvb(cur,1)); cur = cur + 1
  local show_ip = tvb(cur,1):uint(); tree:add(f_pf_show_ip, tvb(cur,1)); cur = cur + 1
  local list = tree:add("Players")
  local tail = 3
  while cur < endpos - tail do
    local row = list:add("Player")
    if show_ip ~= 0 then
      if cur + 4 > endpos - tail then break end
      row:add(f_pf_ip, tvb(cur,4)); cur = cur + 4
    end
    if cur >= endpos - tail then break end
    local name, nextpos = read_cstr(tvb, cur, endpos - tail)
    row:add(f_pf_name, tvb(cur, nextpos-cur))
    cur = nextpos
  end
  add_reserved3(tree, tvb, cur, endpos, f_pf_res3)
  set_info(pinfo, "(PF players)")
end

local function dissect_pf_other_simple(tvb, pinfo, tree, off, len, label)
  local st = tree:add(label or "PF Packet")
  if len > 0 then st:add_expert_info(PI_COMMENT, PI_NOTE, string.format("Payload: %d bytes", len))
  else st:add_expert_info(PI_COMMENT, PI_NOTE, "No payload") end
end

local function dissect_pf_server_hash(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local cur = off
  tree:add(f_pf_ver, tvb(cur,1)); cur = cur + 1
  -- the rest is hash/flags; show as bytes if present
  if len - 1 > 0 then tree:add(f_rf_u8, tvb(cur,1)):set_text("Flags/Res")
    if len - 2 >= 4 then tree:add(f_rf_u32, tvb(cur+1,4)):set_text("Hash (LE)") end
  end
  set_info(pinfo, "(PF server_hash)")
end

local function dissect_pf_client_hash(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local cur = off
  tree:add(f_pf_ver, tvb(cur,1)); cur = cur + 1
  if len - 1 > 0 then tree:add(f_rf_u8, tvb(cur,1)):set_text("Flags/Res") end
  -- rest: client hash bytes
  set_info(pinfo, "(PF client_hash)")
end

local function dissect_pf_request_cheat_check(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  tree:add(f_pf_ver, tvb(off,1))
  set_info(pinfo, "(PF request_cheat_check)")
end

local function dissect_pf_client_cheat_check(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  tree:add(f_pf_ver, tvb(off,1))
  set_info(pinfo, "(PF client_cheat_check)")
end

-- ---------- PF version pretty-printer (use once, above rf_game_info) ----------
local function pf_ver_to_string(u16)
  -- Layout: 0xMMXY -> "M.Xy", where X is 0..9 and y is a..f (10..15)
  local maj  = math.floor(u16 / 256)
  local byte = u16 % 256
  local hi   = math.floor(byte / 16)        -- 0..9
  local lo   = byte % 16                    -- 0..15 (10..15 -> 'a'..'f')
  local loch = (lo < 10) and tostring(lo) or string.char(87 + lo) -- 10->'a'(97)
  return string.format("%d.%s%s", maj, tostring(hi), loch)
end




local function dissect_pf(gt, tvb, pinfo, tree, off, len, hdr_off)
  tree:add(f_pf_type, tvb(hdr_off, 1))
  if     gt == 0x2A then dissect_pf_player_stats    (tvb, pinfo, tree, off, len)
  elseif gt == 0x40 then dissect_pf_announce_player (tvb, pinfo, tree, off, len)
  elseif gt == 0xA1 then dissect_pf_players         (tvb, pinfo, tree, off, len)
  elseif gt == 0x3B then dissect_pf_server_hash            (tvb, pinfo, tree, off, len)
  elseif gt == 0x3C then dissect_pf_client_hash            (tvb, pinfo, tree, off, len)
  elseif gt == 0x3D then dissect_pf_request_cheat_check    (tvb, pinfo, tree, off, len)
  elseif gt == 0x3E then dissect_pf_client_cheat_check     (tvb, pinfo, tree, off, len)
  elseif gt == 0x3A then dissect_pf_other_simple    (tvb, pinfo, tree, off, len, "PF players_request")
  
  else tree:add_expert_info(PI_UNDECODED, PI_NOTE, string.format("Unhandled PF 0x%02X", gt))
  end
  pinfo.cols.protocol = "RF/PF"
  pinfo.cols.info = string.format("Game (PF %s)", PF_TypeNames[gt] or string.format("0x%02X", gt))
end

-- ========= CLASSIC RF =========

-- GAME_INFO (attempts to parse known layout + AF tail + PF suffix)
local function rf_game_info(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local cur, endpos = off, off+len
  tree:add(f_rf_u8, tvb(cur,1)):set_text("Version: "..tvb(cur,1):uint()); cur=cur+1
  local name; name, cur = read_cstr(tvb, cur, endpos)
  if #name>0 then tree:add(f_rf_str, tvb(cur-#name-1, #name+1)):set_text("Server Name: "..name) end
  if cur+3 <= endpos then
    local gt = tvb(cur,1):uint(); tree:add(f_rf_u8, tvb(cur,1)):set_text("Game Type: "..gt); cur=cur+1
    tree:add(f_rf_u8, tvb(cur,1)):set_text("Players Count: "..tvb(cur,1):uint()); cur=cur+1
    tree:add(f_rf_u8, tvb(cur,1)):set_text("Max Players: "..tvb(cur,1):uint()); cur=cur+1
  end
  local level; level, cur = read_cstr(tvb, cur, endpos); if #level>0 then tree:add(f_rf_str, tvb(cur-#level-1, #level+1)):set_text("Level: "..level) end
  local mod; mod, cur = read_cstr(tvb, cur, endpos);     if #mod>0   then tree:add(f_rf_str, tvb(cur-#mod-1,   #mod+1  )):set_text("Mod: "..mod) end
  if cur < endpos then tree:add(f_rf_srvflags, tvb(cur,1)); cur=cur+1 end

  -- Try to parse AF GAME_INFO tail (appended): [sig u32][verM u8][verN u8][verP u8][verT u8][flags u32][opt: level filename zstr]
  if endpos - cur >= 12 and tvb(cur,4):le_uint() == ALPINE_FACTION_SIGNATURE then
    local t = tree:add("AF GameInfo Tail")
    t:add(f_af_gi_sig,   tvb(cur+0,4))
    t:add(f_af_ver_maj,  tvb(cur+4,1))
    t:add(f_af_ver_min,  tvb(cur+5,1))
    t:add(f_af_ver_pat,  tvb(cur+6,1))
    t:add(f_af_ver_type, tvb(cur+7,1))
    t:add(f_af_gi_flags, tvb(cur+8,4))
    cur = cur + 12
    if cur < endpos then
      local af_level, nx = read_cstr(tvb, cur, endpos)
      if nx <= endpos then
        t:add(f_af_gi_level, tvb(cur, nx-cur))
        cur = nx
      end
    end
    set_info(pinfo, "(AF server)")
  end

-- ---------- inside rf_game_info(...) replace your try_pf_suffix_scan with this ----------
local function try_pf_suffix_scan()
  -- PF suffix: 6 bytes at the very end of the datagram or just before an AF tail.
  -- Layout: PF sig (DE AD BE EF on wire -> tvb:le_uint() == 0xEFBEADDE) + u16 PF version (LE)
  local window = math.min(128, len)                   -- scan the last N bytes
  local start  = math.max(off, endpos - window)
  for i = endpos - 6, start, -1 do
    if i >= off and (i + 6) <= endpos and tvb(i,4):le_uint() == PF_GAME_INFO_SIGNATURE then
      local sub = tree:add("PF GameInfo Suffix")
      sub:add(f_pf_gi_sig, tvb(i,4))
      local ver = tvb(i+4,2):le_uint()
      local pretty = pf_ver_to_string(ver)
      sub:add(f_pf_gi_ver, tvb(i+4,2))
         :set_text(string.format("PF Version: 0x%04X (%s)", ver, pretty))
      set_info(pinfo, "(PF server)")
      return true
    end
  end
  return false
end

-- call it after AF tail attempt (order doesn’t matter; scan finds it either way)
try_pf_suffix_scan()


  set_info(pinfo, "(GAME_INFO)")
end

-- JOIN_REQUEST (base + AF/DF tails)
local function rf_join_request(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local cur, endpos = off, off+len
  local ver = tvb(cur,1):uint(); tree:add(f_rf_u8, tvb(cur,1)):set_text("Version: "..ver); cur=cur+1
  local name; name, cur = read_cstr(tvb, cur, endpos); tree:add(f_rf_str, tvb(cur-#name-1, #name+1)):set_text("Player Name: "..name)
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Entity Type"); cur=cur+4 end
  local pw; pw, cur = read_cstr(tvb, cur, endpos); if #pw>0 then tree:add(f_rf_str, tvb(cur-#pw-1, #pw+1)):set_text("Password: "..pw) end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Rate (bytes/s)"); cur=cur+4 end
  if ver == 0x87 and cur+16 <= endpos then
    tree:add(f_rf_u32, tvb(cur,4)):set_text("meshes_vpp_checksum"); cur=cur+4
    tree:add(f_rf_u32, tvb(cur,4)):set_text("meshes_vpp_size"); cur=cur+4
    tree:add(f_rf_u32, tvb(cur,4)):set_text("motions_vpp_checksum"); cur=cur+4
    tree:add(f_rf_u32, tvb(cur,4)):set_text("motions_vpp_size"); cur=cur+4
  end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("tables_vpp_checksum"); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("tables_vpp_size"); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("mod_vpp_checksum"); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("mod_vpp_size"); cur=cur+4 end

  -- ==== Alpine/Dash extended tails (scan tail variants) ====
  local function parse_af_v3_tail()
    if endpos - off < 6 then return false end
    local magic = tvb(endpos-4,4):le_uint()
    if magic ~= AFTR_MAGIC then return false end
    local total_len = tvb(endpos-6,2):le_uint()
    if total_len < 16 or (total_len+6) > (endpos - off) then return false end
    local af_start = endpos - 6 - total_len
    if tvb(af_start,4):le_uint() ~= ALPINE_FACTION_SIGNATURE then return false end
    local st = tree:add("AF JoinReq Tail v3")
    st:add(f_af_jr_total, tvb(endpos-6,2))
    st:add(f_af_jr_magic, tvb(endpos-4,4))
    st:add(f_af_jr_sig,     tvb(af_start+0,4))
    st:add(f_af_jr_vermaj,  tvb(af_start+4,1))
    st:add(f_af_jr_vermin,  tvb(af_start+5,1))
    st:add(f_af_jr_verpat,  tvb(af_start+6,1))
    st:add(f_af_jr_vertype, tvb(af_start+7,1))
    st:add(f_af_jr_maxrfl,  tvb(af_start+8,4))
    st:add(f_af_jr_flags,   tvb(af_start+12,4))
    local tlv_off = af_start + 16
    local tlv_len = total_len - 16
    if tlv_len > 0 then st:add(f_af_jr_tlvs, tvb(tlv_off, tlv_len)) end
    set_info(pinfo, "(AF JR v3)")
    return true
  end

  local function parse_af_v2_tail()
    -- size: 16 bytes
    if endpos - off < 16 then return false end
    local pos = endpos - 16
    if tvb(pos,4):le_uint() ~= ALPINE_FACTION_SIGNATURE then return false end
    local st = tree:add("AF JoinReq Tail v2")
    st:add(f_af_jr_sig,     tvb(pos+0,4))
    st:add(f_af_jr_vermaj,  tvb(pos+4,1))
    st:add(f_af_jr_vermin,  tvb(pos+5,1))
    st:add(f_af_jr_verpat,  tvb(pos+6,1))
    st:add(f_af_jr_vertype, tvb(pos+7,1))
    st:add(f_af_jr_maxrfl,  tvb(pos+8,4))
    st:add(f_af_jr_flags,   tvb(pos+12,4))
    set_info(pinfo, "(AF JR v2)")
    return true
  end

  local function parse_af_v1_tail()
    -- size: 12 bytes
    if endpos - off < 12 then return false end
    local pos = endpos - 12
    if tvb(pos,4):le_uint() ~= ALPINE_FACTION_SIGNATURE then return false end
    local st = tree:add("AF JoinReq Tail v1")
    st:add(f_af_jr_sig,     tvb(pos+0,4))
    st:add(f_af_jr_vermaj,  tvb(pos+4,1))
    st:add(f_af_jr_vermin,  tvb(pos+5,1))
    -- pos+6,pos+7 are padding in AF v1
    st:add(f_af_jr_flags,   tvb(pos+8,4))
    set_info(pinfo, "(AF JR v1)")
    return true
  end

  local function parse_df_tail()
    -- size: 8 bytes
    if endpos - off < 8 then return false end
    local pos = endpos - 8
    if tvb(pos,4):le_uint() ~= DASH_FACTION_SIGNATURE then return false end
    local st = tree:add("Dash Faction JoinReq Tail")
    st:add(f_af_jr_sig,     tvb(pos+0,4))
    st:add(f_af_jr_vermaj,  tvb(pos+4,1))
    st:add(f_af_jr_vermin,  tvb(pos+5,1))
    -- pos+6,pos+7 padding in DF
    set_info(pinfo, "(DF JR)")
    return true
  end

  if not (parse_af_v3_tail() or parse_af_v2_tail() or parse_af_v1_tail() or parse_df_tail()) then
    -- nothing recognized; it's fine
  end

  set_info(pinfo, "(JOIN_REQUEST)")
end

-- JOIN_ACCEPT (level string + rest + AF ext tail)
local function rf_join_accept(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local level; level, cur = read_cstr(tvb, cur, endpos); if #level>0 then tree:add(f_rf_str, tvb(cur-#level-1, #level+1)):set_text("Level: "..level) end
  if cur + 4*3 + 4 + 4 + 1 + 4 + 4 + 4 <= endpos then
    tree:add(f_rf_u32, tvb(cur+0,4)):set_text("Level checksum"); 
    tree:add(f_rf_u32, tvb(cur+4,4)):set_text("Game type");
    tree:add(f_rf_gameopt, tvb(cur+8,4))
    tree:add(f_rf_f32, tvb(cur+12,4)):set_text("Level time")
    tree:add(f_rf_f32, tvb(cur+16,4)):set_text("Time limit")
    tree:add(f_rf_u8,  tvb(cur+20,1)):set_text("Player ID")
    tree:add(f_rf_pflags, tvb(cur+21,4))
  end

  -- Try to parse AF JoinAccept tail at the very end.
  -- Structure (likely 20 bytes with padding): [sig u32][maj u8][min u8][pad u8 u8][flags u32][max_fov f32][cooldown i32]
  local function try_af_ja(sz, flag_off, fov_off, cd_off)
    if endpos - off < sz then return false end
    local pos = endpos - sz
    if tvb(pos,4):le_uint() ~= ALPINE_FACTION_SIGNATURE then return false end
    local st = tree:add("AF JoinAccept Tail")
    st:add(f_af_ja_sig,    tvb(pos+0,4))
    st:add(f_af_ja_vermaj, tvb(pos+4,1))
    st:add(f_af_ja_vermin, tvb(pos+5,1))
    st:add(f_af_ja_flags,  tvb(pos+flag_off,4))
    add_flags32(st, tvb(pos+flag_off,4), AF_JoinAcceptFlags)
    st:add(f_af_ja_fov,    tvb(pos+fov_off,4))
    st:add(f_af_ja_cd,     tvb(pos+cd_off,4))
    set_info(pinfo, "(AF join_accept)")
    return true
  end
  -- Prefer padded 20-byte layout; fallback to 18 just in case.
  if not (try_af_ja(20, 8, 12, 16) or try_af_ja(18, 6, 10, 14)) then
    -- no AF tail present
  end

  set_info(pinfo, "(JOIN_ACCEPT)")
end

local function rf_join_deny(tvb, pinfo, tree, off, len)
  if len >= 1 then tree:add(f_rf_u8, tvb(off,1)):set_text("Reason") end
  set_info(pinfo, "(JOIN_DENY)")
end

local function rf_new_player(tvb, pinfo, tree, off, len)
  if len < 1 then return end
  local cur, endpos = off, off+len
  tree:add(f_rf_u8, tvb(cur,1)):set_text("ID"); cur=cur+1
  if cur+4 <= endpos then tree:add(f_pf_ip, tvb(cur,4)); cur=cur+4 end
  if cur+2 <= endpos then tree:add(f_rf_u16, tvb(cur,2)):set_text("Port"); cur=cur+2 end
  if cur+4 <= endpos then tree:add(f_rf_pflags, tvb(cur,4)); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Rate (bytes/s)"); cur=cur+4 end
  local name; name, cur = read_cstr(tvb, cur, endpos); if #name>0 then tree:add(f_rf_str, tvb(cur-#name-1,#name+1)):set_text("Name: "..name) end
  set_info(pinfo, "(NEW_PLAYER)")
end

-- PLAYERS list (uses RF_Player shape heuristically)
local function rf_players(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local list = tree:add("Players")
  while cur < endpos do
    if cur + 2 > endpos then break end
    local st = list:add("Player")
    local flags = tvb(cur,1):uint(); st:add(f_rf_u8, tvb(cur,1)):set_text("Flags: 0x"..string.format("%02X",flags)); cur=cur+1
    st:add(f_rf_u8, tvb(cur,1)):set_text("ID"); cur=cur+1
    if BAND(flags, 0x01) ~= 0 then if cur+4 > endpos then break end; st:add(f_rf_u32, tvb(cur,4)):set_text("Unknown (flags&1)"); cur=cur+4 end
    if cur+4 > endpos then break end; st:add(f_rf_u32, tvb(cur,4)):set_text("Unknown2"); cur=cur+4
    if cur+4 > endpos then break end; st:add(f_pf_ip, tvb(cur,4)); cur=cur+4
    if cur+2 > endpos then break end; st:add(f_rf_u16, tvb(cur,2)):set_text("Port"); cur=cur+2
    local name; name, cur = read_cstr(tvb, cur, endpos); if #name>0 then st:add(f_rf_str, tvb(cur-#name-1,#name+1)):set_text("Name: "..name) end
    if cur >= endpos then break end
    st:add(f_rf_team, tvb(cur,1)); cur=cur+1
  end
  set_info(pinfo, "(PLAYERS)")
end

local function rf_left_game(tvb, pinfo, tree, off, len)
  if len >= 2 then
    tree:add(f_rf_u8, tvb(off,1)):set_text("Player ID")
    tree:add(f_rf_u8, tvb(off+1,1)):set_text("Reason")
  end
  set_info(pinfo, "(LEFT_GAME)")
end

local function rf_state_info_request(tvb, pinfo, tree, off, len)
  local level, _ = read_cstr(tvb, off, off+len)
  if #level>0 then tree:add(f_rf_str, tvb(off, #level+1)):set_text("Level: "..level) end
  set_info(pinfo, "(STATE_INFO_REQUEST)")
end

local function rf_trigger_activate(tvb, pinfo, tree, off, len)
  if len >= 8 then
    tree:add(f_rf_u32, tvb(off,4)):set_text("Trigger UID")
    tree:add(f_rf_u32, tvb(off+4,4)):set_text("Entity Handle")
  end
  set_info(pinfo, "(TRIGGER_ACTIVATE)")
end

local function rf_pregame_glass(tvb, pinfo, tree, off, len)
  if len > 0 then tree:add(f_rf_u8, tvb(off, len)):set_text("Rooms Bitmap ("..len.." bytes)") end
  set_info(pinfo, "(PREGAME_GLASS)")
end

local function rf_chat_line(tvb, pinfo, tree, off, len)
  if len < 2 then return end
  local cur, endpos = off, off+len
  tree:add(f_rf_u8, tvb(cur,1)):set_text("Player ID"); cur=cur+1
  local team = tvb(cur,1):uint(); tree:add(f_rf_u8, tvb(cur,1)):set_text(team==0 and "Global" or "Team"); cur=cur+1
  local msg; msg, cur = read_cstr(tvb, cur, endpos)
  if #msg>0 then tree:add(f_rf_str, tvb(cur-#msg-1, #msg+1)):set_text("Message: "..msg) end
  set_info(pinfo, "(CHAT)")
end

local function rf_name_change(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  if cur >= endpos then return end
  tree:add(f_rf_u8, tvb(cur,1)):set_text("Player ID"); cur=cur+1
  local name; name, cur = read_cstr(tvb, cur, endpos)
  if #name>0 then tree:add(f_rf_str, tvb(cur-#name-1, #name+1)):set_text("New Name: "..name) end
  set_info(pinfo, "(NAME_CHANGE)")
end

local function rf_respawn_request(tvb, pinfo, tree, off, len)
  if len >= 5 then
    tree:add(f_rf_u32, tvb(off,4)):set_text("Character Index")
    tree:add(f_rf_u8,  tvb(off+4,1)):set_text("Player ID")
  end
  set_info(pinfo, "(RESPAWN_REQUEST)")
end

local function rf_leave_limbo(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local level; level, cur = read_cstr(tvb, cur, endpos)
  if #level>0 then tree:add(f_rf_str, tvb(cur-#level-1, #level+1)):set_text("Level: "..level) end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Level checksum") end
  set_info(pinfo, "(LEAVE_LIMBO)")
end

local function rf_team_change(tvb, pinfo, tree, off, len)
  if len >= 2 then
    tree:add(f_rf_u8,  tvb(off,1)):set_text("Player ID")
    tree:add(f_rf_team,tvb(off+1,1))
  end
  set_info(pinfo, "(TEAM_CHANGE)")
end

local function rf_netgame_update(tvb, pinfo, tree, off, len)
  if len < 2 then return end
  local cur, endpos = off, off+len
  tree:add(f_rf_u8, tvb(cur,1)):set_text("Unknown"); cur=cur+1
  local n = tvb(cur,1):uint(); tree:add(f_rf_u8, tvb(cur,1)):set_text("Player Count: "..n); cur=cur+1
  local rec = 8
  for i=1,n do
    if cur + rec > endpos then break end
    local st = tree:add(string.format("PlayerStats %d", i))
    st:add(f_rf_u8,  tvb(cur+0,1)):set_text("ID")
    st:add(f_rf_u16, tvb(cur+1,2)):set_text("Ping")
    st:add(f_rf_u8,  tvb(cur+3,1)):set_text("Unknown")
    st:add(f_rf_i16, tvb(cur+4,2)):set_text("Score")
    st:add(f_rf_u8,  tvb(cur+6,1)):set_text("Captures")
    st:add(f_rf_u8,  tvb(cur+7,1)):set_text("Unknown2")
    cur = cur + rec
  end
  if cur + 8 <= endpos then
    tree:add(f_rf_f32, tvb(cur,4)):set_text("Level time"); cur=cur+4
    tree:add(f_rf_f32, tvb(cur,4)):set_text("Time limit")
  end
  set_info(pinfo, "(NETGAME_UPDATE)")
end

local function rf_rate_change(tvb, pinfo, tree, off, len)
  if len >= 3 then
    tree:add(f_rf_u8,  tvb(off,1)):set_text("Player ID")
    tree:add(f_rf_u16, tvb(off+1,2)):set_text("New Rate (bytes/s)")
  end
  set_info(pinfo, "(RATE_CHANGE)")
end

local function rf_pregame_clutter(tvb, pinfo, tree, off, len)
  if len < 4 then return end
  local count = tvb(off,4):le_uint()
  tree:add(f_rf_u32, tvb(off,4)):set_text("Clutter Count: "..count)
  if len > 4 then
    tree:add(f_rf_u8, tvb(off+4, len-4)):set_text("Clutter Bitmap ("..(len-4).." bytes)")
  end
  set_info(pinfo, "(PREGAME_CLUTTER)")
end

local function rf_clutter_kill(tvb, pinfo, tree, off, len)
  if len >= 8 then
    tree:add(f_rf_u32, tvb(off,4)):set_text("UID")
    tree:add(f_rf_u32, tvb(off+4,4)):set_text("Reason?")
  end
  set_info(pinfo, "(CLUTTER_KILL)")
end

local function rf_ctf_picked_up(tvb, pinfo, tree, off, len)
  if len >= 3 then
    tree:add(f_rf_u8,  tvb(off,1)):set_text("Player ID")
    tree:add(f_rf_u8,  tvb(off+1,1)):set_text("Flags Red")
    tree:add(f_rf_u8,  tvb(off+2,1)):set_text("Flags Blue")
  end
  set_info(pinfo, "(CTF_PICKED_UP)")
end

local function rf_ctf_captured(tvb, pinfo, tree, off, len)
  if len >= 4 then
    tree:add(f_rf_team, tvb(off,1))
    tree:add(f_rf_u8,   tvb(off+1,1)):set_text("Player ID")
    tree:add(f_rf_u8,   tvb(off+2,1)):set_text("Flags Red")
    tree:add(f_rf_u8,   tvb(off+3,1)):set_text("Flags Blue")
  end
  set_info(pinfo, "(CTF_CAPTURED)")
end

local function rf_ctf_update(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local function side(label)
    if cur >= endpos then return end
    local block = tree:add(label)
    local pid = tvb(cur,1):uint(); block:add(f_rf_u8, tvb(cur,1)):set_text("Player ID or 0xFF"); cur=cur+1
    if pid == 0xFF then
      if cur >= endpos then return end
      local in_base = tvb(cur,1):uint(); block:add(f_rf_u8, tvb(cur,1)):set_text("In Base: "..in_base); cur=cur+1
      if in_base == 0 and cur + 12 + 36 <= endpos then
        cur = cur + add_vec3(block, tvb, cur, "pos")
        cur = cur + add_matrix3(block, tvb, cur, "orient")
      end
    end
  end
  side("Red Flag")
  side("Blue Flag")
  set_info(pinfo, "(CTF_UPDATE)")
end

local function rf_ctf_returned(tvb, pinfo, tree, off, len)
  if len >= 4 then
    tree:add(f_rf_team, tvb(off,1))
    tree:add(f_rf_u8,   tvb(off+1,1)):set_text("Player ID")
    tree:add(f_rf_u8,   tvb(off+2,1)):set_text("Flags Red")
    tree:add(f_rf_u8,   tvb(off+3,1)):set_text("Flags Blue")
  end
  set_info(pinfo, "(CTF_RETURNED)")
end

local function rf_ctf_dropped(tvb, pinfo, tree, off, len)
  if len >= 1+1+1+12 then
    tree:add(f_rf_team, tvb(off,1))
    tree:add(f_rf_u8,   tvb(off+1,1)):set_text("Flags Red")
    tree:add(f_rf_u8,   tvb(off+2,1)):set_text("Flags Blue")
    add_vec3(tree, tvb, off+3, "pos")
  end
  set_info(pinfo, "(CTF_DROPPED)")
end

local function rf_remote_charge_kill(tvb, pinfo, tree, off, len)
  if len >= 5 then
    tree:add(f_rf_u32, tvb(off,4)):set_text("Entity Handle")
    tree:add(f_rf_u8,  tvb(off+4,1)):set_text("Player ID")
  end
  set_info(pinfo, "(REMOTE_CHARGE_KILL)")
end

local function rf_item_update(tvb, pinfo, tree, off, len)
  if len >= 25 then tree:add(f_rf_u8, tvb(off,25)):set_text("Level Items Bitmap (25 bytes)") end
  set_info(pinfo, "(ITEM_UPDATE)")
end

-- OBJECT_UPDATE (loop until 0xFFFFFFFF terminator)
local function rf_object_update(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local idx = 1
  while cur + 5 <= endpos do
    if tvb(cur,4):le_uint() == 0xFFFFFFFF then
      tree:add(f_rf_u32, tvb(cur,4)):set_text("Terminator"); cur = cur + 4; break
    end
    local st = tree:add(string.format("Object %d", idx))
    st:add(f_rf_u32, tvb(cur,4)):set_text("Handle"); cur=cur+4
    local flags = tvb(cur,1):uint(); add_flags8(st, tvb(cur,1), RF_ObjectUpdateFlags); cur=cur+1

    if BAND(flags, 0x01) ~= 0 then
      if cur + 2 + 12 + 2 + 2 + 1 + 1 + 1 + 1 <= endpos then
        st:add(f_rf_u16, tvb(cur,2)):set_text("Ticks"); cur=cur+2
        cur = cur + add_vec3(st, tvb, cur, "pos")
        st:add(f_rf_i16, tvb(cur,2)):set_text("angle_x"); cur=cur+2
        st:add(f_rf_i16, tvb(cur,2)):set_text("angle_y"); cur=cur+2
        st:add(f_rf_flags8, tvb(cur,1)):set_text("state_flags"); cur=cur+1
        st:add(f_rf_i16, tvb(cur,1)):set_text("move_dir_x"); cur=cur+1
        st:add(f_rf_i16, tvb(cur,1)):set_text("move_dir_y"); cur=cur+1
        st:add(f_rf_i16, tvb(cur,1)):set_text("move_speed");  cur=cur+1
      end
    end
    if BAND(flags, 0x80) ~= 0 then if cur+1<=endpos then st:add(f_rf_flags8, tvb(cur,1)):set_text("amp_flags"); cur=cur+1 end end
    if BAND(flags, 0x04) ~= 0 then if cur+1<=endpos then st:add(f_rf_weapon, tvb(cur,1)); cur=cur+1 end end
    if BAND(flags, 0x20) ~= 0 then if cur+3<=endpos then
      st:add(f_rf_u8, tvb(cur+0,1)):set_text("Health")
      st:add(f_rf_u8, tvb(cur+1,1)):set_text("Armor")
      st:add(f_rf_u8, tvb(cur+2,1)):set_text("Unknown2")
      cur=cur+3
    end end
    if BAND(flags, 0x08) ~= 0 then
      if cur+1 <= endpos then
        local c = tvb(cur,1):uint(); st:add(f_rf_u8, tvb(cur,1)):set_text("Unknown3 Count"); cur=cur+1
        local need = c*3
        if cur+need <= endpos then st:add(f_rf_u8, tvb(cur, need)):set_text("Unknown3 Data ("..need.." bytes)"); cur=cur+need end
      end
    end
    if BAND(flags, 0x02) ~= 0 then if cur+2<=endpos then st:add(f_rf_u16, tvb(cur,2)):set_text("Unknown4"); cur=cur+2 end end
    idx = idx + 1
  end
  set_info(pinfo, "(OBJECT_UPDATE)")
end

local function rf_object_kill(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  if cur + 4 + 4 + 1 + 1 + 2 + 1 > endpos then return end
  tree:add(f_rf_u32, tvb(cur,4)):set_text("Entity Handle"); cur=cur+4
  tree:add(f_rf_f32, tvb(cur,4)):set_text("Unknown (life?)"); cur=cur+4
  tree:add(f_rf_u8,  tvb(cur,1)):set_text("Killer ID"); cur=cur+1
  tree:add(f_rf_u8,  tvb(cur,1)):set_text("Killed ID"); cur=cur+1
  tree:add(f_rf_u16, tvb(cur,2)):set_text("Animation");  cur=cur+2
  local flags = tvb(cur,1):uint(); tree:add(f_rf_flags8, tvb(cur,1)):set_text("Kill Flags: 0x"..string.format("%02X",flags)); cur=cur+1
  if BAND(flags, 0x03) ~= 0 then
    if cur+2 <= endpos then tree:add(f_rf_u16, tvb(cur,2)):set_text("Unknown2"); cur=cur+2 end
    if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Item Type"); cur=cur+4 end
    if cur+8 <= endpos then tree:add(f_rf_u8, tvb(cur,8)):set_text("Unknown4 (8 bytes)"); cur=cur+8 end
    if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Item Handle"); cur=cur+4 end
    if cur+12 <= endpos then cur = cur + add_vec3(tree, tvb, cur, "item_pos") end
    if cur+36 <= endpos then cur = cur + add_matrix3(tree, tvb, cur, "rot_matrix") end
  end
  set_info(pinfo, "(OBJECT_KILL)")
end

local function rf_item_apply(tvb, pinfo, tree, off, len)
  if len >= 20 then
    tree:add(f_rf_u32, tvb(off+0,4)):set_text("Item Handle")
    tree:add(f_rf_u32, tvb(off+4,4)):set_text("Entity Handle")
    tree:add(f_rf_u32, tvb(off+8,4)):set_text("Weapon (0xFFFFFFFF none)")
    tree:add(f_rf_u32, tvb(off+12,4)):set_text("Ammo")
    tree:add(f_rf_u32, tvb(off+16,4)):set_text("Clip Ammo")
  end
  set_info(pinfo, "(ITEM_APPLY)")
end

local function rf_entity_create(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local name; name, cur = read_cstr(tvb, cur, endpos); if #name>0 then tree:add(f_rf_str, tvb(cur-#name-1, #name+1)):set_text("Entity Name: "..name) end
  if cur + 1+1+4+4+12+36+1+4+4+4 <= endpos then
    tree:add(f_rf_team, tvb(cur+0,1))
    tree:add(f_rf_u8,   tvb(cur+1,1)):set_text("Entity Type")
    tree:add(f_rf_u32,  tvb(cur+2,4)):set_text("Entity Handle")
    tree:add(f_rf_u32,  tvb(cur+6,4)):set_text("Unknown2")
    cur = cur + 10
    cur = cur + add_vec3(tree, tvb, cur, "pos")
    cur = cur + add_matrix3(tree, tvb, cur, "orient")
    tree:add(f_rf_u8,   tvb(cur,1)):set_text("Player ID"); cur=cur+1
    tree:add(f_rf_u32,  tvb(cur,4)):set_text("Character"); cur=cur+4
    tree:add(f_rf_u32,  tvb(cur,4)):set_text("Weapon");    cur=cur+4
    tree:add(f_rf_u32,  tvb(cur,4)):set_text("Unknown3");  cur=cur+4
  end
  set_info(pinfo, "(ENTITY_CREATE)")
end

local function rf_item_create(tvb, pinfo, tree, off, len)
  local cur, endpos = off, off+len
  local s; s, cur = read_cstr(tvb, cur, endpos); if #s>0 then tree:add(f_rf_str, tvb(cur-#s-1, #s+1)):set_text("Script Name: "..s) end
  if cur+1 <= endpos then tree:add(f_rf_u8,  tvb(cur,1)):set_text("Unknown"); cur=cur+1 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Item Type"); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Respawn Time"); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Count"); cur=cur+4 end
  if cur+4 <= endpos then tree:add(f_rf_u32, tvb(cur,4)):set_text("Item Handle"); cur=cur+4 end
  if cur+2 <= endpos then tree:add(f_rf_u16, tvb(cur,2)):set_text("Item Bit"); cur=cur+2 end
  if cur+1 <= endpos then tree:add(f_rf_u8,  tvb(cur,1)):set_text("Unknown2"); cur=cur+1 end
  if cur+12 <= endpos then cur = cur + add_vec3(tree, tvb, cur, "pos") end
  if cur+36 <= endpos then cur = cur + add_matrix3(tree, tvb, cur, "rot_matrix") end
  set_info(pinfo, "(ITEM_CREATE)")
end

local function rf_reload(tvb, pinfo, tree, off, len)
  if len >= 16 then
    tree:add(f_rf_u32, tvb(off+0,4)):set_text("Entity Handle")
    tree:add(f_rf_u32, tvb(off+4,4)):set_text("Weapon")
    tree:add(f_rf_u32, tvb(off+8,4)):set_text("Clip Ammo")
    tree:add(f_rf_u32, tvb(off+12,4)):set_text("Ammo")
  end
  set_info(pinfo, "(RELOAD)")
end

local function rf_reload_request(tvb, pinfo, tree, off, len)
  if len >= 4 then tree:add(f_rf_u32, tvb(off,4)):set_text("Weapon") end
  set_info(pinfo, "(RELOAD_REQUEST)")
end

local function rf_weapon_fire(tvb, pinfo, tree, off, len)
  if len < 2 then return end
  local cur, endpos = off, off+len
  tree:add(f_rf_weapon,  tvb(cur,1)); cur=cur+1
  local flags = tvb(cur,1):uint(); tree:add(f_rf_wfflags, tvb(cur,1)); cur=cur+1
  if BAND(flags, 0x04) == 0 then
    if cur + 12 + 6 <= endpos then
      cur = cur + add_vec3(tree, tvb, cur, "pos")
      tree:add(f_rf_i16, tvb(cur+0,2)):set_text("dir_x"); 
      tree:add(f_rf_i16, tvb(cur+2,2)):set_text("dir_y");
      tree:add(f_rf_i16, tvb(cur+4,2)):set_text("dir_z");
      cur = cur + 6
    end
  end
  if BAND(flags, 0x02) ~= 0 and cur < endpos then
    tree:add(f_rf_u8, tvb(cur,1)):set_text("Unknown"); cur=cur+1
  end
  set_info(pinfo, "(WEAPON_FIRE)")
end

local function rf_fall_damage(tvb, pinfo, tree, off, len)
  if len >= 4 then tree:add(f_rf_f32, tvb(off,4)):set_text("Force?") end
  set_info(pinfo, "(FALL_DAMAGE)")
end

local function rf_sound(tvb, pinfo, tree, off, len)
  if len >= 2+12 then
    tree:add(f_rf_u16, tvb(off,2)):set_text("Sound ID")
    add_vec3(tree, tvb, off+2, "pos (NaN=pos-independent)")
  end
  set_info(pinfo, "(SOUND)")
end

local function rf_team_scores(tvb, pinfo, tree, off, len)
  if len >= 4 then
    tree:add(f_rf_u16, tvb(off,2)):set_text("Red")
    tree:add(f_rf_u16, tvb(off+2,2)):set_text("Blue")
  end
  set_info(pinfo, "(TEAM_SCORES)")
end

local function rf_glass_kill(tvb, pinfo, tree, off, len)
  if len >= 1+4+12+12 then
    tree:add(f_rf_u32, tvb(off,4)):set_text("Room ID (0x7FFFFFFF indexed from 1)")
    tree:add(f_rf_u8,  tvb(off+4,1)):set_text("Explosion (1/0)")
    add_vec3(tree, tvb, off+5, "start pos")
    tree:add(f_rf_f32, tvb(off+17,4)):set_text("Unknown #1")
    tree:add(f_rf_f32, tvb(off+21,4)):set_text("Unknown #2")
    tree:add(f_rf_f32, tvb(off+25,4)):set_text("Unknown #3")
  end
  set_info(pinfo, "(GLASS_KILL)")
end

-- ========= GAME DISSECTOR =========
local function dissect_rf_game(tvb, pinfo, tree, off)
  if off + 3 > tvb:len() then return end
  local t  = tvb(off+0,1):uint()
  local sz = tvb(off+1,2):le_uint()
  local g = tree:add(string.format("Game Header: type=0x%02X %s, size=%d",
    t, RF_GameTypeNames[t] or AF_TypeNames[t] or PF_TypeNames[t] or "", sz))
  g:add(f_game_type, tvb(off+0,1))
  g:add(f_game_size, tvb(off+1,2))

  local poff = off + 3
  local plen = math.max(0, math.min(sz, tvb:len() - poff))

  -- Alpine?
  if t >= 0x50 and t <= 0x56 then
    dissect_af(t, tvb, pinfo, g, poff, plen, off)
    return
  end
  -- PF?
  if PF_TypeNames[t] ~= nil then
    dissect_pf(t, tvb, pinfo, g, poff, plen, off)
    return
  end

  -- Classic RF + extensions
  if     t == 0x01 then rf_game_info(tvb, pinfo, g, poff, plen)
  elseif t == 0x02 then rf_join_request(tvb, pinfo, g, poff, plen)
  elseif t == 0x03 then rf_join_accept (tvb, pinfo, g, poff, plen)
  elseif t == 0x04 then rf_join_deny   (tvb, pinfo, g, poff, plen)
  elseif t == 0x05 then rf_new_player  (tvb, pinfo, g, poff, plen)
  elseif t == 0x06 then rf_players     (tvb, pinfo, g, poff, plen)
  elseif t == 0x07 then rf_left_game   (tvb, pinfo, g, poff, plen)
  elseif t == 0x09 then rf_state_info_request(tvb, pinfo, g, poff, plen)
  elseif t == 0x0C then rf_chat_line   (tvb, pinfo, g, poff, plen)
  elseif t == 0x0D then rf_name_change (tvb, pinfo, g, poff, plen)
  elseif t == 0x0E then rf_respawn_request(tvb, pinfo, g, poff, plen)
  elseif t == 0x10 then g:add_expert_info(PI_COMMENT, PI_NOTE, "USE_KEY_PRESSED")
  elseif t == 0x12 then rf_pregame_glass   (tvb, pinfo, g, poff, plen)
  elseif t == 0x15 then g:add_expert_info(PI_COMMENT, PI_NOTE, "ENTER_LIMBO")
  elseif t == 0x16 then rf_leave_limbo     (tvb, pinfo, g, poff, plen)
  elseif t == 0x17 then rf_team_change     (tvb, pinfo, g, poff, plen)
  elseif t == 0x18 then g:add_expert_info(PI_COMMENT, PI_NOTE, "PING")
  elseif t == 0x19 then g:add_expert_info(PI_COMMENT, PI_NOTE, "PONG")
  elseif t == 0x1A then rf_netgame_update  (tvb, pinfo, g, poff, plen)
  elseif t == 0x1B then rf_rate_change     (tvb, pinfo, g, poff, plen)
  elseif t == 0x1E then rf_clutter_kill    (tvb, pinfo, g, poff, plen)
  elseif t == 0x1F then rf_ctf_picked_up   (tvb, pinfo, g, poff, plen)
  elseif t == 0x20 then rf_ctf_captured    (tvb, pinfo, g, poff, plen)
  elseif t == 0x21 then rf_ctf_update      (tvb, pinfo, g, poff, plen)
  elseif t == 0x22 then rf_ctf_returned    (tvb, pinfo, g, poff, plen)
  elseif t == 0x23 then rf_ctf_dropped     (tvb, pinfo, g, poff, plen)
  elseif t == 0x24 then rf_remote_charge_kill(tvb, pinfo, g, poff, plen)
  elseif t == 0x25 then rf_item_update     (tvb, pinfo, g, poff, plen)
  elseif t == 0x26 then rf_object_update   (tvb, pinfo, g, poff, plen)
  elseif t == 0x27 then rf_object_kill     (tvb, pinfo, g, poff, plen)
  elseif t == 0x28 then rf_item_apply      (tvb, pinfo, g, poff, plen)
  elseif t == 0x2C then rf_entity_create   (tvb, pinfo, g, poff, plen)
  elseif t == 0x2D then rf_item_create     (tvb, pinfo, g, poff, plen)
  elseif t == 0x2E then rf_reload          (tvb, pinfo, g, poff, plen)
  elseif t == 0x2F then rf_reload_request  (tvb, pinfo, g, poff, plen)
  elseif t == 0x30 then rf_weapon_fire     (tvb, pinfo, g, poff, plen)
  elseif t == 0x31 then rf_fall_damage     (tvb, pinfo, g, poff, plen)
  elseif t == 0x34 then rf_sound           (tvb, pinfo, g, poff, plen)
  elseif t == 0x35 then rf_team_scores     (tvb, pinfo, g, poff, plen)
  elseif t == 0x36 then rf_glass_kill      (tvb, pinfo, g, poff, plen)
  else
    g:add_expert_info(PI_UNDECODED, PI_NOTE, string.format("Unhandled RF type 0x%02X (%s)", t, RF_GameTypeNames[t] or ""))
  end
  pinfo.cols.protocol = "RF"
  pinfo.cols.info = string.format("Game (%s)", RF_GameTypeNames[t] or string.format("0x%02X", t))
end

-- ========= RELIABLE / TRACKER =========
local function dissect_rf_reliable(tvb, pinfo, tree, off)
  if off + 1 > tvb:len() then return end

  local rel_type = tvb(off+0,1):uint()
  local rel = tree:add(string.format("Reliable Envelope: type=0x%02X", rel_type))
  rel:add(f_rel_type, tvb(off+0,1))

  -- Minimum header is 10 bytes: [type u8][unk u8][id u16][len u16][ticks u32]
  local avail = tvb:len() - off
  if avail >= 10 then
    rel:add(f_rel_unknown, tvb(off+1,1))
    rel:add(f_rel_id,      tvb(off+2,2))
    rel:add(f_rel_len,     tvb(off+4,2))
    rel:add(f_rel_ticks,   tvb(off+6,4))

    local data_len = tvb(off+4,2):le_uint()
    local data_off = off + 10
    local have     = math.max(0, tvb:len() - data_off)

    if data_len == 0 then
      rel:add_expert_info(PI_COMMENT, PI_NOTE, "No Reliable payload (ack/keepalive)")
    elseif have >= data_len and data_len >= 3 then
      -- Walk embedded Game packets: [type u8][size u16][payload...]
      local cursor, remain, idx = data_off, data_len, 1
      while remain >= 3 do
        local sub_sz = tvb(cursor+1,2):le_uint() + 3
        if sub_sz > remain then break end
        local sub_t = tvb(cursor+0,1):uint()
        local sg = rel:add(string.format(
          "Reliable Data #%d: Game type=0x%02X, size=%d", idx, sub_t, sub_sz-3))
        dissect_rf_game(tvb, pinfo, sg, cursor)
        cursor, remain, idx = cursor + sub_sz, remain - sub_sz, idx + 1
      end
      if remain > 0 then
        rel:add_expert_info(PI_UNDECODED, PI_NOTE,
          string.format("Remaining %d bytes (not parsed)", remain))
      end
    else
      -- Truncated capture or bad length
      rel:add_expert_info(PI_UNDECODED, PI_NOTE,
        string.format("Reliable payload len=%d, have=%d (no embedded Game data)", data_len, have))
    end
  else
    rel:add_expert_info(PI_MALFORMED, PI_WARN, "Too short for Reliable envelope (need ≥10 bytes)")
  end

  set_info(pinfo, "(Reliable)")
end

local function dissect_rf_tracker(tvb, pinfo, tree, off)
  if off + 9 > tvb:len() then
    tree:add_expert_info(PI_MALFORMED, PI_WARN, "Too short for Tracker header")
    return
  end
  local tr = tree:add("Tracker Header")
  tr:add(f_trk_u0,   tvb(off+0,1))
  tr:add(f_trk_type, tvb(off+1,2))
  tr:add(f_trk_seq,  tvb(off+3,4))
  tr:add(f_trk_plen, tvb(off+7,2))
  set_info(pinfo, "(Tracker)")
end

-- ========= HEURISTICS & MAIN =========
local function looks_like_rf(tvb)
  if tvb:len() < 1 then return false end
  local m = tvb(0,1):uint()
  if m == 0x00 then return tvb:len() >= 3
  elseif m == 0x01 then return tvb:len() >= 3
  elseif m == 0x02 then return tvb:len() >= 5
  else return false end
end

function rf_proto.dissector(tvb, pinfo, tree)
  if tvb:len() < 1 then return end
  pinfo.cols.protocol = "RF"
  pinfo.cols.info = ""

  local root = tree:add(rf_proto, tvb(), "Red Faction")
  root:add(f_raw_len, tvb:len())

  local mtype = tvb(0,1):uint()
  root:add(f_main_type, tvb(0,1))
  pinfo.cols.info = RF_MainPacketType[mtype] or string.format("Unknown(0x%02X)", mtype)

  if mtype == 0x00 then
    dissect_rf_game(tvb, pinfo, root, 1)
  elseif mtype == 0x01 then
    dissect_rf_reliable(tvb, pinfo, root, 1)
  elseif mtype == 0x02 then
    dissect_rf_tracker(tvb, pinfo, root, 1)
  else
    root:add_expert_info(PI_UNDECODED, PI_WARN, "Unrecognized RF main type")
  end
end

function rf_proto.init() end

rf_proto:register_heuristic("udp", function(tvb, pinfo, tree)
  if not looks_like_rf(tvb) then return false end
  rf_proto.dissector(tvb, pinfo, tree)
  return true
end)

-- Optional: bind known ports
-- local udp_table = DissectorTable.get("udp.port")
-- udp_table:add(7755, rf_proto)   -- typical RF server port
-- udp_table:add(18444, rf_proto)  -- tracker port

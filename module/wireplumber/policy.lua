-- vpn-zones: WirePlumber's policy for the zones' PipeWire clients
-- (docs/LEAK-MODEL.md §17, rust/src/pw_context.rs).
--
-- A hermetic zone's `pipewire-0` is a security context the zone's helper made
-- (`vpn-zone-core pipewire-context`): every client of it carries
-- pipewire.sec.engine = "vpn-zone", pipewire.sec.app-id = <zone> and
-- pipewire.access = "restricted" — properties a client cannot change. A stock
-- WirePlumber gives such a client read and execute on EVERY object: other
-- programs' streams, every monitor, the link factory. This script decides
-- instead, and the program in the zone is treated as hostile:
--
--  * nothing is visible that is not granted here: the client's default ("any")
--    permission is none — set by the access rule shipped beside this script
--    (90-vpn-zones.conf) and again here; the core only once the rest is set
--    (a client without R on the core is held by the daemon);
--  * its own stream nodes and their ports: yes (rwx on the nodes, r on the
--    ports), the streams of the zone's other programs read only; any other
--    node of its own — a virtual sink or source, a filter — is destroyed at
--    once: a zone makes no devices the host could be routed to;
--  * sinks (Audio/Sink, Audio/Duplex) of the host: read only — to play to,
--    never to destroy or reconfigure;
--  * capture sources of the host: read only, and only while the zone's
--    microphone is "yes" (the helper publishes it in the metadata object
--    "vpn-zones"); revoked, the links are broken here at once;
--  * the metadata "default": read only (which sink is the default);
--  * the "client-node" factory, read: a stream is a client node. Not the link
--    factory, not the adapter or device factories: a zone links nothing
--    itself and opens no ALSA device inside the daemon;
--  * links: only WirePlumber makes them, and only a zone's playback stream to
--    a host's sink and — microphone "yes" — a host's source to a zone's
--    capture stream. Never a sink's monitor (what the host plays), never a
--    zone's node with anybody else's (a host program's capture fed by a zone,
--    a zone's node standing in for a device). The guard sits in WirePlumber's
--    own linking chain, and a watchdog destroys any link that got past it;
--  * default nodes: a zone's node is never a candidate.
--
-- The script announces itself with vpn-zones.policy = "1" in the metadata
-- object "vpn-zones" — only when the access rule is in force (below); the
-- helper hands the zone's socket to PipeWire only while that key is there.
-- Written for WirePlumber 0.5.14 (the older, ObjectManager-based client
-- access) and 0.5.15+ (the select-access event chain) alike.

local log = Log.open_topic ("s-vpn-zones")

local ENGINE = "vpn-zone"
local METADATA = "vpn-zones"
local POLICY_KEY = "vpn-zones.policy"
local POLICY_VERSION = "1"
local MIC_PREFIX = "vpn-zones.microphone."

-- bound id of a zone's client -> { zone = <app-id>, client = <WpClient> }
local zones = {}

-- A property of a node, port, link or client: its info properties (what
-- the object says of itself now; the global ones carry only some keys).
local function prop (obj, key)
  local props = obj.properties
  return props and props [key] or nil
end

-- A property of a factory or a metadata object: they have no info
-- properties, only the global ones.
local function gprop (obj, key)
  local props = obj ["global-properties"]
  return props and props [key] or nil
end

-- The zone client that owns a node, or nil.
local function owner (node)
  local id = prop (node, "client.id")
  id = id and tonumber (id)
  return id and zones [id] or nil
end

-- The "vpn-zones" metadata, once it is active.
local metadata = nil

local function microphone (zone)
  if metadata == nil then
    return false
  end
  local value = metadata:find (0, MIC_PREFIX .. zone)
  return value == "yes"
end

local SINKS = { ["Audio/Sink"] = true, ["Audio/Duplex"] = true }
local SOURCES = {
  ["Audio/Source"] = true,
  ["Audio/Source/Virtual"] = true,
  ["Audio/Duplex"] = true,
}

-- What a zone's client may do with a node: its own, rwx; another program's
-- of the same zone, read (a zone is one trust domain — its programs share
-- its files anyway); another zone's, nothing.
local function node_permission (z, node)
  local other = owner (node)
  if other ~= nil then
    if other == z then
      return "rwx"
    end
    return other.zone == z.zone and "r" or "-"
  end
  local class = prop (node, "media.class")
  if class and SINKS [class] then
    return "r"
  end
  if class and SOURCES [class] and microphone (z.zone) then
    return "r"
  end
  return "-"
end

-- A zone's own node that is a stream and nothing more: no media class of a
-- device, no filter, no link group.
local function own_node_allowed (node)
  local class = prop (node, "media.class")
  if class ~= nil and not class:find ("^Stream/") then
    return false
  end
  if prop (node, "node.link-group") ~= nil or prop (node, "filter.smart") ~= nil then
    return false
  end
  return true
end

-- May `stream` (the node a link is made for) be linked to `target`?
-- `playback`: the stream plays (its output to the target's input).
local function link_allowed (stream, target, playback)
  local sz = owner (stream)
  local tz = owner (target)
  if sz == nil and tz == nil then
    return true
  end
  if sz ~= nil and tz ~= nil then
    return sz == tz
  end
  if sz == nil then
    -- Anybody else's stream with a zone's node: never.
    return false
  end
  local class = prop (target, "media.class")
  if playback then
    return class ~= nil and SINKS [class] == true
  end
  -- A sink as a capture target is its monitor: never.
  return class ~= nil and SOURCES [class] == true and microphone (sz.zone)
end

-- Globals of the script, not locals: a local nothing refers to once the
-- chunk has run is collected, and an object manager collected sends no more
-- events — new clients would be left held by the daemon for ever (seen in
-- the VM test: the clients present at load were seen, none after).
nodes_om = ObjectManager { Interest { type = "node" } }
ports_om = ObjectManager { Interest { type = "port" } }
links_om = ObjectManager { Interest { type = "link" } }
factories_om = ObjectManager { Interest { type = "factory" } }
metadata_om = ObjectManager { Interest { type = "metadata" } }
clients_om = ObjectManager { Interest { type = "client" } }

local function node_by_id (id)
  id = id and tonumber (id)
  if id == nil then
    return nil
  end
  return nodes_om:lookup {
    Constraint { "bound-id", "=", id, type = "gobject" },
  }
end

local function rescan_linking ()
  local source = Plugin.find ("standard-event-source")
  if source ~= nil then
    source:call ("schedule-rescan", "linking")
  end
end

-- Every grant a zone's client has, then the core: the client is held by the
-- daemon until it may read the core, and then sees only this.
local function finalize (z)
  local id = z.client ["bound-id"]
  local perms = { ["any"] = "-" }
  for node in nodes_om:iterate () do
    local nid = node ["bound-id"]
    local p
    if owner (node) == z then
      p = own_node_allowed (node) and "rwx" or "-"
    else
      p = node_permission (z, node)
    end
    perms [nid] = p
  end
  for port in ports_om:iterate () do
    local node = node_by_id (prop (port, "node.id"))
    if node ~= nil and owner (node) == z then
      perms [port ["bound-id"]] = "r"
    end
  end
  for factory in factories_om:iterate () do
    if gprop (factory, "factory.name") == "client-node" then
      perms [factory ["bound-id"]] = "r"
    end
  end
  local default = metadata_om:lookup { Constraint { "metadata.name", "=", "default" } }
  if default ~= nil then
    perms [default ["bound-id"]] = "r"
  end
  z.client:update_permissions (perms)
  -- A separate request, after the rest: the daemon applies them in order.
  z.client:update_permissions { [0] = "rx" }
  log:info (z.client, string.format ("zone %s: client %d restricted", z.zone, id))
end

-- The sources' permissions of every client of `zone` again (its microphone
-- changed): a revoked R breaks the links in the daemon at once.
local function regrant_sources (zone)
  for _, z in pairs (zones) do
    if z.zone == zone then
      local perms = {}
      for node in nodes_om:iterate () do
        local class = prop (node, "media.class")
        if owner (node) == nil and class and SOURCES [class] and not SINKS [class] then
          perms [node ["bound-id"]] = node_permission (z, node)
        end
      end
      if next (perms) ~= nil then
        z.client:update_permissions (perms)
      end
    end
  end
end

clients_om:connect ("object-added", function (_, client)
  local engine = prop (client, "pipewire.sec.engine")
  log:info (client, string.format ("client %d added (engine %s)",
      client ["bound-id"], tostring (engine)))
  if engine ~= ENGINE then
    return
  end
  local zone = prop (client, "pipewire.sec.app-id") or ""
  local z = { zone = zone, client = client }
  zones [client ["bound-id"]] = z
  finalize (z)
end)

clients_om:connect ("object-removed", function (_, client)
  zones [client ["bound-id"]] = nil
end)

nodes_om:connect ("object-added", function (_, node)
  local z = owner (node)
  local nid = node ["bound-id"]
  if z ~= nil and not own_node_allowed (node) then
    log:notice (node, string.format (
        "zone %s: node %d (%s) is not a plain stream (a device, a filter, a link group) — destroyed", z.zone, nid,
        tostring (prop (node, "media.class"))))
    z.client:update_permissions { [nid] = "-" }
    node:request_destroy ()
    return
  end
  for _, c in pairs (zones) do
    c.client:update_permissions { [nid] = node_permission (c, node) }
  end
end)

ports_om:connect ("object-added", function (_, port)
  local node = node_by_id (prop (port, "node.id"))
  local z = node and owner (node)
  if z ~= nil then
    z.client:update_permissions { [port ["bound-id"]] = "r" }
  end
end)

factories_om:connect ("object-added", function (_, factory)
  if gprop (factory, "factory.name") == "client-node" then
    for _, z in pairs (zones) do
      z.client:update_permissions { [factory ["bound-id"]] = "r" }
    end
  end
end)

metadata_om:connect ("object-added", function (_, m)
  local name = gprop (m, "metadata.name")
  if name == "default" then
    for _, z in pairs (zones) do
      z.client:update_permissions { [m ["bound-id"]] = "r" }
    end
  end
end)

-- The watchdog: a link WirePlumber's chain did not refuse, or somebody else
-- made — destroyed if it is not one the policy allows.
local function check_link (link)
  local out_node = node_by_id (prop (link, "link.output.node"))
  local in_node = node_by_id (prop (link, "link.input.node"))
  if out_node == nil or in_node == nil then
    return
  end
  local oz, iz = owner (out_node), owner (in_node)
  if oz == nil and iz == nil then
    return
  end
  local ok
  if oz ~= nil and iz ~= nil then
    ok = oz == iz
  elseif oz ~= nil then
    ok = link_allowed (out_node, in_node, true)
  else
    ok = link_allowed (in_node, out_node, false)
  end
  if not ok then
    log:notice (link, string.format ("link %d -> %d of a zone refused — destroyed",
        out_node ["bound-id"], in_node ["bound-id"]))
    link:request_destroy ()
  end
end

links_om:connect ("object-added", function (_, link)
  check_link (link)
end)

-- Every link again, when what is allowed changed (a zone's microphone): the
-- daemon breaks a link only when a PORT's permission changes, and the policy
-- grants nodes — so a microphone taken back is unlinked here.
local function check_all_links ()
  for link in links_om:iterate () do
    check_link (link)
  end
end

-- The guard in WirePlumber's linking chain: after every hook that picks a
-- target, before the link is made.
SimpleEventHook {
  name = "linking/vpn-zones-guard",
  after = "linking/prepare-link",
  before = "linking/link-target",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-target" },
    },
  },
  execute = function (event)
    local target = event:get_data ("target")
    if not target then
      return
    end
    local si = event:get_subject ()
    local stream = si:get_associated_proxy ("node")
    local target_node = target:get_associated_proxy ("node")
    if stream == nil or target_node == nil then
      return
    end
    if owner (stream) == nil and owner (target_node) == nil then
      return
    end
    local playback = si.properties ["item.node.direction"] == "output"
    if not link_allowed (stream, target_node, playback) then
      log:info (si, string.format ("zone link %d -> %d refused",
          stream ["bound-id"], target_node ["bound-id"]))
      event:set_data ("target", nil)
    end
  end
}:register ()

-- A zone's node is never a default device candidate.
SimpleEventHook {
  name = "default-nodes/vpn-zones-hide",
  before = {
    "default-nodes/find-selected-default-node",
    "default-nodes/find-stored-default-node",
    "default-nodes/find-best-default-node",
  },
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-default-node" },
    },
  },
  execute = function (event)
    local available = event:get_data ("available-nodes")
    available = available and available:parse ()
    if not available then
      return
    end
    local kept, dropped = {}, false
    for _, props in ipairs (available) do
      local id = props ["client.id"] and tonumber (props ["client.id"])
      if id and zones [id] then
        dropped = true
      else
        table.insert (kept, Json.Object (props))
      end
    end
    if dropped then
      event:set_data ("available-nodes", Json.Array (kept))
    end
  end
}:register ()

-- WirePlumber 0.5.15+: a zone's client gets no permissions from the access
-- chain whatever other rules say — its default is none, set before the
-- config's rules are looked at. (0.5.14 has no such event: there the access
-- rule does it, and the marker waits for it — below.)
SimpleEventHook {
  name = "client/vpn-zones-access",
  before = "client/find-config-access",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-access" },
    },
  },
  execute = function (event)
    local client = event:get_subject ()
    if prop (client, "pipewire.sec.engine") == ENGINE then
      event:set_data ("default-permissions", "-")
    end
  end
}:register ()

-- Is the access rule of 90-vpn-zones.conf in force: does a zone's client get
-- no default permission from the config's rules? Without it WirePlumber 0.5.14
-- would give it read and execute on everything.
local function access_rule_in_force ()
  local rules = Conf.get_section_as_json ("access.rules")
  if rules == nil then
    return false
  end
  local sample = {
    ["pipewire.sec.engine"] = ENGINE,
    ["pipewire.sec.app-id"] = "probe",
    ["pipewire.access"] = "restricted",
    ["access"] = "restricted",
    ["application.name"] = "probe",
  }
  local props = JsonUtils.match_rules_update_properties (rules, sample)
  local perms = props and props ["default_permissions"]
  return perms ~= nil and (perms:gsub ("-", "")) == ""
end

clients_om:activate ()
nodes_om:activate ()
ports_om:activate ()
links_om:activate ()
factories_om:activate ()
metadata_om:activate ()

impl_metadata = ImplMetadata (METADATA)
impl_metadata:activate (Features.ALL, function (m, e)
  if e then
    log:warning ("cannot make the vpn-zones metadata: " .. tostring (e))
    return
  end
  metadata = m
  m:connect ("changed", function (_, subject, key, _, _)
    if subject == 0 and key ~= nil and key:sub (1, #MIC_PREFIX) == MIC_PREFIX then
      regrant_sources (key:sub (#MIC_PREFIX + 1))
      check_all_links ()
      rescan_linking ()
    end
  end)
  if access_rule_in_force () then
    m:set (0, POLICY_KEY, "Spa:String", POLICY_VERSION)
    log:info ("vpn-zones policy active")
  else
    log:warning ("vpn-zones: the access rule of 90-vpn-zones.conf is not in force — "
        .. "the zones' PipeWire stays closed")
  end
end)

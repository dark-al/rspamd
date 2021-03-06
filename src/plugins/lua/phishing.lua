--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

-- Phishing detection interface for selecting phished urls and inserting corresponding symbol
--
--
local symbol = 'PHISHED_URL'
local domains = nil
local strict_domains = {}
local redirector_domains = {}
local rspamd_logger = require "rspamd_logger"
local util = require "rspamd_util"
local opts = rspamd_config:get_all_opt('phishing')

local function phishing_cb(task)
  local urls = task:get_urls()

  if urls then
    for _,url in ipairs(urls) do
      if url:is_phished() then
        local found = false
        local purl = url:get_phished()
        local tld = url:get_tld()
        local ptld = purl:get_tld()

        if not ptld or not tld then
          return
        end

        local weight = 1.0
        local dist = util.levenshtein_distance(tld, ptld)
        dist = 2 * dist / (#tld + #ptld)

        if dist > 0.3 and dist <= 1.0 then
          -- Use distance to penalize the total weight
          weight = util.tanh(3 * (1 - dist + 0.1))
        end
        rspamd_logger.debugx("distance: %1 -> %2: %3", tld, ptld, dist)

        if #redirector_domains > 0 then
          for _,rule in ipairs(redirector_domains) do
            if rule['map']:get_key(url:get_tld()) then
              task:insert_result(rule['symbol'], weight, ptld)
              found = true
            end
          end
        end
        if not found and #strict_domains > 0 then
          for _,rule in ipairs(strict_domains) do
            if rule['map']:get_key(ptld) then
              task:insert_result(rule['symbol'], 1.0, ptld)
              found = true
            end
          end
        end
        if not found then
          if domains then
            if domains:get_key(ptld) then
              task:insert_result(symbol, weight, ptld)
            end
          else
            task:insert_result(symbol, weight, ptld)
          end
        end
      end
    end
  end
end

local function phishing_map(mapname, phishmap)
  if opts[mapname] then
    local xd = {}
    if type(opts[mapname]) == 'table' then
      xd = opts[mapname]
    else
      xd[1] = opts[mapname]
    end
    for _,d in ipairs(xd) do
      local s, _ = string.find(d, ':[^:]+$')
      if s then
        local sym = string.sub(d, s + 1, -1)
        local map = string.sub(d, 1, s - 1)
        rspamd_config:register_virtual_symbol(sym, 1, id)
        local rmap = rspamd_config:add_hash_map (map, 'Phishing ' .. mapname .. ' map')
        if rmap then
          local rule = {symbol = sym, map = rmap}
          table.insert(phishmap, rule)
        else
          rspamd_logger.info('cannot add map: ' .. map .. ' for symbol: ' .. sym)
        end
      else
        rspamd_logger.info(mapname .. ' option must be in format <map>:<symbol>')
      end
    end
  end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
  if rspamd_config:get_api_version() >= 1 then
    rspamd_config:register_module_option('phishing', 'symbol', 'string')
    rspamd_config:register_module_option('phishing', 'domains', 'map')
    rspamd_config:register_module_option('phishing', 'strict_domains', 'string')
    rspamd_config:register_module_option('phishing', 'redirector_domains', 'string')
  end
end

if opts then
  if opts['symbol'] then
    symbol = opts['symbol']
    -- Register symbol's callback
    rspamd_config:register_symbol(symbol, 1.0, phishing_cb)
  end
  if opts['domains'] and type(opt['domains']) == 'string' then
    domains = rspamd_config:add_hash_map (opts['domains'])
  end
  phishing_map('strict_domains', strict_domains)
  phishing_map('redirector_domains', redirector_domains)
end

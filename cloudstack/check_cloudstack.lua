#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/7/7
--Function:Check cloudstack use nsf vulnerabilities.

agent.load "rex_pcre"
local rex = rex_pcre

function check_nsf()
	local content=io.open("/etc/exports")
	if content== nil then
		print("null")
	else
		for line in content:lines() do
			local match_flag=rex.match(line,[[\/export(\s)*\*\s*\(rw,async,no_root_squash\)]])
			if match_flag ~= nil then
				print("success")
				return 1,"success"
			end
		end
	end
end

function main()
	check_nsf()
end
main()

#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/6/30
--Function:Check Jenkins unauthorized access(script/manage)page opening hacker can REC.

local common=agent.require"agent.platform.linux.common"
local execute_shell=common.execute_shell

function check_script(url,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/script")
	if msg=="200" then
		print("[*]"..url..":"..port.."/script".." Jenkins script page is opening!")
		return 1,"success"
	else
		return -1,msg
	end
end

function check_manage(url,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/manage")
	if msg=="200" then
		print("[*]"..url..":"..port.."/manage".." Jenkins Manage page is opening!")
		return 1,"success"
	else
		return -1,msg
	end
end

function main()
	check_manage("221.140.57.199","8080")
	check_script("221.140.57.199","8080")
	check_script("webapp.hoperun.com","8131")
	check_manage("webapp.hoperun.com","8131")
end
main()

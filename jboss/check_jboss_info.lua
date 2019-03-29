#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/6/29
--Function:Check Jboss Information Disclosure vulnerabilities

local common=agent.require"agent.platform.linux.common"
local execute_shell=common.execute_shell


--function for check_info response 200 is success,404 is failed.
--return 1 is success.return -1 is failed.
--@param url and port
function check_info(url,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/status?full=true")
	if msg=="200" then
		print("[*]"..url..":"..port.."/status?full=true".."  Jboss Information Disclosure vulnerabilities!")
		return 1,msg
	else
		return -1,msg
	end
end

function check_web_console(url,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/web-console")
	if msg =="200" then
		print("[*]"..url..":"..port.."/web-console".." Jboss Information Disclosure vulnerabilities! ")
		local status,messge=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/web-console/Invoker")
		if status=="200" then
			print("[*]"..url..":"..port.."/web-console/Invoker".." Jboss Information Disclosure vulnerabilities! ")
			return 1,messge
		else
			return -1,messge
		end
		return 1,msg
	else
		return -1,msg
	end
end

function check_jmx_console(url,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/jmx-console")
	if msg == "200" then
		print("[*]"..url..":"..port.."/jmx-console".." Jboss Information Disclosure vulnerabilities! ")
		return 1,msg
	else
		return -1,msg
	end
end

function check_invoker_jmx(url,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..url..":"..port.."/invoker/JMXInvokerServlet")
	if msg == "200" then
		print("[*]"..url..":"..port.."//invoker/JMXInvokerServlet".." Jboss Information Disclosure vulnerabilities! ")
		return 1,msg
	else
		return -1,msg
	end
end

local rps_code,res_msg=check_info("43.224.208.193","8080")
print(rps_code,res_msg)
local rp,re=check_web_console("43.224.208.193","8080")
print(rp,re)
lcoal q,w=check_jmx_console("43.224.208.193","8080")
print(q,w)
local e,r=check_invoker_jmx("43.224.208.193","8080")
print(e,r)

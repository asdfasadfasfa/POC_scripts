#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/6/26
--Function:check html2text RCE

agent.load "rex_pcre"
local rex = rex_pcre
local common=agent.require"agent.platform.linux.common"
local execute_shell=common.execute_shell
local execute_shell_l=common.execute_shell_l


function find_html2text(path)
	local code,msg=execute_shell("find "..path.." -name html2text.class.php")
	local result=string.gsub(msg,"\n","")
	if code ==0 then
		if result ~="" then
			print(result)
			local content=getFileLine(result)
			local match_flag=rex.match(content,[[\'\/\<a\s*\[\^\>\]\*href\s*=\s*\"\(\[\^\"\]\+\)\"\[\^\>\]\*\>\(\.\*\?\)\<\\\/a\>\/ie\'\,]])
			if match_flag =="\'/<a \[^>\]*href=\"(\[^\"\]+)\"\[^>\]*>(.*?)<\\/a>/ie\'," then
				return 1,"success"
			else
				return -1,"The File Not Have Harm"
			end
		else
			return -1,"Not Find Html2text File"
		end
	else
		return -1,"Failed"
	end
end

--read file 
--@param read file name
--return  The file content
function getFileLine(file_name)
	local BUFSIZE = 84012
	local f = assert(io.open(file_name, 'r'))
	local lines,rest = f:read(BUFSIZE, "*line")
	f:close()
	return lines , rest
end

local code,msg=find_html2text("/data/www/default/")
print(code)
print(msg)

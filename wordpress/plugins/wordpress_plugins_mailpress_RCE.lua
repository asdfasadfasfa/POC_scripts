#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/7/12
--Function:Check wordpress plugins mailpress RCE.
agent.load "rex_pcre"
local rex = rex_pcre

function check_rec(webpath)
	local content=io.open(webpath.."/wp-content/plugins/mailpress/mp-includes/action.php")
	if content ~= nil then
		local action=io.open(webpath.."/wp-content/plugins/mailpress/mp-includes/class/MP_Actions.class.php")
		if action ~= nil then
			for line in action:lines() do
				local match_flag=rex.match(line,[[\$x->do_eval\(\$mail->subject\)\;]])
				if match_flag then
					local contents=io.open(webpath.."/wp-content/plugins/mailpress/mp-includes/class/MP_Mail.class.php")
					if contents ~= nil then
						for i in contents:lines() do
							local result=rex.match(i,[[echo\(eval\(\$x\)\)]])
							if result then
								return 1,"success"
							end
						end
						contents:close()
					end
				end
			end
		end
	content:close()
	end
end

function main()
	local code,msg=check_rec("/usr")
	print(code,msg)
end

main()

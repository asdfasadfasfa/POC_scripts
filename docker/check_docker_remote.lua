#!/usr/local/bin/lua
--Author:Sevck
--Date:2016/7/5
--Function:Check Docker Remote API Nauthorized Access.

local a = require "agent"                                                                                                                     
local socket = a.require("socket")  
agent.load "rex_pcre"
local rex = rex_pcre

function check_docker(host,port)
	--local host = "223.105.1.48" 
	local path = "/containers/json" 
	local sock = assert(socket.connect(host, port))
	sock:send("GET " .. path .. " HTTP/1.0\r\n\r\n")
	repeat
		-- 以 1K 的字节块来接收数据，并把接收到字节块输出来
		local chunk, status, partial = sock:receive(1024)
		--print(chunk or partial)
		result=chunk
	until status ~= "closed" 
	-- 关闭 TCP 连接
	sock:close()
	--print(result)
	code=rex.match(result,[[\d\d\d]])
	if code == "200" then
		print("[*]"..host..":"..port.."   Exist Docker Remote API Vulerability.")
		return 1,"success"
	else
		return -1,"Failed"
	end
	
end

function main()
	local ip="223.105.1.48"
	local port="2375"
	--local path="/containers/json"
	check_docker(ip,port)
end


main()

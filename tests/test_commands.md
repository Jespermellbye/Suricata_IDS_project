# ==== CUSTOM RULES ====

# SSH SYN attempts to servers in HOME_NET
alert tcp any any -> $HOME_NET 22 (flags:S; msg:"Custom SSH SYN"; sid:1000100; rev:3;)

# Suspicious TCP SYN to port 4444 (often used by backdoors/tools)
alert tcp any any -> $HOME_NET 4444 (flags:S; msg:"Custom 4444 SYN"; sid:1000101; rev:2;)

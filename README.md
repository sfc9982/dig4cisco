# dig4cisco
A dig command for Cisco IOS

## How to use

1. Copy the `dig.tcl` into the CompactFlash card (or other flash)
2. Use `dir` command to **carefully check the filename** (sometimes Cisco IOS recognize the filename as **Upper-case**)
3. `configure terminal` `alias exec dig tclsh flash:<FILENAME>`
4. Now the alias is binded in exec mode, if you want to bind more, use `alias configure dig tclsh flash:<FILENAME>` `alias interface dig tclsh flash:<FILENAME>`
5. Use `dig 8.8.8.8` and `dig dns.google` now and see the result!

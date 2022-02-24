#-
# Copyright (c) 2008-2010 Joe Marcus Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#
#
# Modified 2010 Jakob Pfeiffer <code@pfeiffer.ws>
# * UDP support added. Use '-u' as first parameter.
# * Looks in 'show host' for name server too.
#

namespace eval MarcusHost {
    variable A_RECORD    0x0001
    variable AAAA_RECORD 0x001c
    variable PTR_RECORD  0x000c
    variable CLASS_IN    0x0001
    variable REQ_FLAGS   0x0100

    variable RCODES [list        \
        {No error}                 \
        {Format error}                \
        {Server failure}        \
        {No such name}                \
        {Not implemented}        \
        {Refused}                \
        {Name exists}                \
        {RRset exists}                \
        {RRset does not exist}        \
        {Not authoritative}        \
        {Name out of zone}        \
    ]

    proc connect { server proto } {
        if { $proto == "tcp" } {
            if { [catch {set fd [socket $server 53]} result] } {
                return -code error $result
            }
            fconfigure $fd -translation binary

        } else {
            if { [catch {set fd [udp_open]} result] } {
                return -code error $result
            }
            fconfigure $fd -remote [list $server 53] -translation binary -buffering none
        }

        return $fd
    }

    proc getTid { } {
        expr srand([expr [clock seconds] ^ [pid]])
        return [expr int([expr rand() * 65535])]
    }

    proc getPtr6Req { addr } {
	set shorts [split $addr ":"]
	set zeros 0
	set ptraddr [list]
	if { [llength $shorts] < 8 } {
	    set zeros [expr (8 - [llength $shorts] + 1) * 4]
	}
	for { set i [expr [llength $shorts] - 1] } { $i >= 0 } { incr i -1 } {
	    if { [lindex $shorts $i] == "" } {
		set ptraddr [concat $ptraddr [split [string repeat "0" $zeros] ""]]
	    } else {
		set l [split [lindex $shorts $i] ""]
	        set l [concat [string repeat "0" [expr 4 - [string length [lindex $shorts $i]]]] $l]
		for { set j [expr [llength $l] - 1] } { $j >= 0 } { incr j -1 } {
		    lappend ptraddr [lindex $l $j]
		}
	    }
	}

	lappend ptraddr {ip6} {arpa}

	return [join $ptraddr "."]
    }

    proc getPtrReq { addr } {
	if { [isIP6Addr $addr] } {
	    return [getPtr6Req $addr]
	}
        set octets [split $addr "."]
        for { set i [expr [llength $octets] - 1] } { $i >= 0 } { incr i -1 } {
            lappend ptraddr [lindex $octets $i]
        }

        lappend ptraddr {in-addr} {arpa}

        return [join $ptraddr "."]
    }

    proc isIP6Addr { host } {
	set shorts [split $host ":"]
	if { [llength $shorts] > 8 } {
	    return 0
	}

	foreach short $shorts {
	    if { $short == "" } {
		continue
	    }
	    if { [string length $short] > 4 } {
		return 0
	    }
	    if { ![regexp {^[A-Fa-f0-9]+$} $short] } {
		return 0
	    }
	}

	return 1
    }

    proc isIPAddr { host } {
	if { [isIP6Addr $host] } {
	    return 1
	}
        set octets [split $host "."]
        if { [llength $octets] != 4 } {
            return 0
        }

        foreach octet $octets {
            if { ![regexp {\d+} $octet] } {
                return 0
            }
        }

        return 1
    }

    proc udp_event { fd } {
        global inData
        global host_event

        set inData [read $fd]
        set host_event "reply"
    }

    proc arrToV6 { addr } {
	set j 0
	set start -1
	set end -1
	set tstart -1
	for { set i 0 } { $i < [llength $addr] } { incr i 2 } {
	    set o1 [lindex $addr $i]
	    set o2 [lindex $addr [expr $i + 1]]
	    if { $o1 == 0 && $o2 == 0 } {
		lappend res 0
		if { $tstart == -1 } {
		    set tstart $j
		}
	    } else {
		if { $o1 == 0 } {
		    lappend res [format "%x" $o2]
		} else {
	            lappend res [format "%x%02x" $o1 $o2]
		}
		if { $tstart != -1 && ($start == -1 || [expr $end - $start] < [expr $j - $tstart]) } {
		    set start $tstart
		    set tstart -1
		    set end $j
		}
	    }
	    incr j
	}

	if { $tstart != -1 && [expr $end - $start] < [expr $j - $tstart] } {
	    set start $start
	    set end $j
	}

	if { [expr $end - $start] > 1 } {
	    set res [lreplace $res $start [expr $end - 1]]
	    set res [linsert $res $start ""]
	}
	return [join $res ":"]
    }

    proc lookup { host server proto {ts "A"} } {
        set fd [MarcusHost::connect $server $proto]
        if { [catch {set fd [MarcusHost::connect $server $proto]} result] } {
            return -code error $result
        }

        set tid [MarcusHost::getTid]
        set flags $MarcusHost::REQ_FLAGS
        set class $MarcusHost::CLASS_IN
	if { $ts == "A" } {
            set type $MarcusHost::A_RECORD
            set reqTypeStr "A"
	} elseif { $ts == "AAAA" } {
	    set type $MarcusHost::AAAA_RECORD
	    set reqTypeStr "AAAA"
	}
        if { [MarcusHost::isIPAddr $host] } {
            set type $MarcusHost::PTR_RECORD
            set host [MarcusHost::getPtrReq $host]
            set reqTypeStr "PTR"
        }

        set qs "\x00\x01"
        set as "\x00\x00"
        set aurrs "\x00\x00"
        set adrrs "\x00\x00"

        set hparts [split $host "."]
        set lkup ""
        foreach part $hparts {
            set len [format "%02x" [string length $part]]
            append lkup [binary format H2 $len]
            append lkup $part
        }

        set query ""
        append query [binary format H4 [format "%04x" $tid]]
        append query [binary format H4 [format "%04x" $flags]]
        append query $qs
        append query $as
        append query $aurrs
        append query $adrrs
        append query $lkup
        append query "\x00"
        append query [binary format H4 [format "%04x" $type]]
        append query [binary format H4 [format "%04x" $class]]
        set reqlen [string length $query]
        if { $proto == "tcp" } {
            set query [binary format H4 [format "%04x" $reqlen]]$query
        }

        puts -nonewline $fd $query
        flush $fd

        if { $proto == "tcp" } {
            set inData [read $fd 2]
            if { $inData == "" || $inData == 0 || ![binary scan $inData S readLen]} {
                close $fd
                return -code error "Error reading reply length from server"
            }

            set readLen [expr $readLen & 0xFFFF]

            set inData [read $fd $readLen]
            close $fd

        } else {
            global inData
	    global host_event

            set host_event ""
	    # XXX This hardcoded value should be configurable.
            after 5000 set host_event "timeout"
            fileevent $fd readable [list MarcusHost::udp_event $fd]
            vwait host_event
            close $fd

            if { $host_event == "timeout" } {
                return -code error "Timeout didn't recieved answer"
            }
        }

        if { $inData == "" || $inData == 0 } {
            return -code error "Error reading reply from server"
        }

        if { ! [binary scan $inData SSSS repTid repFlags repQs repAs] } {
            return -code error "Error parsing reply header"
        }

        set repTid [expr $repTid & 0xFFFF]
        set repFlags [expr $repFlags & 0xFFFF]
        set repAs [expr $repAs & 0xFFFF]

        if { $repTid != $tid } {
            return -code error "Transaction ID mismatch"
        }

        set repError [expr $repFlags & 0x000F]
        if { $repAs == 0 } {
            return -code error [lindex $MarcusHost::RCODES $repError]
        }

        set answers [string range $inData $reqlen end]

        set aaddrs [list $host $reqTypeStr]
        for { set i 0 } { $i < $repAs } { incr i } {
            if { ! [binary scan $answers SSSIS respName respType respClass respTTL respLen] } {
                return -code error "Error parsing reply body"
            }
            set respType [expr $respType & 0xFFFF]
            set respClass [expr $respClass & 0xFFFF]
            set respLen [expr $respLen & 0xFFFF]
            set answers [string range $answers 12 end]

            if { $respType != $type  || $respClass != $class } {
                set answers [string range $answers $respLen end]
                continue
            }

            set aaddr [list]
            if { $reqTypeStr == "PTR" } {
                binary scan $answers c elen
                set elen [expr $elen & 0xFF]
                while { $elen > 0 } {
                    set answers [string range $answers 1 end]
                    binary scan $answers a$elen elem
                    lappend aaddr $elem
                    set answers [string range $answers $elen end]
                    binary scan $answers c elen
                    set elen [expr $elen & 0xFF]
                }
            } else {
                for { set j 0 } { $j < $respLen } { incr j } {
                    binary scan $answers c octet
                    set octet [expr $octet & 0xFF]
                    lappend aaddr $octet
                    set answers [string range $answers 1 end]
                }
            }

	    if { $reqTypeStr == "AAAA" } {
		lappend aaddrs [arrToV6 $aaddr]
	    } else {
                lappend aaddrs [join $aaddr "."]
	    }
        }

        return -code ok $aaddrs
    }
}

proc get_server { } {
    set cmd "show run | inc ^ip name-server"
    set output [split [exec $cmd] "\n"]
    foreach line $output {
        if { [regexp {([\d\.]+)} $line -> server] } {
            return $server
        }
    }

    set cmd "show host | inc ^Name servers are"
    set output [split [exec $cmd] "\n"]
    foreach line $output {
        if { [regexp {([\d\.]+)} $line -> server] } {
            return $server
        }
    }

    return ""
}

proc host { args } {
    set args [join $args " "]

    set proto "tcp"
    set ts "A"
    set i 0
    for { } { $i < [llength $args] } { incr i } {
	switch -glob -- [lindex $args $i] {
	    -u { set proto "udp" }
	    -6 { set ts "AAAA" }
	    -* { puts "Unknown option, [lindex $args $i]"
		 return -code error
	    }
	    * { break }
	}
    }

    if { $i < [llength $args] } {
	set host [lindex $args $i]
	incr i
	if { $i < [llength $args] } {
	    set dns [lindex $args $i]
	} else {
	    set dns [get_server]
	}
    }

    if { $dns == "" } {
        puts "Failed to find a valid DNS server."
        return -code error
    }

    if { $host == "" } {
        puts {usage: host [-u] [-6] address [dns_server]}
        return -code error
    }

    if { [catch {set addrs [MarcusHost::lookup $host $dns $proto $ts]} result] } {
        puts "ERROR: $result"
        return -code error
    }

    set host [lindex $addrs 0]
    set type [lindex $addrs 1]

    for { set i 2 } { $i < [llength $addrs] } { incr i } {
        if { $type == "A" || $type == "AAAA" } {
            puts "$host has address [lindex $addrs $i]"
        } elseif { $type == "PTR" } {
            puts "$host domain name pointer [lindex $addrs $i]"
        }
    }
}

if { $argv0 == "tclsh" } {
    puts "Loaded [info script] successfully."
} else {
    set rc [catch { host $argv } result]
    return -code $rc $result
}


# Script of blocking dangerous addresses by drPioneer.
# https://forummikrotik.ru/viewtopic.php?t=4781&start=20
# tested on ROS 6.49
# updated 2022/01/19

do {
    # ----------- Checking & installing firewall-filter rule ----------- 
    if ([ip firewall filter find src-address-list="BlockDangerAddress";] ="") do={
         ip firewall filter add action=drop chain=input comment="Dropping dangerous adresses" src-address-list=BlockDangerAddress;
    }
    if ([ip firewall filter find src-address-list="BlockDangerAddress" disabled=yes;] !="") do={
         ip firewall filter enable [find src-address-list="BlockDangerAddress" disabled=yes];
    }

    # IP-address validation function
    local DangerIPAddr do={
        if ($1~"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}") do={
            if ([ip firewall address-list find list="BlockDangerAddress" address=$1;] ="") do={ 
                ip firewall address-list add address=$1 list="BlockDangerAddress" timeout=14d;
                put ">>> added in black list IP $1";
                log warning ">>> Added in black list IP $1";
                return true;
            }
        }
        return false;
    }

    # Function that reports the absence of dangerous addresses
    local NotFound do={
        if (!$1) do={
            put ">>> no new dangerous IP-addresses were found...";
        }
    }

    #----------- Stage 1 - searching of failed login attempt -----------
    put ("$[system clock get time;] Stage 1 - searching of failed login attempt");
    local isDetected false;
    foreach dangerString in=[log find topics~"system" message~"login failure for user";] do={
        local stringTemp ([log get $dangerString message;]);
        local dangerIP ([pick $stringTemp ([find $stringTemp "from"] +5) ([find $stringTemp "via"] -1)]);
        if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
    }
    [$NotFound $isDetected];
    
    #----------- Stage 2 - search for login attempts from unknown networks  -----------
    put ("$[system clock get time;] Stage 2 - search for login attempts from unknown networks");
    set $isDetected false;
    foreach dangerString in=[log find topics~"warning" message~"denied winbox/dude connect from";] do={
        local stringTemp ([log get $dangerString message;]);
        local dangerIP ([pick $stringTemp ([find $stringTemp "from"] +5) ([len $stringTemp])]);
        if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
    }
    [$NotFound $isDetected];

    #----------- Stage 3 - search for an attempt to enter through IPSec password -----------
    put ("$[system clock get time;] Stage 3 - search for an attempt to enter through IPSec password");
    set $isDetected false;
    foreach dangerString in=[log find topics~"ipsec" message~"parsing packet failed, possible cause: wrong password"] do={
        local stringTemp ([log get $dangerString message]);
        local dangerIP ([pick $stringTemp 0 ([find $stringTemp "parsing" ] -1)]);
        if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
    }
    [$NotFound $isDetected];

    #----------- Stage 4 - search for an attempt to enter through IPSec proposal -----------
    put ("$[system clock get time;] Stage 4 - search for an attempt to enter through IPSec proposal");
    set $isDetected false;
    foreach dangerString in=[log find topics~"ipsec" message~"failed to get valid proposal";] do={
        local stringTemp ([log get $dangerString message;]);
        local dangerIP ([pick $stringTemp 0 ([find $stringTemp "failed" ] -1)]);
        if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
    }
    [$NotFound $isDetected];

    #----------- Stage 5 - search for an attempt to enter through L2TP -----------    
    put ("$[system clock get time;] Stage 5 - search for an attempt to enter through L2TP");
    set $isDetected false;
    foreach dangerString in=[log find topics~"l2tp" message~"authentication failed";] do={
        local stringTemp ([log get $dangerString message]);
        local dangerIP ([pick $stringTemp ([find $stringTemp "<"] +1) ([find $stringTemp ">"]) ]);
        if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
    }
    [$NotFound $isDetected];

    #----------- Stage 6 - search for an attempt to enter through PPTP  -----------
    put ("$[system clock get time;] Stage 6 - search for an attempt to enter through PPTP");
    set $isDetected false;
    foreach dangerStr1 in=[log find topics~"pptp" message~"authentication failed";] do={
        foreach dangerStr2 in=[log find topics~"pptp" message~"TCP connection established from";] do={
            local stringId1 ("0x".[pick $dangerStr1 ([find $dangerStr1 "*"] +1) [len $dangerStr1]]);
            local stringId2 ("0x".[pick $dangerStr2 ([find $dangerStr2 "*"] +1) [len $dangerStr2]]);
            if (($stringId1 - $stringId2) =1) do={
                local stringTemp ([log get $dangerStr2 message;]);
                local dangerIP ([pick $stringTemp ([find $stringTemp "from"] +5) ([len $stringTemp])]);
                if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
            }
        }
    }
    [$NotFound $isDetected];

    #----------- Stage 7 - search for an attempt to enter through OVPN  -----------
    put ("$[system clock get time;] Stage 7 - search for an attempt to enter through OVPN");
    set $isDetected false;
    foreach dangerStr1 in=[log find topics~"ovpn" topics~"error" message~"unknown msg" or message~"msg too short";] do={
        foreach dangerStr2 in=[log find topics~"ovpn" message~"TCP connection established from";] do={
            local stringId1 ("0x".[pick $dangerStr1 ([find $dangerStr1 "*"] +1) [len $dangerStr1]]);
            local stringId2 ("0x".[pick $dangerStr2 ([find $dangerStr2 "*"] +1) [len $dangerStr2]]);
            if (($stringId1 - $stringId2) =1) do={
                local stringTemp ([log get $dangerStr2 message;]);
                local dangerIP ([pick $stringTemp ([find $stringTemp "from"] +5) ([len $stringTemp])]);
                if ([$DangerIPAddr $dangerIP]) do={ set $isDetected true; }
            }
        }
    }
    [$NotFound $isDetected];

    put ("$[system clock get time;] End of search");
} on-error={ 
    put ("Script of blocking dangerous IP addresses worked with errors.");
    log warning ("Script of blocking dangerous IP addresses worked with errors."); 
}


# Script for searching and blocking dangerous addresses by drPioneer.
# https://forummikrotik.ru/viewtopic.php?p=84017#p84017
# tested on ROS 6.49
# updated 2022/02/18

:do {
    # Setting log scan level:  extremeScan = false (usual option) / true (extremal option)
    :local extremeScan true;
    
    # ----------- Checking & installing firewall-filter rules ----------- 
    :if ([ip firewall filter find src-address-list="BlockDangerAddress"]="") do={
        ip firewall filter add action=drop chain=input comment="Dropping dangerous addresses" src-address-list=BlockDangerAddress;
    }
    :if ([ip firewall filter find src-address-list="BlockDangerAddress" disabled=yes]!="") do={
        ip firewall filter enable [find src-address-list="BlockDangerAddress" disabled=yes];
    }
    :if ([ip firewall filter find src-address-list="White List"]="") do={
        ip firewall filter add chain=input comment="White List of IP-addresses" src-address-list="White List" place-before=0;
        ip firewall address-list add address="input_your_address" list="White List";
    }
    :if ([ip firewall filter find src-address-list="White List" disabled=yes]!="") do={
        ip firewall filter enable [find src-address-list="White List" disabled=yes];
    }
    :put "$[system clock get time] - Start of searching dangerous addresses on '$[system identity get name]' router.";
    :if ($extremeScan) do={:put "$[system clock get time] - BE CAREFUL!!!!!! Extreme scanning mode is ENABLED!"}

    # IP-address validation function
    :local DangerIPAddr do={
        :if ($1~"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}") do={
            :if ([ip firewall address-list find list="BlockDangerAddress" address=$1]="") do={ 
                ip firewall address-list add address=$1 list="BlockDangerAddress" timeout=14d;
                :put "$[system clock get time] - Added in black list IP $1";
                :log warning ">>> Added in black list IP $1";
                :return (true);
            }
        }
        :return (false);
    }

    # Function that reports the absence of dangerous addresses
    :local NotFound do={
        :if (!$1) do={:put "$[system clock get time] - No new dangerous IP-addresses were found."}
    }

    # Function of converting decimal numbers to hexadecimal
    :local DecToHex do={
        :if ($1 < 10) do={:return ("*".$1)}
        :local tempNumber $1;
        :local result "";
        :local remainder 0; 
        :local hextable [:toarray "0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F"];
        :while ($tempNumber > 0) do={
            :set remainder ($tempNumber % 16);
            :set tempNumber [:tonum ($tempNumber >> 4)];
            :set result (($hextable->$remainder).$result);
        }
        :return ("*".$result);
    }
    
    #----------- Stage of searching for failed login attempts -----------
    :put "$[system clock get time] - Stage of searching for failed login attempts:";
    :local isDetected false;
    :foreach dangerString in=[:log find topics~"system" message~"login failure for user"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "from"] +5) ([:find $stringTemp "via"] -1)]);
        :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];
    
    #----------- Stage of searching for login attempts from unknown networks  -----------
    :put "$[system clock get time] - Stage of searching for login attempts from unknown networks:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"warning" message~"denied winbox/dude connect from"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "from"] +5) ([:len $stringTemp])]);
        :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to enter through an IPsec password -----------
    :put "$[system clock get time] - Stage of searching for attempts to enter through an IPsec password:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"ipsec" message~"parsing packet failed, possible cause: wrong password"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp 0 ([:find $stringTemp "parsing"] -1)]);
        :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to enter through IPSec proposal -----------
    :put "$[system clock get time] - Stage of searching for attempts to enter through IPSec proposal:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"ipsec" message~"failed to get valid proposal"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp 0 ([:find $stringTemp "failed"] -1)]);
        :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to enter through L2TP -----------    
    :put "$[system clock get time] - Stage of searching for attempts to enter through L2TP:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"l2tp" message~"authentication failed"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "<"] +1) ([:find $stringTemp ">"]) ]);
        :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to establish TCP connection -----------
    :if ($extremeScan) do={
        :put "$[system clock get time] - Stage of searching for attempts to establish TCP connection:";
        :set $isDetected false;
        :foreach dangerString in=[:log find message~"TCP connection established from"] do={
            :local stringTemp ([:log get $dangerString message]);
            :local dangerIP ([:pick $stringTemp ([:find $stringTemp "from"] +5) ([:len $stringTemp]) ]);
            :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
        }
        [$NotFound $isDetected];
    } else={

    #----------- Stage of searching for attempts to enter through PPTP -----------
        :put "$[system clock get time] - Stage of searching for attempts to enter through PPTP:";
        :local dangerString1 [:toarray [:log find topics~"pptp" message~"authentication failed"]];
        :local dangerString2 [:toarray [:log find topics~"pptp" message~"TCP connection established from"]];
        :set $isDetected false;
        :foreach dangerString in=$dangerString2 do={
            :local string2   ([:log get $dangerString message])
            :local stringId2 ("0x".[:pick $dangerString ([:find $dangerString "*"] +1) [:len $dangerString]]);
            :local stringId1 ("$[$DecToHex ([:tonum ($stringId2)] +1)]");
            :if ([:len [:find $dangerString1 $stringId1]]!=0) do={
                :local dangerIP ([:pick $string2 ([:find $string2 "from"] +5) ([:len $string2])]);
                :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
            }
        }
        [$NotFound $isDetected];
    
    #----------- Stage of searching for attempts to enter through OVPN  -----------
        :put "$[system clock get time] - Stage of searching for attempts to enter through OVPN:";
        :local dangerString1 [:toarray [:log find topics~"ovpn" topics~"error" message~"unknown msg" or message~"msg too short"]];
        :local dangerString2 [:toarray [:log find topics~"ovpn" message~"TCP connection established from"]];
        :set $isDetected false;
        :foreach dangerString in=$dangerString2 do={
            :local string2   ([:log get $dangerString message])
            :local stringId2 ("0x".[:pick $dangerString ([:find $dangerString "*"] +1) [:len $dangerString]]);
            :local stringId1 ("$[$DecToHex ([:tonum ($stringId2)] +1)]");
            :if ([:len [:find $dangerString1 $stringId1]]!=0) do={
                :local dangerIP ([:pick $string2 ([:find $string2 "from"] +5) ([:len $string2])]);
                :if ([$DangerIPAddr $dangerIP]) do={:set $isDetected true}
            }
        }
        [$NotFound $isDetected];
    }        

    :put "$[system clock get time] - End of searching dangerous addresses on '$[system identity get name]' router.";
} on-error={ 
    :put ("Script of blocking dangerous IP addresses worked with errors.");
    :log warning ("Script of blocking dangerous IP addresses worked with errors."); 
}

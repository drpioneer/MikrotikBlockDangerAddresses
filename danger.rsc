# Script of blocking dangerous addresses by drPioneer.
# https://forummikrotik.ru/viewtopic.php?t=4781&start=20
# tested on ROS 6.49
# updated 2021/12/29

:do {
    :local outMsg "Detected dangerous addresses:";
    :local lenMsg [:len [$outMsg]];
    
    # ----------- Stage 1 - search for a device login attempt ----------- 
    :foreach dangerString   in=[ /log find message~"login failure for user"; ] do={
        :foreach routerUser in=[ /user find disabled=no; ] do={
            :local stringTemp ([ /log get $dangerString message; ]);
            :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "from" ] - 1 )]);
            :local dangerIP   ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :find $stringTemp "via"  ] - 1 )]);
            :local dangerVia  ([ :pick $stringTemp ([ :find $stringTemp "via"  ])     ([ :find $stringTemp "via"  ] + 20)]);
            :if ($routerUser != $dangerUser) do={
                :if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP; ] = "" ) do={ 
                    /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                    :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong router user '".$dangerUser."' ".$dangerVia.")");
                } 
            }
        }
    }
    
    # ----------- Stage 2 - search for login attempts via WinBox  ----------- 
    :foreach dangerString in=[ /log find message~"denied winbox/dude connect from"; ] do={
        :local stringTemp   ([ /log get $dangerString message; ]);
        :local dangerIP     ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :len $stringTemp ]) ]);
        :if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP; ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (not allowed WinBox user IP-address)");
        }
    }
    
    # ----------- Stage 3 - search for an attempt to enter through IPSec password ----------- 
    :foreach dangerString in=[ /log find message~"parsing packet failed, possible cause: wrong password"; ] do={
        :local stringTemp   ([ /log get $dangerString message; ]);
        :local dangerIP     ([ :pick $stringTemp 0 ([ :find $stringTemp "parsing" ] - 1) ]);
        :if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP; ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong IPSec password)");
        }
    }
    
    # ----------- Stage 4 - search for an attempt to enter through IPSec proposal ----------- 
    :foreach dangerString in=[ /log find message~"failed to get valid proposal"; ] do={
        :local stringTemp   ([ /log get $dangerString message; ]);
        :local dangerIP     ([ :pick $stringTemp 0 ([ :find $stringTemp "failed" ] - 1) ]);
        :if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP; ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong IPSec proposal)");
        } 
    }
    
    # ----------- Stage 5 - search for an attempt to enter through L2TP ----------- 
    :foreach dangerString in=[ /log find topics~"l2tp" message~"user" message~"authentication failed"; ] do={
        :local stringTemp ([ /log get $dangerString message; ]);
        :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "authentication" ] - 1) ]);
        :local dangerIP   ([ :pick $stringTemp ([ :find $stringTemp "<"    ] + 1) ([ :find $stringTemp ">" ]) ]);
        :if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP; ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong L2TP user '".$dangerUser."')");
        }
    }    
    
    # ----------- Stage 6 - search for an attempt to enter through PPTP  ----------- 
    :foreach dangerStr1     in=[ /log find topics~"pptp" message~"user" message~"authentication failed"; ] do={
        :foreach dangerStr2 in=[ /log find topics~"pptp" message~"TCP connection established from"; ] do={
            :local stringId1 ("0x".[:pick $dangerStr1 ([:find $dangerStr1 "*"] + 1) [:len $dangerStr1]]);
            :local stringId2 ("0x".[:pick $dangerStr2 ([:find $dangerStr2 "*"] + 1) [:len $dangerStr2]]);
            :if ((($stringId1 - $stringId2) = 1) || (($stringId2 - $stringId1) = 1)) do={
                :local stringTemp ([ /log get $dangerStr1 message ]);
                :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "authentication" ] - 1) ]);
                :local stringTemp ([ /log get $dangerStr2 message; ]);
                :local dangerIP   ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :len $stringTemp ]) ]);
                :if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                    /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                    :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong PPTP user '".$dangerUser."')");
                }
            }
        }
    }
    
    # ----------- Checking & installing firewall-filter rule ----------- 
    :if ([ /ip firewall filter find src-address-list="BlockDangerAddress"; ] = "") do={
        /ip firewall filter add action=drop chain=input comment="Dropping dangerous adresses" src-address-list=BlockDangerAddress;
    }
    :if ([ /ip firewall filter find src-address-list="BlockDangerAddress" disabled=yes; ] != "") do={
        /ip firewall filter enable [ /ip firewall filter find src-address-list="BlockDangerAddress" disabled=yes; ];
    }

    # ----------- Output searching results ----------- 
    :if ([:len $outMsg] > $lenMsg) do={
        :put $outMsg;
        :log warning $outMsg;
    }
} on-error={ :log warning ("Script of blocking dangerous IP addresses worked with errors."); }


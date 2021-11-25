# Script for blocking dangerous addresses that tried to connect to the router by drPioneer
# https://forummikrotik.ru/viewtopic.php?p=82374#p82374
# tested on ROS 6.49
# updated 2021/11/23

:do {
    :local outMsg "Dangerous addresses detected:";
    :local lenMsg [:len $outMsg];

    # ----------- Stage 1 - search for a device login attempt ----------- 
    foreach routerUser in=[ /user find disabled=no; ] do={
        do {
            foreach dangerString in=[ /log find message~"login failure for user"; ] do={
                do { 
                    :local stringTemp ([ /log get $dangerString message ]);
                    :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "from" ] - 1 )]);
                    :local dangerIP   ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :find $stringTemp "via"  ] - 1 )]);
                    :local dangerVia  ([ :pick $stringTemp ([ :find $stringTemp "via"  ])     ([ :find $stringTemp "via"  ] + 20)]);
                    if ($routerUser != $dangerUser) do={
                        if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                            :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong router user '".$dangerUser."' ".$dangerVia.")");
                        } 
                    }
                } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string 'Login failure for user' in log."); } 
            }
        } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found active router user."); }
    }

    # ----------- Stage 2 - search for login attempts via WinBox  ----------- 
    foreach dangerString in=[ /log find message~"denied winbox/dude connect from"; ] do={
        do {
            :local stringTemp ([ /log get $dangerString message ]);
            :local dangerIP ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :len $stringTemp ]) ]);
            if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (not allowed WinBox user IP-address)");
            }
        } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string 'Denied winbox/dude connect from' in log."); }
    }

    # ----------- Stage 3 - search for an attempt to enter through IPSec password ----------- 
    foreach dangerString in=[ /log find message~"parsing packet failed, possible cause: wrong password"; ] do={
        do {
            :local stringTemp ([ /log get $dangerString message ]);
            :local dangerIP   ([ :pick $stringTemp 0 ([ :find $stringTemp "parsing" ] - 1) ]);
            if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong IPSec password)");
            }
        } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string 'Parsing packet failed, possible cause: wrong password' in log."); }
    }

    # ----------- Stage 4 - search for an attempt to enter through IPSec proposal ----------- 
    foreach dangerString in=[ /log find message~"failed to get valid proposal"; ] do={
        do {
            :local stringTemp ([ /log get $dangerString message ]);
            :local dangerIP   ([ :pick $stringTemp 0 ([ :find $stringTemp "failed" ] - 1) ]);
            if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong IPSec proposal)");
            } 
        } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string 'Failed to get valid proposal' in log."); }
    }

    # ----------- Stage 5 - search for an attempt to enter through L2TP ----------- 
    foreach dangerString in=[ /log find topics~"l2tp" message~"user" message~"authentication failed"; ] do={
        do {
            :local stringTemp ([ /log get $dangerString message ]);
            :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "authentication" ] - 1) ]);
            :local dangerIP   ([ :pick $stringTemp ([ :find $stringTemp "<"    ] + 1) ([ :find $stringTemp ">" ]) ]);
            if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong L2TP user '".$dangerUser."')");
            }
        } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string of L2TP 'User' & 'Authentication failed' in log."); }
    }    

    # ----------- Stage 6 - search for an attempt to enter through PPTP  ----------- 
    foreach dangerStr1 in=[ /log find topics~"pptp" message~"user" message~"authentication failed"; ] do={
        do {
            foreach dangerStr2 in=[ /log find topics~"pptp" message~"TCP connection established from"; ] do={
                do {
                    :local stringId1 ("0x".[:pick $dangerStr1 ([:find $dangerStr1 "*"] + 1) [:len $dangerStr1]]);
                    :local stringId2 ("0x".[:pick $dangerStr2 ([:find $dangerStr2 "*"] + 1) [:len $dangerStr2]]);
                    if (($stringId1 - $stringId2) = 1) do={
                        :local stringTemp ([ /log get $dangerStr1 message ]);
                        :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "authentication" ] - 1) ]);
                        :local stringTemp ([ /log get $dangerStr2 message ]);
                        :local dangerIP   ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :len $stringTemp ]) ]);
                        if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                            :set outMsg ($outMsg."\r\n>>> Added in black list IP ".$dangerIP." (wrong PPTP user '".$dangerUser."')");
                        }
                    }
                } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string of PPTP 'User' & 'Authentication failed' in log."); }
            }
        } on-error={ :set outMsg ($outMsg."\r\n>>> Script error. Not found string of PPTP 'User' & 'Authentication failed' in log."); }
    }

    # ----------- Output searching results ----------- 
    if ([:len $outMsg] > $lenMsg) do={
        :put $outMsg;
        :log warning $outMsg;
    }
}

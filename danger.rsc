# Script for blocking dangerous addresses that tried to connect to the router
# https://forummikrotik.ru/viewtopic.php?t=4781&start=20
# tested on ROS 6.47
# updated 2020/08/27

# ----------- Stage 1 - search for a device login attempt ----------- 
foreach routerUser in=[ /user find disabled=no; ] do={
    do {
        foreach dangerString in=[ /log find message~"login failure for user"; ] do={
            do { 
                :local stringTemp ([ /log get $dangerString message ]);
                :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "from" ] - 1) ]);
                :local dangerIP ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :find $stringTemp "via" ] - 1) ]);
                :local dangerVia ([ :pick $stringTemp ([ :find $stringTemp "via" ]) ([ :find $stringTemp "via" ] + 20)]);
                if ($routerUser != $dangerUser) do={
                    if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
                        /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
                        :log warning (">>> Added in black list IP ".$dangerIP." (wrong router user '".$dangerUser."' ".$dangerVia.")");
                    } 
                }
            } on-error={ :log warning ">>> Script error. Not found string 'login failure for user' in log."; } 
        }
    } on-error={ :log warning ">>> Script error. Not found active router user."; }
}

# ----------- Stage 2 - search for an attempt to enter through IPSec password ----------- 
foreach dangerString in=[ /log find message~"parsing packet failed, possible cause: wrong password"; ] do={
    do {
        :local stringTemp ([ /log get $dangerString message ]);
        :local dangerIP ([ :pick $stringTemp 0 ([ :find $stringTemp "parsing" ] - 1) ]);
        if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :log warning (">>> Added in black list IP ".$dangerIP." (wrong IPSec password)");
        }
    } on-error={ :log warning ">>> Script error. Not found string 'parsing packet failed, possible cause: wrong password' in log."; }
}

# ----------- Stage 3 - search for an attempt to enter through IPSec proposal ----------- 
foreach dangerString in=[ /log find message~"failed to get valid proposal"; ] do={
    do {
        :local stringTemp ([ /log get $dangerString message ]);
        :local dangerIP ([ :pick $stringTemp 0 ([ :find $stringTemp "failed" ] - 1) ]);
        if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :log warning (">>> Added in black list IP ".$dangerIP." (wrong IPSec proposal)");
        } 
    } on-error={ :log warning ">>> Script error. Not found string 'failed to get valid proposal' in log."; }
}

# ----------- Stage 4 - search for an attempt to enter through L2TP ----------- 
foreach dangerString in=[ /log find message~"user" message~"authentication failed"; ] do={
    do {
        :local stringTemp ([ /log get $dangerString message ]);
        :local dangerUser ([ :pick $stringTemp ([ :find $stringTemp "user" ] + 5) ([ :find $stringTemp "authentication" ] - 1) ]);
        :local dangerIP ([ :pick $stringTemp ([ :find $stringTemp "<" ] + 1) ([ :find $stringTemp ">" ]) ]);
        if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :log warning (">>> Added in black list IP ".$dangerIP." (wrong L2TP user '".$dangerUser."')");
        }
    } on-error={ :log warning ">>> Script error. Not found string 'user' & 'authentication failed' in log."; }
}    

# ----------- Stage 5 - search for login attempts via WinBox  ----------- 
foreach dangerString in=[ /log find message~"denied winbox/dude connect from"; ] do={
    do {
        :local stringTemp ([ /log get $dangerString message ]);
        :local dangerIP ([ :pick $stringTemp ([ :find $stringTemp "from" ] + 5) ([ :len $stringTemp ]) ]);
        if ([ /ip firewall address-list find list="BlockDangerAddress" address=$dangerIP ] = "" ) do={ 
            /ip firewall address-list add address=$dangerIP list="BlockDangerAddress" timeout=14d;
            :log warning (">>> Added in black list IP ".$dangerIP." (not allowed WinBox user IP-address)");
        }
    } on-error={ :log warning ">>> Script error. Not found string 'denied winbox/dude connect from' in log."; }
}

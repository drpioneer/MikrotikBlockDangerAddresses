# Script for searching and blocking dangerous addresses by drPioneer.
# Script uses ideas by podarok66, evgeniy.demin, Virtue, tgrba, denismikh, MMAXSIM, andrey-d, GregoryGost
# https://forummikrotik.ru/viewtopic.php?p=84017#p84017
# tested on ROS 6.49.5
# updated 2022/04/01

:do {
    # extremeScan: false / true -> Setting log scan level:  false = usual option; true = extremal option.
    # inIfaceList: "value" -> in.Interface List: "internet","WAN" etc. = manual input of the value; "" = automatic value selection; 

    :local extremeScan      false;
    :local timeoutBL        "2w";
    :local inIfaceList      "";
    :local nameBlackList    "BlockDangerAddress";
    :local nameWhiteList    "WhiteList";
    :local commentRuleBL    "Dropping dangerous addresses";
    :local commentRuleWL    "White List of IP-addresses";
 
    # Verifying function correctness of IP address v.4
    :local DangerIPAddr do={
        :if ($1~"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}") do={
            :if ([/ip firewall address-list find address=$1 list=$2]="") do={ 
                /ip firewall address-list add address=$1 list=$2 timeout=$3;
                :put "$[/system clock get time] - Added in BlackList IP-address: $1";
                :log warning ">>> Added in BlackList IP: $1";
                :return (true);
            }
        }
        :return (false);
    }

    # Function that reports the absence of dangerous addresses
    :local NotFound do={
        :if (!$1) do={:put "$[/system clock get time] - No new dangerous IP-addresses were found."}
    }

    # Function of converting decimal numbers to hexadecimal
    :local DecToHex do={
        :if ($1 < 10) do={:return ("*".$1)}
        :local tempNumber $1;
        :local result "";
        :local remainder 0; 
        :local hexTable [:toarray "0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F"];
        :while ($tempNumber > 0) do={
            :set remainder ($tempNumber % 16);
            :set tempNumber [:tonum ($tempNumber >> 4)];
            :set result (($hexTable->$remainder).$result);
        }
        :return ("*".$result);
    }

    # String parsing function
    :local StrParser do={
        :if ([:len [:find $1 $2 -1]] = 0) do={:return ("")}
        :local startPos ([:find $1 $2 -1] + [:len $2] +1);
        :local stopPos 0;
        :if ([:len [:find $1 ";" $startPos]] = 0) do={
            :set $stopPos [:find $1 "\"" $startPos];
        } else={
            :set $stopPos [:find $1 ";" $startPos];
        }
        :if ($stopPos < $startPos) do={:set stopPos ($startPos + 1)};
        :return ([:pick $1 $startPos $stopPos]);
    }

    #Gateway interface-list search function
    :local IfListGWFinder do={
        :local gwIface [/ip route get [find dst-address=0.0.0.0/0 active=yes] vrf-interface];
        :if ([:len [/interface bridge find name=$gwIface]]!=0) do={
            :foreach brIface in=[/interface bridge port find bridge=$gwIface inactive=no] do={
                :set gwIface [/interface bridge port get $brIface interface];
            }
        }
        :foreach ifList in=[/interface list member find interface=$gwIface] do={
            :return ([/interface list member get $ifList list]);
        }
    }

    # Main body of the script
    :put "$[/system clock get time] - Start of searching dangerous addresses on '$[/system identity get name]' router.";
    :if ($extremeScan) do={:put "$[/system clock get time] - BE CAREFUL!!!!!! Extreme scanning mode is ENABLED!"}
    :set $timeoutBL [:totime $timeoutBL];
    
    #----------- Stage of searching for failed login attempts -----------
    :put "$[/system clock get time] - Stage of searching for failed login attempts:";
    :local isDetected false;
    :foreach dangerString in=[:log find topics~"system" message~"login failure for user"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "from"] +5) ([:find $stringTemp "via"] -1)]);
        :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];
    
    #----------- Stage of searching for login attempts from unknown networks  -----------
    :put "$[/system clock get time] - Stage of searching for login attempts from unknown networks:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"warning" message~"denied winbox/dude connect from"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "from"] +5) ([:len $stringTemp])]);
        :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to enter through an IPsec password -----------
    :put "$[/system clock get time] - Stage of searching for attempts to enter through an IPsec password:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"ipsec" message~"parsing packet failed, possible cause: wrong password"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp 0 ([:find $stringTemp "parsing"] -1)]);
        :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to enter through IPSec proposal -----------
    :put "$[/system clock get time] - Stage of searching for attempts to enter through IPSec proposal:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"ipsec" message~"failed to pre-process ph1 packet"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp 0 ([:find $stringTemp "failed"] -1)]);
        :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to enter through L2TP -----------    
    :put "$[/system clock get time] - Stage of searching for attempts to enter through L2TP:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"l2tp" message~"authentication failed"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "<"] +1) ([:find $stringTemp ">"]) ]);
        :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for TCP SYN attacks attempts  -----------    
    :put "$[/system clock get time] - Stage of searching for TCP SYN attacks attempts:";
    :set $isDetected false;
    :foreach dangerString in=[:log find topics~"firewall" message~"(SYN)"] do={
        :local stringTemp ([:log get $dangerString message]);
        :local dangerIP ([:pick $stringTemp ([:find $stringTemp "TCP (SYN),"] +11) ([:len $stringTemp]) ]);
        :set   dangerIP ([:pick $dangerIP 0 ([:find $dangerIP ":"]) ]);
        :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
    }
    [$NotFound $isDetected];

    #----------- Stage of searching for attempts to establish TCP connection -----------
    :if ($extremeScan) do={
        :put "$[/system clock get time] - Stage of searching for attempts to establish TCP connection:";
        :set $isDetected false;
        :foreach dangerString in=[:log find message~"TCP connection established from"] do={
            :local stringTemp ([:log get $dangerString message]);
            :local dangerIP ([:pick $stringTemp ([:find $stringTemp "from"] +5) ([:len $stringTemp]) ]);
            :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
        }
        [$NotFound $isDetected];
    } else={

    #----------- Stage of searching for attempts to enter through PPTP -----------
        :put "$[/system clock get time] - Stage of searching for attempts to enter through PPTP:";
        :local dangerString1 [:toarray [:log find topics~"pptp" message~"authentication failed"]];
        :local dangerString2 [:toarray [:log find topics~"pptp" message~"TCP connection established from"]];
        :set $isDetected false;
        :foreach dangerString in=$dangerString2 do={
            :local string2   ([:log get $dangerString message])
            :local stringId2 ("0x".[:pick $dangerString ([:find $dangerString "*"] +1) [:len $dangerString]]);
            :local stringId1 ("$[$DecToHex ([:tonum ($stringId2)] +1)]");
            :if ([:len [:find $dangerString1 $stringId1]]!=0) do={
                :local dangerIP ([:pick $string2 ([:find $string2 "from"] +5) ([:len $string2])]);
                :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
            }
        }
        [$NotFound $isDetected];
    
    #----------- Stage of searching for attempts to enter through OVPN  -----------
        :put "$[/system clock get time] - Stage of searching for attempts to enter through OVPN:";
        :local dangerString1 [:toarray [:log find topics~"ovpn" topics~"error" message~"unknown msg" or message~"msg too short"]];
        :local dangerString2 [:toarray [:log find topics~"ovpn" message~"TCP connection established from"]];
        :set $isDetected false;
        :foreach dangerString in=$dangerString2 do={
            :local string2   ([:log get $dangerString message])
            :local stringId2 ("0x".[:pick $dangerString ([:find $dangerString "*"] +1) [:len $dangerString]]);
            :local stringId1 ("$[$DecToHex ([:tonum ($stringId2)] +1)]");
            :if ([:len [:find $dangerString1 $stringId1]]!=0) do={
                :local dangerIP ([:pick $string2 ([:find $string2 "from"] +5) ([:len $string2])]);
                :if ([$DangerIPAddr $dangerIP $nameBlackList $timeoutBL]) do={:set $isDetected true}
            }
        }
        [$NotFound $isDetected];
    }        

    # ----------- Checking & installing firewall rules -----------
    :put "$[/system clock get time] - Stage of checking and installing firewall rules:";
    :if ([/ip firewall address-list find list=$nameWhiteList]="") do={/ip firewall address-list add address="input_your_address" list=$nameWhiteList}
    :if ($inIfaceList="") do={
        :set inIfaceList [$IfListGWFinder];
        :put "$[/system clock get time] - Variable 'inIfaceList' is empty -> so value '$inIfaceList' is automatically assigned.";
    }
    :local ruleID "";
    :local cmment "";
    :if ([:len [/interface list find name=$inIfaceList]]!=0) do={
        /ip firewall filter;
        find;
        :local firewallFilterRules [:toarray {
            "add action=drop chain=input comment=\"$commentRuleBL\" src-address-list=$nameBlackList disabled=yes";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"DDoS Protect - Connection Limit - Step 1\" connection-limit=100,32 log=yes log-prefix=WARNING protocol=tcp in-interface-list=$inIfaceList";
            "add action=tarpit chain=input comment=\"DDoS Protect - Connection Limit - Step 2\" connection-limit=3,32 log=yes log-prefix=WARNING protocol=tcp src-address-list=$nameBlackList in-interface-list=$inIfaceList";
            "add action=jump chain=input comment=\"DDoS Protect - SYN Flood - Step 1\" connection-state=new jump-target=SYN-Protect protocol=tcp tcp-flags=syn in-interface-list=$inIfaceList";
            "add action=return chain=SYN-Protect comment=\"DDoS Protect - SYN Flood - Step 2\" connection-state=new limit=200,5:packet protocol=tcp tcp-flags=syn in-interface-list=$inIfaceList";
            "add action=drop chain=SYN-Protect comment=\"DDoS Protect - SYN Flood - Step 3\" connection-state=new log=yes log-prefix=WARNING protocol=tcp tcp-flags=syn in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"Port scan\" log=yes log-prefix=WARNING protocol=tcp psd=21,3s,3,1 in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"FIN/!SYN/!RST/!PSH/!ACK scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,!syn,!rst,!psh,!ack,!urg in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"FIN/SYN/RST/PSH/ACK/URG scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"FIN/!SYN/!RST/PSH/!ACK/URG scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"!FIN/!SYN/!RST/!PSH/!ACK/!URG scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"!FIN/!SYN/!RST/!ACK scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=!fin,!syn,!rst,!ack in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"FIN/!ACK scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,!ack in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"FIN/RST scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,rst in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"FIN/URG scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,urg in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"SYN/FIN scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=fin,syn in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"SYN/RST scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=syn,rst in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"RST/URG scan\" log=yes log-prefix=WARNING protocol=tcp tcp-flags=rst,urg in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"TCP Destination Port 0 scan\" dst-port=0 log=yes log-prefix=WARNING protocol=tcp in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"TCP Source Port 0 scan\" log=yes log-prefix=WARNING protocol=tcp src-port=0 in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"UDP Destination Port 0 scan\" dst-port=0 log=yes log-prefix=WARNING protocol=udp in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"UDP Source Port 0 scan\" log=yes log-prefix=WARNING protocol=udp src-port=0 in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=$nameBlackList address-list-timeout=$timeoutBL chain=input comment=\"Protected - WinBox Access - Step 4\" connection-state=new dst-port=8291,8728 log=yes log-prefix=WARNING protocol=tcp src-address-list=WinboxStage3 in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=WinboxStage3 address-list-timeout=1m chain=input comment=\"Protected - WinBox Access - Step 3\" connection-state=new dst-port=8291,8728 protocol=tcp src-address-list=WinboxStage2 in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=WinboxStage2 address-list-timeout=1m chain=input comment=\"Protected - WinBox Access - Step 2\" connection-state=new dst-port=8291,8728 protocol=tcp src-address-list=WinboxStage1 in-interface-list=$inIfaceList";
            "add action=add-src-to-address-list address-list=WinboxStage1 address-list-timeout=1m chain=input comment=\"Protected - WinBox Access - Step 1\" connection-state=new dst-port=8291,8728 protocol=tcp in-interface-list=$inIfaceList";
            "add action=accept chain=input comment=\"Accepted - WinBox Access\" dst-port=8291,8728 protocol=tcp in-interface-list=$inIfaceList";
        }];
        :if ([:len [find]]=0) do={
            add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no;
        } else={
            :if ([find src-address-list=$nameWhiteList]="") do={
                :if ([find action~"passthrough" dynamic=yes]="") do={
                    add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=0;
                } else={
                    :set ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid"];
                    :if ($ruleID!="") do={add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=$ruleID}
                }
            }
        }
        :if ([find src-address-list=$nameWhiteList disabled=yes]!="") do={enable [find src-address-list=$nameWhiteList disabled=yes]}
        :foreach filterRule in=$firewallFilterRules do={
            :set $cmment [$StrParser [:tostr $filterRule] "comment="];
            :if ([:len [/ip firewall filter find comment~$cmment]] = 0) do={
                :put ("$[/system clock get time] - Firewall Filter rule with comment '$cmment' not found. Added a missing rule.");
                [:parse "ip firewall filter $filterRule"];
            } 
        }
        :if ([find src-address-list=$nameBlackList disabled=yes]!="") do={
            #enable [find src-address-list=$nameBlackList disabled=yes];
            :put "$[/system clock get time] - ATTENTION!!! Filter-rule for blocking dangerous IP-addresses is DISABLED. Check rule properties in 'IP-Firewall-Filter Rules'.";
            :log warning "ATTENTION!!! Rule for blocking dangerous IP-addresses is DISABLED.";
            :log warning "Check rule properties in 'IP-Firewall-Filter Rules'.";
        }
        /;
    
        /ip firewall raw;
        find;
        :local firewallRawRules [:toarray {
            "add action=drop chain=prerouting comment=\"$commentRuleBL\" src-address-list=$nameBlackList disabled=yes";
            "add action=drop chain=prerouting comment=\"Drop NetBIOS parasit traffic\" dst-port=137,138,139 protocol=udp in-interface-list=$inIfaceList";
            "add action=drop chain=prerouting comment=\"Drop DNS parasit traffic\" dst-port=53 protocol=udp in-interface-list=$inIfaceList";
            "add action=drop chain=prerouting comment=\"Drop NTP parasit traffic\" dst-port=123 protocol=udp in-interface-list=$inIfaceList";
        }];
        :if ([:len [find]]=0) do={
            add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no
        } else={
            :if ([find src-address-list=$nameWhiteList]="") do={
                :if ([find action~"passthrough" dynamic=yes]="") do={
                    add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=0;
                } else={
                    :set ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid"];
                    :if ($ruleID!="") do={add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=$ruleID;}
                }
            }
        }
        :if ([find src-address-list=$nameWhiteList disabled=yes]!="") do={enable [find src-address-list=$nameWhiteList disabled=yes]}
        :foreach filterRule in=$firewallRawRules do={
            :set $cmment [$StrParser [:tostr $filterRule] "comment="];
            :if ([:len [/ip firewall raw find comment~$cmment]] = 0) do={
                :put ("$[/system clock get time] - Firewall Raw rule with comment '$cmment' not found. Added a missing rule.");
                [:parse "ip firewall raw $filterRule"];
            } 
        }
        :if ([find src-address-list=$nameBlackList disabled=yes]!="") do={
            #enable [find src-address-list=$nameBlackList disabled=yes];
            :put "$[/system clock get time] - ATTENTION!!! RAW-rule for blocking dangerous IP-addresses is DISABLED. Check rule properties in 'IP-Firewall-Raw'.";
            :log warning "ATTENTION!!! Rule for blocking dangerous IP-addresses is DISABLED.";
            :log warning "Check rule properties in 'IP-Firewall-Raw'.";
        }
        /;
    } else={:put ("$[/system clock get time] - ATTENTION!!! Not found input list interfaces named '$inIfaceList'. Check it 'Interfaces-Interface List'.")}

    # ----------- Script completion -----------
    :put "$[/system clock get time] - End of searching dangerous addresses on '$[/system identity get name]' router.";
} on-error={ 
    :put ("Script of blocking dangerous IP addresses worked with errors.");
    :log warning ("Script of blocking dangerous IP addresses worked with errors."); 
}

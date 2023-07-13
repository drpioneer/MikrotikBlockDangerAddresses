# Script for searching and blocking dangerous addresses
# Script uses ideas by podarok66, evgeniy.demin, Virtue, tgrba, denismikh, MMAXSIM, andrey-d, GregoryGost, Chupaka, Jotne, drPioneer.
# https://forummikrotik.ru/viewtopic.php?p=84017#p84017
# https://github.com/drpioneer/MikrotikBlockDangerAddresses
# tested on ROS 6.49.8
# updated 2023/07/12

:global scriptBlckr;                # Flag of the running script:   false=>in progress, true=>idle
:do {
    :local timeoutBL     "1d";      # Timeout of Blacklist
    :local inIfaceList   "";        # Name of input interface list: "internet","WAN" etc. = manual input value; "" = automatic value selection
    :local firewallUsage true;      # Enabling firewall rules
    :local extremeScan   true;      # Setting log scan level: false = usual option; true = extremal option
    :local logEntry      false;     # Maintaining log entries
    :local staticAddrLst false;     # Converting Blacklist from dynamic to static
    :local nameBlackList "BlockDangerAddress";           # Name of Blacklist
    :local nameWhiteList "WhiteList";                    # Name of Whitelist
    :local commentRuleBL "Dropping dangerous addresses"; # Comment for Blacklist rule
    :local commentRuleWL "White List of IP-addresses";   # Comment for Whitelist rule

    # Function of verifying correctness IP-address v.4 & blacklisting it
    :local DangerIPAddr do={
        :if ($1~"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}") do={
            :if ([/ip firewall address-list find address=$1 list=$2]="") do={ 
                /ip firewall address-list add address=$1 list=$2 timeout=$3;
                :put "$[/system clock get time]\tAdded in BlackList IP-address: $1";
                :if ($4) do={:log warning ">>> Added in BlackList IP: $1"}
                :return true;
            }
        }
        :return false;
    }

    # Function that reports the absence of dangerous addresses
    :local NotFound do={
        :if (!$1) do={:put "$[/system clock get time]\tNo new dangerous IP-addresses were found"}
    }

    # Function of converting decimal numbers to hexadecimal
    :local DecToHex do={
        :if ($1<10) do={:return "*$1"}
        :local tempNumber $1;
        :local result "";
        :local remainder 0; 
        :local hexTable [:toarray "0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F"];
        :while ($tempNumber>0) do={
            :set remainder ($tempNumber%16);
            :set tempNumber [:tonum ($tempNumber>>4)];
            :set result (($hexTable->$remainder).$result);
        }
        :return "*$result";
    }

    # String parsing function
    :local StrParser do={
        :if ([:len [:find $1 $2 -1]]=0) do={:return ""}
        :local startPos ([:find $1 $2 -1]+[:len $2] +1);
        :local stopPos 0;
        :if ([:len [:find $1 ";" $startPos]]=0) do={:set $stopPos [:find $1 "\"" $startPos]} else={:set $stopPos [:find $1 ";" $startPos]}
        :if ($stopPos<$startPos) do={:set stopPos ($startPos+1)}
        :return [:pick $1 $startPos $stopPos];
    }

    #Gateway interface-list search function
    :local IfListGWFinder do={
        :local inetGate [/ip route find dst-address=0.0.0.0/0 active=yes]
        :local gwInface [/ip route get $inetGate vrf-interface];
        :local brdgName [/interface bridge find name=$gwInface];
        :if ([:len $gwInface]>0 && [:len $brdgName]>0) do={
            :local ipAddrGt  [/ip route get $inetGate gateway];
            :local macAddrGt [/ip arp get [find address=$ipAddrGt interface=$gwInface] mac-address];
            :set   gwInface  [/interface bridge host get [find mac-address=$macAddrGt] interface];
        }
        :foreach ifList in=[/interface list member find interface=$gwInface] do={:return [/interface list member get $ifList list]}
    }

    # Main body of the script
    :put "$[/system clock get time]\tStart of searching dangerous addresses on '$[/system identity get name]' router";
    :if ([:len $scriptBlckr]=0) do={:set scriptBlckr true}
    :if ($scriptBlckr) do={
        :set scriptBlckr false;
        :if ($extremeScan) do={:put "$[/system clock get time]\tBE CAREFUL!!!!!! Extreme scanning mode is ENABLED!"}
        :set $timeoutBL [:totime $timeoutBL];

        # ----------- Checking & installing firewall rules -----------
        :put "$[/system clock get time]\tStage of checking and installing firewall rules:";
        :if ($inIfaceList="") do={:set inIfaceList [$IfListGWFinder]; :put "$[/system clock get time]\tVariable 'inIfaceList' is empty -> so value '$inIfaceList' is automatically assigned"}
        :if ([:len [/interface list find name=$inIfaceList]]!=0) do={

            # ----------- Checking & installing optional firewall rules -----------
            :if ($firewallUsage) do={
                :local cmmnt "";
                /ip firewall filter;
                find;
                :local firewallFilterRules [:toarray {
                    "add action=jump chain=input comment=\"Packet analysis for attacks\" in-interface-list=$inIfaceList jump-target=TARPIT protocol=tcp src-address-list=$nameBlackList";
                    "add action=tarpit chain=TARPIT comment=\"Slow down attack to router\" limit=10,10:packet protocol=tcp";
                    "add action=drop chain=TARPIT comment=\"Drop rest of TCP attack\" protocol=tcp";
                    "add action=jump chain=input comment=\"Brute force protection on specified ports\" connection-state=new dst-port=8291 in-interface-list=$inIfaceList jump-target=BruteForce protocol=tcp"
                    "add action=return chain=BruteForce comment=\"Packet analysis for brute force on the specified ports\" dst-limit=4/1m,1,src-address/1m40s"
                    "add action=add-src-to-address-list chain=BruteForce comment=\"Add to BlackList attacker who used specified ports\" address-list=$nameBlackList address-list-timeout=$timeoutBL"
                    "add action=accept chain=input comment=\"Accepted WinBox access\" dst-port=8291 protocol=tcp in-interface-list=$inIfaceList";
                    "add action=add-src-to-address-list chain=input comment=\"Add to BlackList attacker who used unopened ports\" address-list=$nameBlackList address-list-timeout=$timeoutBL dst-address-type=!broadcast in-interface-list=$inIfaceList";
                    "add action=drop chain=input comment=\"Drop rest of the packets\" in-interface-list=$inIfaceList";
                }];
                :foreach filterRule in=$firewallFilterRules do={
                    :set $cmmnt [$StrParser [:tostr $filterRule] "comment="];
                    :if ([:len [/ip firewall filter find comment~$cmmnt]]=0) do={
                        :put "$[/system clock get time]\tFirewall Filter rule with comment '$cmmnt' not found. Added a missing rule";
                        [:parse "ip firewall filter $filterRule"];
                    } 
                }
                /;

                /ip firewall raw;
                find;
                :local firewallRawRules [:toarray {
                    "add action=drop chain=prerouting comment=\"Drop NetBIOS parasit traffic\" dst-port=137,138,139 protocol=udp in-interface-list=$inIfaceList";
                    "add action=drop chain=prerouting comment=\"Drop DNS parasit traffic\" dst-port=53 protocol=udp in-interface-list=$inIfaceList";
                }];
                :foreach filterRule in=$firewallRawRules do={
                    :set $cmmnt [$StrParser [:tostr $filterRule] "comment="];
                    :if ([:len [/ip firewall raw find comment~$cmmnt]]=0) do={
                        :put "$[/system clock get time]\tFirewall Raw rule with comment '$cmmnt' not found. Added a missing rule";
                        [:parse "ip firewall raw $filterRule"];
                    } 
                }
                /;
            } else={:put "$[/system clock get time]\tATTENTION!!! Firewall rule checking is DISABLED (firewallUsage = false). Recommended to ENABLE (firewallUsage = true)"}

            # ----------- Checking & installing mandatory firewall rules -----------
            :local ruleID "";
            :if ([/ip firewall address-list find list=$nameWhiteList]="") do={/ip firewall address-list add address="input_your_address" list=$nameWhiteList}
            /ip firewall filter;
            :local firewallFlt [find];
            :if ([:len $firewallFlt]=0) do={
                add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no;
            } else={
                :if ([find src-address-list=$nameWhiteList]="") do={
                    :if ([find action~"passthrough" dynamic=yes]="") do={
                        add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=($firewallFlt->0);
                    } else={
                        :set ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid"];
                        :if ($ruleID!="") do={add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=$ruleID}
                    }
                }
            }        
            :if ([find src-address-list=$nameWhiteList disabled=yes]!="") do={enable [find src-address-list=$nameWhiteList disabled=yes]}
            /

            /ip firewall raw;
            :local firewallRaw [find];
            :if ([:len $firewallRaw]=0) do={
                add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no;
            } else={
                :if ([find src-address-list=$nameWhiteList]="") do={
                    :if ([find action~"passthrough" dynamic=yes]="") do={
                        add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=($firewallRaw->0);
                    } else={
                        :set ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid"];
                        :if ($ruleID!="") do={add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=$ruleID}
                    }
                }
            }
            :if ([find src-address-list=$nameWhiteList disabled=yes]!="") do={enable [find src-address-list=$nameWhiteList disabled=yes]}
            :if ([find src-address-list=$nameBlackList]="") do={add action=drop chain=prerouting comment=$commentRuleBL src-address-list=$nameBlackList in-interface-list=$inIfaceList protocol=!tcp disabled=yes}
            :if ([find src-address-list=$nameBlackList disabled=yes]!="") do={
                :put "$[/system clock get time]\tATTENTION!!! RAW-rule for blocking dangerous IP-addresses is DISABLED. Check rule properties in 'IP-Firewall-Raw'";
                :log warning "ATTENTION!!! Rule for blocking dangerous IP-addresses is DISABLED.";
                :log warning "Check rule properties in 'IP-Firewall-Raw'.";
            }
            /
        } else={:put "$[/system clock get time]\tATTENTION!!! Not found input list interfaces named '$inIfaceList'. Check it 'Interfaces-Interface List'. Protection does not work!!!"}

        #----------- Stage of searching for failed login attempts -----------
        :put "$[/system clock get time]\tStage of searching for failed login attempts:";
        :local isDetected false;
        :foreach dangerString in=[:log find topics~"system" message~"login failure for user"] do={
            :local stringTemp [:log get $dangerString message];
            :local dangerIP [:pick $stringTemp ([:find $stringTemp "from"] +5) ([:find $stringTemp "via"] -1)];
            :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
        }
        [$NotFound $isDetected];

        #----------- Stage of searching for login attempts from unknown networks  -----------
        :put "$[/system clock get time]\tStage of searching for login attempts from unknown networks:";
        :set $isDetected false;
        :foreach dangerString in=[:log find topics~"warning" message~"denied winbox/dude connect from"] do={
            :local stringTemp [:log get $dangerString message];
            :local dangerIP [:pick $stringTemp ([:find $stringTemp "from"] +5) ([:len $stringTemp])];
            :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
        }
        [$NotFound $isDetected];

        #----------- Stage of searching for attempts to enter through an IPsec password -----------
        :put "$[/system clock get time]\tStage of searching for attempts to enter through an IPsec password:";
        :set $isDetected false;
        :foreach dangerString in=[:log find topics~"ipsec" message~"parsing packet failed, possible cause: wrong password"] do={
            :local stringTemp [:log get $dangerString message];
            :local dangerIP [:pick $stringTemp 0 ([:find $stringTemp "parsing"] -1)];
            :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
        }
        [$NotFound $isDetected];

        #----------- Stage of searching for attempts to enter through IPSec proposal -----------
        :put "$[/system clock get time]\tStage of searching for attempts to enter through IPSec proposal:";
        :set $isDetected false;
        :foreach dangerString in=[:log find topics~"ipsec" message~"failed to pre-process ph1 packet"] do={
            :local stringTemp [:log get $dangerString message];
            :local dangerIP [:pick $stringTemp 0 ([:find $stringTemp "failed"] -1)];
            :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
        }
        [$NotFound $isDetected];

        #----------- Stage of searching for attempts to enter through L2TP -----------
        :put "$[/system clock get time]\tStage of searching for attempts to enter through L2TP:";
        :set $isDetected false;
        :foreach dangerString in=[:log find topics~"l2tp" message~ "user" message~"authentication failed"] do={
            :local stringTemp [:log get $dangerString message];
            :local dangerIP [:pick $stringTemp ([:find $stringTemp "<"] +1) [:find $stringTemp ">"]];
            :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
        }
        [$NotFound $isDetected];

        #----------- Stage of searching for attempts to establish TCP connection -----------
        :if ($extremeScan) do={
            :put "$[/system clock get time]\tStage of searching for attempts to establish TCP connection:";
            :set $isDetected false;
            :foreach dangerString in=[:log find message~"TCP connection established from"] do={
                :local stringTemp [:log get $dangerString message];
                :local dangerIP [:pick $stringTemp ([:find $stringTemp "from"] +5) [:len $stringTemp]];
                :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
            }
            [$NotFound $isDetected];
        } else={

        #----------- Stage of searching for attempts to enter through PPTP -----------
            :put "$[/system clock get time]\tStage of searching for attempts to enter through PPTP:";
            :local dangerString1 [:toarray [:log find topics~"pptp" message~"authentication failed"]];
            :local dangerString2 [:toarray [:log find topics~"pptp" message~"TCP connection established from"]];
            :set $isDetected false;
            :foreach dangerString in=$dangerString2 do={
                :local string2 [:log get $dangerString message];
                :local stringId2 ("0x".[:pick $dangerString ([:find $dangerString "*"] +1) [:len $dangerString]]);
                :local stringId1 "$[$DecToHex ([:tonum ($stringId2)] +1)]";
                :if ([:len [:find $dangerString1 $stringId1]]!=0) do={
                    :local dangerIP [:pick $string2 ([:find $string2 "from"] +5) [:len $string2]];
                    :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
                }
            }
            [$NotFound $isDetected];

        #----------- Stage of searching for attempts to enter through OVPN  -----------
            :put "$[/system clock get time]\tStage of searching for attempts to enter through OVPN:";
            :local dangerString1 [:toarray [:log find topics~"ovpn" topics~"error" message~"unknown msg" or message~"msg too short"]];
            :local dangerString2 [:toarray [:log find topics~"ovpn" message~"TCP connection established from"]];
            :set $isDetected false;
            :foreach dangerString in=$dangerString2 do={
                :local string2 [:log get $dangerString message];
                :local stringId2 ("0x".[:pick $dangerString ([:find $dangerString "*"] +1) [:len $dangerString]]);
                :local stringId1 "$[$DecToHex ([:tonum ($stringId2)] +1)]";
                :if ([:len [:find $dangerString1 $stringId1]]!=0) do={
                    :local dangerIP [:pick $string2 ([:find $string2 "from"] +5) [:len $string2]];
                    :if [$DangerIPAddr $dangerIP $nameBlackList $timeoutBL $logEntry] do={:set $isDetected true}
                }
            }
            [$NotFound $isDetected];
        }

        #----------- Stage of converting Blacklist from dynamic to static -----------
        :if ($staticAddrLst) do={
        :put "$[/system clock get time]\tStage of converting Blacklist from dynamic to static:";
            :foreach idx in=[/ip firewall address-list find dynamic=yes list=$nameBlackList] do={
                :local ipaddress [/ip firewall address-list get $idx address];
                /ip firewall address-list remove $idx;
                /ip firewall address-list add list=$nameBlackList address=$ipaddress;
            }
        }

        # ----------- Script completion -----------
        :set scriptBlckr true;
    } else={:put "$[/system clock get time]\tScript already being executed..."}
    :put "$[/system clock get time]\tEnd of searching dangerous addresses script";
} on-error={
    # ----------- Script error ----------- 
    :set scriptBlckr true;
    :put "Script of blocking dangerous IP addresses worked with errors";
    :log warning "Script of blocking dangerous IP addresses worked with errors";
}

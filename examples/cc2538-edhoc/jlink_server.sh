#! /usr/bin/sh
 
JLinkGDBServerCLExe -Device cc2538sf53 -Speed 4000 -If JTAG -JTAGConf "-1,-1" -LocalHostOnly 1 -Silent 1 -Reset 1 -nohalt

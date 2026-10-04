Threat lists used by the Packet Eye alert engine.

The upstream lists are NOT stored in the repository (their licences don't
all allow redistribution). Download them with:

    npm run fetch-threats

which writes into this folder:

    spamhaus-drop.txt       https://www.spamhaus.org/drop/drop.txt
    firehol-level1.netset   https://iplists.firehol.org/files/firehol_level1.netset
    tor-exit.txt            https://check.torproject.org/exit-addresses

custom.txt is your own list (one IP or CIDR per line, # for comments).
Restart the agent after updating any file.

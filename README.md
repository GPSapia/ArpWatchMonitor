A program that monitors log file generated by arpwatch (executed with -d option in order to redirect its input to a chosen file).

Whenever the python script discover a new entry in the log, it calls the C shared object responsible of sending a packet to the ethernet address contained in the log entry.

Done for small university project. 

Usage: python3 file_parser.py iface_name log_file

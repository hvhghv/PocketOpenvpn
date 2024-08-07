import sys


if len(sys.argv) != 2:
    print("argument error")
    
if sys.argv[1] == "server":
    import server

else:
    import client
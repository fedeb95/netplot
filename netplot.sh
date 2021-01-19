sudo tcpdump -i $1 -w $2 && sudo ./venv/bin/python3 netplot.py -i $1 -f $2 "${@:3:10}"

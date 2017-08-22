# erspan-capture
captures traffic and replays it emulating an ERSPAN session

Some examples

# dump on eth0 1 packet, erspan it to 1.1.1.1 with erspan span_id=666, using gre sequence numbers (start from 0)
./erspan-capture -i eth0 --erspan_l3dest 1.1.1.1 -c 1   --erspan_id 666 --erspan_gre_seq 1

# dump on eth0 1 packet of icmp traffic, erspan it to 1.1.1.1 with erspan span_id=222, not using gre sequence numbers
./erspan-capture -i eth0 --erspan_l3dest 1.1.1.1 -c 1   --erspan_id 222 --erspan_gre_seq 0 --filter "icmp"

# dump on eth0 1 packet, erspan it to 1.1.1.1 with erspan src 2.2.2.2
./erspan-capture -i eth0 --erspan_l3dest 1.1.1.1 -c 1  --erspan_l3src 2.2.2.2

# dump on eth0 1 packet, erspan it to 1.1.1.1. l2 src/dst and egress interface hardset
./erspan-capture -i eth0 --erspan_l3dest 1.1.1.1 -c 1 --erspan_l2src "aa:bb:cc:dd:ee:ff" --erspan_l2dest "aa:bb:cc:dd:ee:ff" --erspan_egress_IF "eth0"

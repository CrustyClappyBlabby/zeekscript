# File: /opt/zeek/share/zeek/site/mqtt_only_conn.zeek

@load base/protocols/conn
@load base/frameworks/logging

event zeek_init()
    {
    # 1. Remove the default filter (which logs ALL traffic)
    Log::remove_default_filter(Conn::LOG);

    # 2. Add a new filter to ONLY log Port 1883 (MQTT)
    Log::add_filter(Conn::LOG, [
        $name = "mqtt-only",
        $path = "conn", # This writes to conn.log
        $pred = function(rec: Conn::Info): bool {
            # Return TRUE only if destination port is 1883
            return rec$id$resp_p == 1883/tcp;
        }
    ]);
    }
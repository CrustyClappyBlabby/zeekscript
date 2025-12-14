@load base/protocols/conn
@load base/protocols/mqtt/main
@load base/frameworks/logging
@load base/frameworks/notice

module C2_MQTT_Stealth;

export {
    redef enum Log::ID += { LOG_C2_MQTT };

    type SignalRecord: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        client_id: string &log &optional;
        category: string &log;
        indicator: string &log;
        details: string &log;
        confidence: double &log;
    };

    # Tunable thresholds
    const COOLDOWN_INTERVAL: interval = 5 mins &redef;
    const TIMING_SHORT_MIN: interval = 1.5 secs &redef;
    const TIMING_SHORT_MAX: interval = 2.5 secs &redef;
    const TIMING_LONG_MIN: interval = 4.5 secs &redef;
    const TIMING_LONG_MAX: interval = 5.5 secs &redef;
}

type C2State: record {
    # General state
    client_id: string;
    last_pub_ts: time;
    last_alert: table[string] of time; # Alert category -> timestamp

    # Indicator sets
    qos_levels: set[count];
    inter_arrival_buckets: set[string]; # "short", "long"
    header_keys: set[string];
    header_values: table[string] of set[string]; # key -> set of values
};

global state_tracker: table[addr] of C2State &read_expire = 15 mins;

event zeek_init()
    {
    Log::create_stream(C2_MQTT_Stealth::LOG_C2_MQTT, [$columns=SignalRecord, $path="c2_mqtt"]);
    }

function log_c2(c: connection, state: C2State, cat: string, ind: string, det: string, conf: double)
    {
    # Throttle alerts to avoid log spam
    if ( cat in state$last_alert && network_time() - state$last_alert[cat] < COOLDOWN_INTERVAL )
        return;

    state$last_alert[cat] = network_time();
    Log::write(LOG_C2_MQTT, [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $client_id=state$client_id,
        $category=cat,
        $indicator=ind,
        $details=det,
        $confidence=conf
    ]);
    }

event mqtt_connect(c: connection, is_orig: bool, client_id: string, proto_name: string, proto_version: count, connect_flags: MQTT::Connect_Flags, keep_alive: count)
    {
    local orig_h = c$id$orig_h;
    if ( orig_h !in state_tracker )
        {
        state_tracker[orig_h] = [
            $client_id = client_id,
            $last_pub_ts = 0.0,
            $last_alert = table(),
            $qos_levels = set(),
            $inter_arrival_buckets = set(),
            $header_keys = set(),
            $header_values = table()
        ];
        }
    else
        {
        state_tracker[orig_h]$client_id = client_id;
        }
    }

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg)
    {
    if ( ! is_orig )
        return;

    local orig_h = c$id$orig_h;
    if ( orig_h !in state_tracker )
        return; # Should be initialized by mqtt_connect, but guard anyway

    local state = state_tracker[orig_h];
    local now = network_time();

    # --- 1. TIMING CHANNEL ANALYSIS ---
    if ( state$last_pub_ts > 0.0 )
        {
        local delta = now - state$last_pub_ts;
        local bucket = "";
        if ( delta >= TIMING_SHORT_MIN && delta <= TIMING_SHORT_MAX )
            bucket = "short";
        else if ( delta >= TIMING_LONG_MIN && delta <= TIMING_LONG_MAX )
            bucket = "long";

        if ( bucket != "" )
            {
            add state$inter_arrival_buckets[bucket];
            if ( |state$inter_arrival_buckets| >= 2 )
                log_c2(c, state, "Covert Timing", "Two Distinct Intervals",
                      fmt("Client is alternating between short (~2s) and long (~5s) publish intervals. Seen: %s", state$inter_arrival_buckets),
                      0.8);
            }
        }
    state$last_pub_ts = now;

    # --- 2. QOS CHANNEL ANALYSIS ---
    # Python script uses 1 and 2 for C2, benign is 0.
    if ( msg$qos == 1 || msg$qos == 2 )
        {
        add state$qos_levels[msg$qos];
        if ( |state$qos_levels| >= 2 )
            log_c2(c, state, "Covert QoS", "QoS Fluctuation",
                  fmt("Client is alternating between QoS 1 and QoS 2. Seen levels: %s", state$qos_levels),
                  0.7);
        }

    # --- 3. HEADER CHANNEL ANALYSIS ---
    if ( msg$properties?$user_properties )
        {
        for ( i in msg$properties$user_properties )
            {
            local p = msg$properties$user_properties[i];
            local key = p$key;
            local val = p$value;

            # Channel 3a: Key Rotation (e.g., trace_id vs span_id)
            add state$header_keys[key];
            if ( |state$header_keys| >= 2 )
                 log_c2(c, state, "Covert Header - Key Rotation", "Key Rotation",
                       fmt("Client is rotating UserProperty keys. Seen keys: %s", state$header_keys),
                       0.9);

            # Channel 3b: Value Fluctuation (e.g., trace_id: "0" vs "1")
            if ( key !in state$header_values )
                state$header_values[key] = set();

            add state$header_values[key][val];
            if ( |state$header_values[key]| >= 2 )
                log_c2(c, state, "Covert Header - Value Fluctuation", "Value Fluctuation",
                      fmt("Client is alternating values for key '%s'. Seen values: %s", key, state$header_values[key]),
                      0.9);
            }
        }
    }

event zeek_done()
    {
    # Optional: print final state for debugging
    # for ( h in state_tracker )
    #     print fmt("Final state for %s: %s", h, state_tracker[h]);
    }

@load base/protocols/conn
@load base/protocols/mqtt/main
@load base/frameworks/logging

module C2_Fuzzy;

export {
    type SignalRecord: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        category: string &log;
        details: string &log;
    };

    redef enum Log::ID += { LOG_C2_FUZZY };
    
    # Tunable Heuristics
    # 0.5s ignores rapid bursts; 1.2 ratio detects significant timing shifts
    const min_inter_arrival: interval = 0.5secs &redef; 
}

type C2State: record {
    last_pub_ts: time;
    observed_qos: set[count];     
    observed_keys: set[string];   
    last_delta: interval;         
};

# MEMORY LEAK FIX: Expire old state after 5 minutes
global state_tracker: table[addr] of C2State &read_expire=5mins;

event zeek_init()
    {
    Log::create_stream(C2_Fuzzy::LOG_C2_FUZZY, [$columns = SignalRecord, $path = "c2_fuzzy"]);
    }

# ---------------------------------------------------------
# 1. TIMING CHANNEL DETECTION
# ---------------------------------------------------------
event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg)
    {
    local orig = c$id$orig_h;
    
    # CRASH FIX: Safe initialization for Zeek 8.0.4
    if ( orig !in state_tracker )
        {
        local new_state: C2State;
        local s_qos: set[count] = set();
        local s_keys: set[string] = set();

        new_state$last_pub_ts = network_time();
        new_state$observed_qos = s_qos;
        new_state$observed_keys = s_keys;
        new_state$last_delta = 0secs;
        state_tracker[orig] = new_state;
        }

    local now = network_time();
    local delta = now - state_tracker[orig]$last_pub_ts;
    state_tracker[orig]$last_pub_ts = now;

    if ( delta > min_inter_arrival )
        {
        local prev = state_tracker[orig]$last_delta;
        
        if ( prev > 0.1secs )
            {
            local ratio = (delta > prev) ? (delta / prev) : (prev / delta);
            
            # LOGIC: If timing jumps by > 20% (e.g. 2s vs 5s is a 150% jump), flag it.
            if ( ratio > 1.2 && ratio < 10.0 )
                {
                Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
                    $ts = network_time(), $uid = c$uid, $id = c$id,
                    $category = "timing-pattern",
                    $details = fmt("Interval switched %.2fs -> %.2fs (Ratio: %.2f)", 
                                   interval_to_double(prev), interval_to_double(delta), ratio)
                ]);
                }
            }
        state_tracker[orig]$last_delta = delta;
        }
    }

# ---------------------------------------------------------
# 2. QoS CHANNEL DETECTION
# ---------------------------------------------------------
event mqtt_puback(c: connection, is_orig: bool, msg_id: count)
    {
    if ( c$id$orig_h in state_tracker )
        {
        add state_tracker[c$id$orig_h]$observed_qos[1];
        if ( |state_tracker[c$id$orig_h]$observed_qos| > 1 )
            Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
                $ts = network_time(), $uid = c$uid, $id = c$id,
                $category = "qos-instability",
                $details = "Device toggling between QoS 1 and 2"
            ]);
        }
    }

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count)
    {
    if ( c$id$orig_h in state_tracker )
        {
        add state_tracker[c$id$orig_h]$observed_qos[2];
        if ( |state_tracker[c$id$orig_h]$observed_qos| > 1 )
            Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
                $ts = network_time(), $uid = c$uid, $id = c$id,
                $category = "qos-instability",
                $details = "Device toggling between QoS 1 and 2"
            ]);
        }
    }

# ---------------------------------------------------------
# 3. METADATA/HEADER CHANNEL DETECTION
# ---------------------------------------------------------
event mqtt_user_property(c: connection, is_orig: bool, msg_id: count, key: string, value: string)
    {
    local orig = c$id$orig_h;

    if ( orig in state_tracker )
        {
        local known_keys = state_tracker[orig]$observed_keys;
        
        if ( key !in known_keys )
            {
            add state_tracker[orig]$observed_keys[key];
            
            # LOGIC: If a device uses multiple different keys (e.g. rotating trace_id/span_id)
            if ( |state_tracker[orig]$observed_keys| >= 2 ) 
                {
                Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
                    $ts = network_time(), $uid = c$uid, $id = c$id,
                    $category = "metadata-churn",
                    $details = fmt("Device rotating keys (seen %d variants). Latest: %s", 
                                   |state_tracker[orig]$observed_keys|, key)
                ]);
                }
            }
        }
    }
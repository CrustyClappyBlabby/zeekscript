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
    
    # DEBUG: Threshold lowered to 1.01 to catch EVERYTHING
    const min_inter_arrival: interval = 0.1secs &redef; 
}

type C2State: record {
    last_pub_ts: time;
    observed_qos: set[count];     
    observed_keys: set[string];   
    last_delta: interval;         
};

global state_tracker: table[addr] of C2State &read_expire=5mins;

event zeek_init()
    {
    Log::create_stream(C2_Fuzzy::LOG_C2_FUZZY, [$columns = SignalRecord, $path = "c2_fuzzy"]);
    
    # FORCE LOG CREATION: Write a test entry immediately
    Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
        $ts = network_time(), $uid = "STARTUP", 
        $id = [$orig_h=0.0.0.0, $orig_p=0/tcp, $resp_h=0.0.0.0, $resp_p=0/tcp],
        $category = "DEBUG",
        $details = "Log initialized. Waiting for traffic..."
    ]);
    print "DEBUG: Script loaded and log file forced.";
    }

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg)
    {
    local orig = c$id$orig_h;
    
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
        print fmt("DEBUG: New Device Tracked: %s", orig);
        }

    local now = network_time();
    local delta = now - state_tracker[orig]$last_pub_ts;
    state_tracker[orig]$last_pub_ts = now;

    if ( delta > min_inter_arrival )
        {
        local prev = state_tracker[orig]$last_delta;
        
        # DEBUG PRINT: See the exact math Zeek is doing
        print fmt("DEBUG: Device %s | Prev=%.2fs | Curr=%.2fs", orig, interval_to_double(prev), interval_to_double(delta));

        if ( prev > 0.1secs )
            {
            local ratio = (delta > prev) ? (delta / prev) : (prev / delta);
            
            # DEBUG: Threshold is 1.01 (Detects almost any jitter)
            if ( ratio > 1.01 ) 
                {
                print fmt("!!! DETECTION TRIGGERED (Ratio: %.2f) !!!", ratio);
                Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
                    $ts = network_time(), $uid = c$uid, $id = c$id,
                    $category = "timing-pattern",
                    $details = fmt("Interval %.2fs -> %.2fs (Ratio: %.2f)", interval_to_double(prev), interval_to_double(delta), ratio)
                ]);
                }
            }
        state_tracker[orig]$last_delta = delta;
        }
    }
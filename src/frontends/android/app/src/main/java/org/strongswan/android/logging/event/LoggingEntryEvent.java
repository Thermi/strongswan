package org.strongswan.android.logging.event;

/**
 * Created by mariusz.rafalski on 2017-03-22.
 */
import static org.strongswan.android.logging.SimpleLogEventSaver.LogEventType;

public class LoggingEntryEvent {

    private LogEventType event;

    public LoggingEntryEvent(LogEventType event) {
        this.event = event;
    }

    public LogEventType getLogEventType() {
        return event;
    }
}

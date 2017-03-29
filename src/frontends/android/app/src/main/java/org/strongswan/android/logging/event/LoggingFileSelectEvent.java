package org.strongswan.android.logging.event;

/**
 * Created by mariusz.rafalski on 2017-03-23.
 */

public class LoggingFileSelectEvent {
    int loggingLevel;

    public LoggingFileSelectEvent(int loggingLevel) {
        this.loggingLevel = loggingLevel;
    }

    public int getLoggingLevel() {
        return loggingLevel;
    }
}

package org.strongswan.android.logging;


/**
 * Created by mariuszrafalski on 10.03.17.
 */

public class LoggingLevelManager {
    public static final int STRONGSWAN_MINIMAL_LOGGING_LEVEL = 1;


    public int getStrongSwanLoggingLevel(int loggingLevel){
        return loggingLevel < STRONGSWAN_MINIMAL_LOGGING_LEVEL ? STRONGSWAN_MINIMAL_LOGGING_LEVEL : loggingLevel;
    }

}

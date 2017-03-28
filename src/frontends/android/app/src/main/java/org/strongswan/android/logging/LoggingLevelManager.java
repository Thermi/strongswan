package org.strongswan.android.logging;

import android.content.Context;
import android.widget.Toast;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;

/**
 * Created by mariuszrafalski on 10.03.17.
 */

public class LoggingLevelManager {
    public static final int STRONGSWAN_MINIMAL_LOGGING_LEVEL = 1;
    private Context context;

    public LoggingLevelManager(Context context) {
        this.context = context;
    }



    public int getStrongSwanLoggingLevel(int loggingLevel){
        return loggingLevel < STRONGSWAN_MINIMAL_LOGGING_LEVEL ? STRONGSWAN_MINIMAL_LOGGING_LEVEL : loggingLevel;
    }

}

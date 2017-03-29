package org.strongswan.android.logging;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import org.greenrobot.eventbus.Subscribe;
import org.strongswan.android.logging.event.LoggingFileSelectEvent;
import org.strongswan.android.logic.CharonVpnService;

/**
 * Created by mariusz.rafalski on 2017-03-23.
 */

public class LogFileController {
    private static final String LOGGING_FILE_NAME_KEY = "logging_file";
    private Context context;


    public LogFileController(Context context) {
        this.context = context;
    }

    public String getActiveLoggingFile(){
        return PreferenceManager.getDefaultSharedPreferences(context).getString(LOGGING_FILE_NAME_KEY, CharonVpnService.SIMPLE_LOG_FILE);
    }

    @Subscribe
    public void setLoggingFile(LoggingFileSelectEvent event){
        SharedPreferences.Editor editor = PreferenceManager.getDefaultSharedPreferences(context).edit();
        if(event.getLoggingLevel() > -1){
            editor.putString(LOGGING_FILE_NAME_KEY, CharonVpnService.LOG_FILE);
        }else{
            editor.putString(LOGGING_FILE_NAME_KEY, CharonVpnService.SIMPLE_LOG_FILE);
        }
        editor.apply();
    }

    public boolean isSimpleLoggingActive(){
        return CharonVpnService.SIMPLE_LOG_FILE.equals(getActiveLoggingFile());
    }

}

package org.strongswan.android.logging;

import android.content.Context;

import org.greenrobot.eventbus.Subscribe;
import org.strongswan.android.R;
import org.strongswan.android.logging.event.LoggingEntryEvent;
import org.strongswan.android.logic.CharonVpnService;

import java.io.FileOutputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by mariusz.rafalski on 2017-03-22.
 */

public class SimpleLogEventSaver {
    public enum LogEventType {
        CONNECTED,
        DISCONNECTED,
        NO_INTERNET_ACCESS,
        AUTHORIZATION_FAILED
    }

    private Context context;
    private boolean isSimpleLoggingLevelActive;

    public SimpleLogEventSaver(Context context) {
        this.context = context;
    }

    @Subscribe
    public void saveEventToLogFile(LoggingEntryEvent event){
        refreshLoggingLevel();
        if(!isSimpleLoggingLevelActive){
            return;
        }
        FileOutputStream outputStream = null;
        try {
            outputStream = context.openFileOutput(CharonVpnService.SIMPLE_LOG_FILE,Context.MODE_APPEND);
            String logEntry = convertToLogFormat(event.getLogEventType());
            outputStream.write(logEntry.getBytes());
        } catch (Exception e) {

        }finally {
            closeFileOutputStream(outputStream);
        }
    }

    private void closeFileOutputStream(FileOutputStream outputStream){
        if(outputStream != null) {
            try {
                outputStream.close();
            } catch (IOException e) {

            }
        }
    }

    private String convertToLogFormat(LogEventType logEventType) {
        String entry;
        switch (logEventType){
            case CONNECTED:
                entry = context.getString(R.string.simple_log_connected);
                break;
            case DISCONNECTED:
                entry = context.getString(R.string.simple_log_disconnected);
                break;
            case AUTHORIZATION_FAILED:
                entry = context.getString(R.string.simple_log_auth_failed);
                break;
            case NO_INTERNET_ACCESS:
                entry = context.getString(R.string.simple_log_no_network_access);
                break;
            default:
                entry = "";
                break;
        }
        return getDate()+" " + entry + "\n";
    }

    private String getDate() {
        DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
        Date now = Calendar.getInstance().getTime();
        return df.format(now);
    }

    public void refreshLoggingLevel(){
        isSimpleLoggingLevelActive = new LogFileController(context).isSimpleLoggingActive();
    }
}

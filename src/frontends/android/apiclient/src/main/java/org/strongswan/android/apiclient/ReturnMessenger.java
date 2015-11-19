/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import com.fancyfon.strongswan.apiclient.R;
import com.google.inject.Inject;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
public class ReturnMessenger {
    private static final String TAG = ReturnMessenger.class.getSimpleName();
    private static final int SUCCESS = 0;

    @Inject
    Context context;
    @Inject
    Logger logger;

    public Messenger getReturnMessenger() {
        return returnMessenger;
    }

    private Messenger returnMessenger = new Messenger(new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if (msg.what == getInteger(R.integer.vpn_profile_create_message)) {
                if (msg.arg2 == SUCCESS) {
                    logger.logAndToast(TAG, "Vpn created successfully.");
                } else {
                    logger.logAndToast(TAG, "Vpn create failed.");
                }
            } else if (msg.what == getInteger(R.integer.vpn_profile_read_message)) {
                // not used for now
            } else if (msg.what == getInteger(R.integer.vpn_profile_read_all_message)) {
                Bundle data = msg.getData();
                long[] ids = data.getLongArray(context.getString(R.string.vpn_profile_bundle_ids_key));
                if (ids.length == 0) {
                    logger.logAndToast(TAG, "No vpn profiles");
                    return;
                }
                logVpnProfiles(data, ids);
            } else if (msg.what == getInteger(R.integer.vpn_profile_update_message)) {
                logger.logAndToast(TAG, "Vpn updated successfully.");
            } else if (msg.what == getInteger(R.integer.vpn_profile_delete_message)) {
                logger.logAndToast(TAG, "Vpn deleted successfully.");
            } else if (msg.what == getInteger(R.integer.vpn_profile_delete_all_message)) {
                logger.logAndToast(TAG, "was any vpn profiles deleted via messenger? " + (msg.arg2 == 0));
            } else {
                logger.logAndToast(TAG,"Unknown message: " + msg);
                super.handleMessage(msg);
            }
        }
    });

    private void logVpnProfiles(Bundle data, long[] ids) {
        for (long id : ids) {
            Bundle bundle = data.getBundle(context.getString(R.string.vpn_profile_bundle_id_params_key, id));
            logger.logAndToastVpnProfileBundle(TAG, bundle);
        }
    }

    private int getInteger(int id) {
        return context.getResources().getInteger(id);
    }
}
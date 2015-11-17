/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Message;
import android.os.RemoteException;
import android.view.View;
import android.widget.Button;
import android.widget.CheckedTextView;
import android.widget.EditText;
import com.google.inject.Inject;
import roboguice.activity.RoboActivity;
import roboguice.inject.ContentView;
import roboguice.inject.InjectView;

import java.util.ArrayList;
import java.util.Random;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
@ContentView(R.layout.api_client_create_vpn_profile)
public class CreateVpnProfileView extends RoboActivity {

    private static final String TAG = CreateVpnProfileView.class.getSimpleName();

    @Inject
    Random random;
    @Inject
    Resources resources;
    @Inject
    Logger logger;
    @Inject
    VpnServiceConnector vpnServiceConnector;
    @Inject
    CertificateReader certificateReader;
    @Inject
    ReturnMessenger returnMessenger;
    @InjectView(R.id.vpn_name_edit_text)
    EditText vpnNameEditText;
    @InjectView(R.id.vpn_gateway_edit_text)
    EditText vpnGatewayEditText;
    @InjectView(R.id.vpn_username_edit_text)
    EditText vpnUsernameEditText;
    @InjectView(R.id.vpn_password_edit_text)
    EditText vpnPasswordEditText;
    @InjectView(R.id.vpn_user_certificate_password_edit_text)
    EditText vpnUserCertificatePasswordEditText;
    @InjectView(R.id.package_name_edit_text)
    EditText vpnPackageNameEditText;
    @InjectView(R.id.user_certificate)
    CheckedTextView vpnUserCertificateCheckedTextView;
    @InjectView(R.id.ca_certificate)
    CheckedTextView vpnCaCertificateCheckedTextView;
    @InjectView(R.id.vpn_type)
    Button vpnTypeButton;

    private String vpnType;

    @Override
    protected void onResume() {
        super.onResume();
        vpnServiceConnector.connect();
    }

    @Override
    protected void onStop() {
        super.onStop();
        vpnServiceConnector.disconnect();
    }

    public void checkUserCertificateClick(View view) {
        vpnUserCertificateCheckedTextView.setChecked(!vpnUserCertificateCheckedTextView.isChecked());
        vpnUserCertificatePasswordEditText.setEnabled(vpnUserCertificateCheckedTextView.isChecked());
    }

    public void checkCaCertificateClick(View view) {
        vpnCaCertificateCheckedTextView.setChecked(!vpnCaCertificateCheckedTextView.isChecked());
    }

    public void selectVpnTypeClick(View view) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Choose vpn type")
                .setItems(R.array.array_vpn_type, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        vpnType = resources.getStringArray(R.array.array_vpn_type)[which];
                        vpnTypeButton.setText(vpnType);
                    }
                });
        AlertDialog dialog =  builder.create();
        dialog.show();
    }

    public void clickCreateVpnProfile(View view) {
        Bundle vpnProfile = new Bundle();
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_name_key), vpnNameEditText.getText().toString());
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), vpnGatewayEditText.getText
                ().toString());
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_type_key), vpnType);
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_password_key),
                vpnUserCertificatePasswordEditText.getText().toString());
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_username_key), vpnUsernameEditText
                .getText().toString());
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_password_key), vpnPasswordEditText
                .getText().toString());
        if(vpnCaCertificateCheckedTextView.isChecked()) {
            vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_certificate_key),
                    certificateReader.getCaCertificate
                            ());
        }
        if(vpnUserCertificateCheckedTextView.isChecked()) {
            vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_key),
                    certificateReader.getUserCertificate());
        }

        ArrayList<String> packages = new ArrayList<String>();
        packages.add(vpnPackageNameEditText.getText().toString());
        vpnProfile.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications), packages);
        try {
            Message message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_create_message), random.nextInt(), 0);
            message.setData(vpnProfile);
            message.replyTo = returnMessenger.getReturnMessenger();
            try {
                vpnServiceConnector.getMessenger().send(message);
            } catch (RemoteException e) {
                logger.logAndToast(TAG, "failed to add eap vpn profile via service", e);
            }
        } catch (Exception e) {
            logger.logAndToast(TAG, "failed to add eap vpn profile via service", e);
        }
    }
}
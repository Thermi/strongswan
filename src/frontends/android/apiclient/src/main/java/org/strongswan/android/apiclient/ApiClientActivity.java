package org.strongswan.android.apiclient;

import android.content.Intent;
import android.content.res.Resources;
import android.os.*;
import android.view.View;
import android.widget.EditText;
import android.widget.RadioButton;
import com.google.inject.Inject;
import roboguice.activity.RoboActivity;
import roboguice.inject.ContentView;
import roboguice.inject.InjectView;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@ContentView(R.layout.api_client_activity)
public class ApiClientActivity extends RoboActivity {
    public static final String TAG = "strongSwanApiClient";
    public static final int SERVICE_IPC_TYPE = 0;
    public static final int MESSENGER_IPC_TYPE = 1;

    @Inject
    Resources resources;
    @Inject
    Random random;
    @Inject
    Logger logger;
    @Inject
    VpnServiceConnector vpnServiceConnector;
    @Inject
    CertificateReader certificateReader;
    @Inject
    ReturnMessenger returnMessenger;
    @InjectView(R.id.messenger_radio_button)
    RadioButton messengerRadioButton;
    @InjectView(R.id.service_radio_button)
    RadioButton serviceRadioButton;
    @InjectView(R.id.package_name_edit_text)
    EditText packageNameEditText;
    @InjectView(R.id.profile_id_edit_text)
    EditText vpnProfileIdEditText;

    private  ArrayList<String>allowedApps;
    private int ipcType;

    @Override
    protected void onDestroy() {
        super.onDestroy();
        vpnServiceConnector.disconnect();
    }

    public void clickReadVpnProfiles(View view) {
        if (ipcType == MESSENGER_IPC_TYPE) {
            if (vpnServiceConnector.getMessenger() != null) {
                Message message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_read_all_message), random.nextInt(), 0);
                message.replyTo = returnMessenger.getReturnMessenger();
                try {
                    vpnServiceConnector.getMessenger().send(message);
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to get vpn profiles via messenger", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to messenger");
            }
        } else {
            if (vpnServiceConnector.getService() != null) {
                try {
                    List<Bundle> vpnProfiles = vpnServiceConnector.getService().readVpnProfiles();
                    for (Bundle bundle : vpnProfiles) {
                        logger.logAndToastVpnProfileBundle(TAG, bundle);
                    }
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to get vpn profiles via service", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to service");
            }
        }
    }

    public void clickDisconnectFromStrongSwan(View view) {
        vpnServiceConnector.disconnect();
    }

    public void clickConnectToStrongSwan(View view) {
        boolean result = vpnServiceConnector.connectToService();
        logger.logAndToast(TAG, "bind successful to service? " + result);
        result = vpnServiceConnector.connectToMessengerService();
        logger.logAndToast(TAG, "bind successful to messenger service? " + result);
    }

    public void clickCreateVpnProfile(View view) {
        allowedApps = new ArrayList<String>();
        allowedApps.add( packageNameEditText.getText().toString());
        Bundle eapBundle = getEapBundle();
        Bundle certBundle = getCertBundle();
        if (ipcType == MESSENGER_IPC_TYPE) {
            if (vpnServiceConnector.getMessenger() != null) {
                Message message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_create_message), random.nextInt(), 0);
                message.setData(eapBundle);
                message.replyTo = returnMessenger.getReturnMessenger();
                try {
                    vpnServiceConnector.getMessenger().send(message);
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to add eap vpn profile via service", e);
                }
                message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_create_message), random.nextInt(), 0);
                message.setData(certBundle);
                message.replyTo = returnMessenger.getReturnMessenger();
                try {
                    vpnServiceConnector.getMessenger().send(message);
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to add cert vpn profile via service", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to messenger");
            }
        } else {
            if (vpnServiceConnector.getService() != null) {
                try {
                    boolean result = vpnServiceConnector.getService().createVpnProfile(eapBundle);
                    logger.logAndToast(TAG, "was eap vpn profile added? " + result);
                } catch (Exception e) {
                    logger.logAndToast(TAG, "failed to add eap vpn profile via service", e);
                }
                try {
                    boolean result = vpnServiceConnector.getService().createVpnProfile(certBundle);
                    logger.logAndToast(TAG, "was cert vpn profile added? " + result);
                } catch (Exception e) {
                    logger.logAndToast(TAG, "failed to add cert vpn profile via service", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to service");
            }
        }
    }

    private Bundle getEapBundle() {
        Bundle vpnProfile = new Bundle();
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_name_key), "eap famocvpn");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), "famocvpn.emdmcloud.com");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_username_key), "john");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_password_key), "haslo123");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_type_key), resources.getString(R.string.vpn_profile_bundle_type_ikev2_eap_value));
        vpnProfile.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications), allowedApps);
        return vpnProfile;
    }

    private Bundle getCertBundle() {
        Bundle vpnProfile = new Bundle();
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_name_key), "cert famocvpn");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), "famocvpn.emdmcloud.com");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_type_key), resources.getString(R.string.vpn_profile_bundle_type_ikev2_cert_value));
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_password_key),
                "PASS");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_certificate_key), certificateReader
                .getCaCertificate() );
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_key), certificateReader.
                getUserCertificate());

        vpnProfile.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications),allowedApps );
        return vpnProfile;
    }

    private int getInteger(int id) {
        return getResources().getInteger(id);
    }

    public void clickCreateVpnProfileActivity(View view) {
        startActivity(new Intent(this, CreateVpnProfileView.class));
    }

    public void clickService(View view) {
        ipcType = SERVICE_IPC_TYPE;
        serviceRadioButton.setChecked(true);
        messengerRadioButton.setChecked(false);
    }

    public void clickMessenger(View view) {
        ipcType = MESSENGER_IPC_TYPE;
        serviceRadioButton.setChecked(false);
        messengerRadioButton.setChecked(true);
    }

    public void clickDeleteVpnProfiles(View view) {
        if (ipcType == MESSENGER_IPC_TYPE) {
            if (vpnServiceConnector.getMessenger() != null) {
                Message message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_delete_all_message), random.nextInt(), 0);
                message.replyTo = returnMessenger.getReturnMessenger();
                try {
                    vpnServiceConnector.getMessenger().send(message);
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to delete vpn profiles via messenger", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to messenger");
            }
        } else {
            try {
                boolean result = vpnServiceConnector.getService().deleteVpnProfiles();
                logger.logAndToast(TAG, "was any vpn profiles deleted? " + result);
            } catch (RemoteException e) {
                logger.logAndToast(TAG, "failed to delete vpn profiles via service", e);
            }
        }

    }

    public void clickDeleteVpnProfile(View view) {
        if (ipcType == MESSENGER_IPC_TYPE) {
            if (vpnServiceConnector.getMessenger() != null) {
                Message message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_delete_message), Integer.parseInt(vpnProfileIdEditText.getText().toString()), 0);
                message.replyTo = returnMessenger.getReturnMessenger();
                try {
                    vpnServiceConnector.getMessenger().send(message);
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to delete vpn profiles via messenger", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to messenger");
            }
        } else {
            try {
                boolean result = vpnServiceConnector.getService().deleteVpnProfile(Long.parseLong(vpnProfileIdEditText.getText().toString()));
                logger.logAndToast(TAG, "was any vpn profiles deleted? " + result);
            } catch (RemoteException e) {
                logger.logAndToast(TAG, "failed to delete vpn profiles via service", e);
            }
        }

    }
}


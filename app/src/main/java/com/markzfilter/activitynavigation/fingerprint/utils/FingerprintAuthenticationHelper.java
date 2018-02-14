package com.markzfilter.activitynavigation.fingerprint.utils;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.view.View;
import android.widget.TextView;

import com.markzfilter.activitynavigation.R;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static android.content.Context.KEYGUARD_SERVICE;

public class FingerprintAuthenticationHelper {
    private Cipher cipher;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private String KEY_NAME;

    public FingerprintAuthenticationHelper(String KEY_NAME) {
        this.KEY_NAME = KEY_NAME;
    }

    public void completeFingerprintAuthentication(Activity activity, TextView feedbackTextView) {
        // If you’ve set your app’s minSdkVersion to anything lower than 23, then you’ll need
        // to verify that the device is running Marshmallow
        // or higher before executing any fingerprint-related code
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            //Get an instance of KeyguardManager and FingerprintManager
            KeyguardManager keyguardManager = (KeyguardManager) activity.getSystemService(KEYGUARD_SERVICE);
            FingerprintManager fingerprintManager = (FingerprintManager) activity.getSystemService(android.content.Context.FINGERPRINT_SERVICE);

            // Check whether the device has a fingerprint sensor
            if (fingerprintManager != null && !fingerprintManager.isHardwareDetected()) {
                // If a fingerprint sensor isn’t available, then inform the user that they’ll be unable to use your app’s fingerprint functionality
                feedbackTextView.setVisibility(View.VISIBLE);
                feedbackTextView.setText(R.string.fingerprint_device_does_not_support);
            }
            // Check whether the user has granted your app the USE_FINGERPRINT permission
            if (ActivityCompat.checkSelfPermission(activity, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                // If your app doesn't have this permission, then display the following text
                feedbackTextView.setVisibility(View.VISIBLE);
                feedbackTextView.setText(R.string.fingerprint_please_enable_permission);
            }

            // Check that the user has registered at least one fingerprint
            if (fingerprintManager != null && !fingerprintManager.hasEnrolledFingerprints()) {
                // If the user has not configured any fingerprints, then display the following message
                feedbackTextView.setVisibility(View.VISIBLE);
                feedbackTextView.setText(R.string.fingerprint_no_fingerprint_configured);
            }

            // Verifies lock screen is secured with a Pass Code
            if (keyguardManager != null) {
                if (!keyguardManager.isKeyguardSecure()) {
                    // If the lock screen has not been secured, then give feedback to the user
                    feedbackTextView.setVisibility(View.VISIBLE);
                    feedbackTextView.setText(R.string.fingerprint_please_enable_lock_screen);
                } else {
                    try {
                        generateKey();
                    } catch (FingerprintException e) {
                        e.printStackTrace();
                    }
                    if (initCipher()) {
                        // If the cipher is initialized successfully, then create a CryptoObject instance
                        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

                        // Here, I’m referencing the FingerprintHandler class that we’ll create in the next section. This class will be responsible
                        // for starting the authentication process (via the startAuth method) and processing the authentication process events
                        FingerprintHandler helper = new FingerprintHandler(activity);
                        helper.startAuth(fingerprintManager, cryptoObject);
                    }
                }
            }
        }
    }

    // Create the generateKey method that we’ll use to gain access to the Android keystore and generate the encryption key

    private void generateKey() throws FingerprintException {
        try {
            // Obtain a reference to the Keystore using the standard Android keystore container identifier (“AndroidKeystore”)
            keyStore = KeyStore.getInstance("AndroidKeyStore");

            // Generate the key
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            }

            // Initialize an empty KeyStore
            keyStore.load(null);

            // Initialize the KeyGenerator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator.init(new
                        // Specify the operation(s) this key can be used for
                        KeyGenParameterSpec.Builder(KEY_NAME,
                        KeyProperties.PURPOSE_ENCRYPT |
                                KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)

                        // Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it
                        .setUserAuthenticationRequired(true)
                        .setEncryptionPaddings(
                                KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .build());
            }

            // Generate the key
            keyGenerator.generateKey();

        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                | CertificateException
                | IOException exc) {
            exc.printStackTrace();
            throw new FingerprintException(exc);
        }
    }

    // Create a new method that we’ll use to initialize our cipher
    @TargetApi(Build.VERSION_CODES.M)
    private boolean initCipher() {
        try {
            // Obtain a cipher instance and configure it with the properties required for fingerprint authentication
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // Return true if the cipher has been initialized successfully
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {

            // Return false if cipher initialization failed
            return false;
        } catch (KeyStoreException | CertificateException
                | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    private class FingerprintException extends Exception {
        FingerprintException(Exception e) {
            super(e);
        }
    }
}

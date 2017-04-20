package edu.temple.nfctransfer;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.CreateNdefMessageCallback;
import android.nfc.NfcEvent;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends Activity implements CreateNdefMessageCallback, View.OnClickListener {
    EditText displayEt;
    Button generateKeyBtn, editMessageBtn, clearBtn;
    RadioGroup radioGroup;
    RadioButton key_rb, msg_rb;

    IntentFilter[] intentFiltersArray;
    PendingIntent pendingIntent;
    NfcAdapter mNfcAdapter;

    KeyFactory keyFactory;
    KeyPairGenerator keyGen;
    KeyPair key;
    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;
    PrivateKey privateKeyTemplate;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        displayEt = (EditText) findViewById(R.id.display_et);
        generateKeyBtn = (Button) findViewById(R.id.generate_key_btn);
        editMessageBtn = (Button) findViewById(R.id.edit_message_btn);
        clearBtn = (Button) findViewById(R.id.clear_btn);
        radioGroup = (RadioGroup) findViewById(R.id.selection_rg);
        key_rb = (RadioButton) findViewById(R.id.key_rb);
        msg_rb = (RadioButton) findViewById(R.id.msg_rb);

        generateKeyBtn.setOnClickListener(this);
        editMessageBtn.setOnClickListener(this);
        clearBtn.setOnClickListener(this);

        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        /**NFC**/
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        if (mNfcAdapter != null)
            mNfcAdapter.setNdefPushMessageCallback(this, this); // Use setBeamPushUris for large files

        pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        IntentFilter ndefFilter = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        try {
            ndefFilter.addDataType("*/*");    /* Handles all MIME based dispatches.
	                                       You should specify only the ones that you need. */
        }
        catch (MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }

        intentFiltersArray = new IntentFilter[] {ndefFilter};
    }


    @Override
    public NdefMessage createNdefMessage(NfcEvent event) {
        NdefMessage msg;
        if(key_rb.isChecked() == true) {
            msg = new NdefMessage(
                    new NdefRecord[]{NdefRecord.createMime(
                            "application/edu.temple.nfctransfer", privateKeyTemplate.getEncoded())

                    });
        }
        else if (msg_rb.isChecked() == true){
            msg = new NdefMessage(
                    new NdefRecord[]{NdefRecord.createMime(
                            "application/edu.temple.nfctransfer", ("message:" + displayEt.getText().toString()).getBytes())

                    });
        }
        else{
            msg = null;
        }

        displayEt.setEnabled(false);
//      displayEt.setText("");
        return msg;
    }


    @Override
    public void onResume(){
        super.onResume();
        if (NfcAdapter.getDefaultAdapter(this) != null) {
            NfcAdapter.getDefaultAdapter(this).enableForegroundDispatch(this, pendingIntent, intentFiltersArray, null);
            // Check to see that the Activity started due to an Android Beam
            if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
                processBeam(getIntent());
            }
        }
    }

    public void onNewIntent(Intent intent) {
        processBeam(intent);
    }

    /**
     * Parses the NDEF Message from the intent and displayes it on the EditText
     */
    void processBeam(Intent intent) {
        Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
                NfcAdapter.EXTRA_NDEF_MESSAGES);
        // only one message sent during the beam
        if (rawMsgs != null){
            NdefMessage msg = (NdefMessage) rawMsgs[0];
            // record 0 contains the MIME type, record 1 is the AAR, if present
            String messageString = new String(msg.getRecords()[0].getPayload());
            //byte [] plaintext = null;
            String plaintextStr;
            String displayMessage;

            if (messageString.substring(0,8).equals("message:") && privateKey != null){
                //decrypt the message
/*                try {
                    cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    plaintext = cipher.doFinal(messageString.substring(8, messageString.length()).getBytes());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }*/

                plaintextStr = decrypt(messageString.substring(8, messageString.length()));
                //displayMessage = new String(plaintext);
                //displayMessage = messageString;
                displayMessage = plaintextStr;
            }

            else{
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(msg.getRecords()[0].getPayload());
                KeyFactory keyFactory;
                try {
                    keyFactory = KeyFactory.getInstance("RSA");
                    privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
                //displayMessage = String.valueOf(privateKey);
                displayMessage = messageString;
            }

            displayEt.setText(displayMessage);
        }

    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.generate_key_btn:
                displayEt.setEnabled(false);
                editMessageBtn.setText("Edit Message");
                try {
                    keyGen = KeyPairGenerator.getInstance("RSA");
                    keyGen.initialize(1024);
                    key = keyGen.genKeyPair();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key.getPublic().getEncoded());
                try {
                    publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
                //privateKey = key.getPrivate();
                //String privateKeyStr = String.valueOf(privateKey);
                privateKeyTemplate = key.getPrivate();
                displayEt.setText(String.valueOf(privateKeyTemplate));

                break;
            case R.id.edit_message_btn:
                if(displayEt.isEnabled() == false) {
                    displayEt.setEnabled(true);
                    displayEt.setText("");
                    editMessageBtn.setText("Confirm");;
                }
                else{
                    //encrypt message
                    String plaintextStr = displayEt.getText().toString();
                    String ciphertextStr = encrypt(plaintextStr);
/*                    try {
                        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                        ciphertext = cipher.doFinal(plaintextStr.getBytes());
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }*/

                    //displayEt.setText("message:" + new String(ciphertext));
                    displayEt.setText(ciphertextStr);
                    displayEt.setEnabled(false);
                    editMessageBtn.setText("Edit Message");
                }
                break;
            case R.id.clear_btn:
                displayEt.setText("");
        }
    }

    protected String decrypt(String input){
        String finalText = null;
        if (privateKey!=null){
            Cipher output = null;
            try {
                output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                output.init(Cipher.DECRYPT_MODE, privateKey);
//            CipherInputStream cipherInputStream = new CipherInputStream(
//                    new ByteArrayInputStream(Base64.decode(message.toString(), Base64.DEFAULT)), output);
                CipherInputStream cipherInputStream = new CipherInputStream(
                        new ByteArrayInputStream(Base64.decode(input.getBytes(), Base64.DEFAULT)), output);
                ArrayList<Byte> values = new ArrayList<>();
                int nextByte;
                while ((nextByte = cipherInputStream.read()) != -1) {
                    values.add((byte) nextByte);
                }

                byte[] bytes = new byte[values.size()];
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = values.get(i).byteValue();
                }

                finalText = new String(bytes, 0, bytes.length, "UTF-8");
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            } catch (NoSuchPaddingException e1) {
                e1.printStackTrace();
            } catch (InvalidKeyException e1) {
                e1.printStackTrace();
            } catch (UnsupportedEncodingException e1) {
                e1.printStackTrace();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

        }
        else{
            Toast.makeText(this,"no valid key",Toast.LENGTH_LONG).show();
        }
        return finalText;
    }

    //public byte[] encrypt(String input) {
    public String encrypt(String input) {
        String finalText = null;
        byte[] vals = new byte[0];

        try {
            Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);
            cipherOutputStream.write(input.getBytes("UTF-8"));
            cipherOutputStream.close();

            vals = outputStream.toByteArray();

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte [] finalBytes = Base64.encode(vals,Base64.DEFAULT);
        finalText = new String(finalBytes);
        //return Base64.encode(vals,Base64.DEFAULT);
        return finalText;
    }
}

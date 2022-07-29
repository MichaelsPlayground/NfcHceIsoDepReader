package de.androidcrypto.nfchceisodepreader;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.nfc.tech.Ndef;
import android.nfc.tech.NfcA;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    //private static final BerTagFactory LOG = "BER";
    TextView dumpField, readResult;
    private NfcAdapter mNfcAdapter;
    String dumpExportString = "";
    String tagIdString = "";
    String tagTypeString = "";
    private static final int REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE = 100;
    Context contextSave;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);
        contextSave = getApplicationContext();

        dumpField = findViewById(R.id.tvMainDump1);
        readResult = findViewById(R.id.tvMainReadResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");
        runOnUiThread(() -> {
            readResult.setText("");
        });

        IsoDep isoDep = null;
        writeToUiAppend(readResult, "Tag found");
        String[] techList = tag.getTechList();
        for (int i = 0; i < techList.length; i++) {
            writeToUiAppend(readResult, "TechList: " + techList[i]);
        }
        String tagId = bytesToHex(tag.getId());
        writeToUiAppend(readResult, "TagId: " + tagId);

        try {
            isoDep = IsoDep.get(tag);

            if (isoDep != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is IsoDep compatible",
                            Toast.LENGTH_SHORT).show();
                });

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                isoDep.connect();
                dumpExportString = "";
                runOnUiThread(() -> {
                    //readResult.setText("");
                });


                writeToUiAppend(readResult, "IsoDep reading");
                String nfcaContent = "IsoDep reading" + "\n";

                // now we run the select command with AID
                String nfcHecNdef2Aid = "F0394148148100";
                String nfcHecNdef1Aid = "F0010203040506";
                String nfcHecNdefSpec = "D2760000850101";

                //byte[] aid = Utils.hexStringToByteArray(nfcHecNdefSpec);
                byte[] aid = Utils.hexStringToByteArray(nfcHecNdef2Aid);
                //byte[] aid = Utils.hexStringToByteArray(nfcHecNdef1Aid);

                byte[] command = selectApdu(aid);
                byte[] responseSelect = isoDep.transceive(command);
                writeToUiAppend(readResult, "selectApdu with AID: " + bytesToHex(command));
                writeToUiAppend(readResult, "selectApdu response: " + bytesToHex(responseSelect));

                if (responseSelect == null) {
                    writeToUiAppend(readResult, "selectApdu with AID fails (null)");
                } else {
                    writeToUiAppend(readResult, "responseSelect length: " + responseSelect.length + " data: " + bytesToHex(responseSelect));
                    System.out.println("responseSelect: " + bytesToHex(responseSelect));
                }

                // todo check for 90 00 at the end to proceed

                // sending cc select = get the capability container
                String selectCapabilityContainer = "00a4000c02e103";
                command = Utils.hexStringToByteArray(selectCapabilityContainer);
                byte[] responseSelectCc = isoDep.transceive(command);
                writeToUiAppend(readResult, "select CC: " + bytesToHex(command));
                writeToUiAppend(readResult, "select CC response: " + bytesToHex(responseSelectCc));
                writeToUiAppend(readResult, "responseSelect length: " + responseSelectCc.length + " data: " + bytesToHex(responseSelectCc));
                System.out.println("responseSelectCc: " + bytesToHex(responseSelectCc));

                // todo check for 90 00 at the end to proceed

                // Sending ReadBinary from CC...
                String sendBinareFromCc = "00b000000f";
                command = Utils.hexStringToByteArray(sendBinareFromCc);
                byte[] responseSendBinaryFromCc = isoDep.transceive(command);
                writeToUiAppend(readResult, "sendBinaryFromCc: " + bytesToHex(command));
                writeToUiAppend(readResult, "sendBinaryFromCc response: " + bytesToHex(responseSendBinaryFromCc));
                writeToUiAppend(readResult, "sendBinaryFromCc response length: " + responseSendBinaryFromCc.length + " data: " + bytesToHex(responseSendBinaryFromCc));
                System.out.println("sendBinaryFromCc response: " + bytesToHex(responseSendBinaryFromCc));

                // todo check for 90 00 at the end to proceed

                // Capability Container header:
                byte[] capabilityContainerHeader = Arrays.copyOfRange(responseSendBinaryFromCc, 0, responseSendBinaryFromCc.length - 2);
                writeToUiAppend(readResult, "capabilityContainerHeader length: " + capabilityContainerHeader.length + " data: " + bytesToHex(capabilityContainerHeader));
                System.out.println("capabilityContainerHeader: " + bytesToHex(capabilityContainerHeader));
                System.out.println("capabilityContainerHeader: " + new String(capabilityContainerHeader));

                // todo check for 90 00 at the end to proceed

                // Sending NDEF Select...
                String sendNdefSelect = "00a4000c02e104";
                command = Utils.hexStringToByteArray(sendNdefSelect);
                byte[] responseSendNdefSelect = isoDep.transceive(command);
                writeToUiAppend(readResult, "sendNdefSelect: " + bytesToHex(command));
                writeToUiAppend(readResult, "sendNdefSelect response: " + bytesToHex(responseSendNdefSelect));
                writeToUiAppend(readResult, "sendNdefSelect response length: " + responseSendNdefSelect.length + " data: " + bytesToHex(responseSendNdefSelect));
                System.out.println("sendNdefSelect response: " + bytesToHex(responseSendNdefSelect));

                // todo check for 90 00 at the end to proceed

                // Sending ReadBinary NLEN...
                String sendReadBinaryNlen = "00b0000002";
                command = Utils.hexStringToByteArray(sendReadBinaryNlen);
                byte[] responseSendBinaryNlen = isoDep.transceive(command);
                writeToUiAppend(readResult, "sendBinaryNlen: " + bytesToHex(command));
                writeToUiAppend(readResult, "sendBinaryNlen response: " + bytesToHex(responseSendBinaryNlen));
                writeToUiAppend(readResult, "sendBinaryNlen response length: " + responseSendBinaryNlen.length + " data: " + bytesToHex(responseSendBinaryNlen));
                System.out.println("sendBinaryNlen response: " + bytesToHex(responseSendBinaryNlen));

                // todo check for 90 00 at the end to proceed

                // Sending ReadBinary, get NDEF data...
                String sendReadBinaryNdefData = "00b000000f";
                command = Utils.hexStringToByteArray(sendReadBinaryNdefData);
                byte[] responseSendBinaryNdefData = isoDep.transceive(command);
                writeToUiAppend(readResult, "sendBinaryNdefData: " + bytesToHex(command));
                writeToUiAppend(readResult, "sendBinaryNdefData response: " + bytesToHex(responseSendBinaryNdefData));
                writeToUiAppend(readResult, "sendBinaryNdefData response length: " + responseSendBinaryNdefData.length + " data: " + bytesToHex(responseSendBinaryNdefData));
                writeToUiAppend(readResult, "sendBinaryNdefData response: " + new String(responseSendBinaryNdefData));
                System.out.println("sendBinaryNdefData response: " + bytesToHex(responseSendBinaryNdefData));
                System.out.println("sendBinaryNdefData response: " + new String(responseSendBinaryNdefData));

                byte[] ndefMessage = Arrays.copyOfRange(responseSendBinaryNdefData, 0, responseSendBinaryNdefData.length - 2);
                writeToUiAppend(readResult, "ndefMessage length: " + ndefMessage.length + " data: " + bytesToHex(ndefMessage));
                writeToUiAppend(readResult, "ndefMessage: " + new String(ndefMessage));
                System.out.println("ndefMessage: " + new String(ndefMessage));

                // strip off the first 2 bytes
                byte[] ndefMessageStrip = Arrays.copyOfRange(ndefMessage, 9, ndefMessage.length);

                //String ndefMessageParsed = Utils.parseTextrecordPayload(ndefMessageStrip);
                String ndefMessageParsed = new String(ndefMessageStrip);
                writeToUiAppend(readResult, "ndefMessage parsed: " + ndefMessageParsed);
                System.out.println("ndefMessage parsed: " + ndefMessageParsed);

                // try to get a NdefMessage from the byte array
                byte[] ndefMessageByteArray = Arrays.copyOfRange(ndefMessage, 2, ndefMessage.length);
                try {
                    NdefMessage ndefMessageFromTag = new NdefMessage(ndefMessageByteArray);
                    NdefRecord[] ndefRecords = ndefMessageFromTag.getRecords();
                    NdefRecord ndefRecord;
                    int ndefRecordsCount = ndefRecords.length;
                    if (ndefRecordsCount > 0) {
                        for (int i = 0; i < ndefRecordsCount; i++) {
                            short ndefTnf = ndefRecords[i].getTnf();
                            byte[] ndefType = ndefRecords[i].getType();
                            byte[] ndefPayload = ndefRecords[i].getPayload();
                            // here we are trying to parse the content
                            // Well known type - Text
                            if (ndefTnf == NdefRecord.TNF_WELL_KNOWN &&
                                    Arrays.equals(ndefType, NdefRecord.RTD_TEXT)) {
                                writeToUiAppend(readResult, "rec: " + i +
                                        " Well known Text payload\n" + new String(ndefPayload) + " \n");
                                writeToUiAppend(readResult, Utils.parseTextrecordPayload(ndefPayload));
                            }
                            // Well known type - Uri
                            if (ndefTnf == NdefRecord.TNF_WELL_KNOWN &&
                                    Arrays.equals(ndefType, NdefRecord.RTD_URI)) {
                                writeToUiAppend(readResult, "rec: " + i +
                                        " Well known Uri payload\n" + new String(ndefPayload) + " \n");
                                writeToUiAppend(readResult, Utils.parseUrirecordPayload(ndefPayload) + " \n");
                            }
                        }
                    }
                } catch (FormatException e) {
                    e.printStackTrace();
                }
            } else {
                writeToUiAppend(readResult, "IsoDep == null");
            }
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR IOException: " + e);
            e.printStackTrace();
        }
    }

    /**
     * Determines whether the specified byte array starts with the specific bytes.
     *
     * @param array      The array whose start is tested.
     * @param startBytes The byte array whose presence at the start of the array is tested.
     * @return 'true' when the array starts with the specified start bytes, 'false' otherwise.
     */
    private static boolean startsWith(byte[] array, byte[] startBytes) {
        if (array == null || startBytes == null || array.length < startBytes.length) {
            return false;
        }

        for (int i = 0; i < startBytes.length; i++) {
            if (array[i] != startBytes[i]) {
                return false;
            }
        }

        return true;
    }

    private static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }
        return Arrays.copyOf(bytes, i + 1);
    }

    // https://stackoverflow.com/a/51338700/8166854
    private byte[] selectApdu(byte[] aid) {
        byte[] commandApdu = new byte[6 + aid.length];
        commandApdu[0] = (byte) 0x00;  // CLA
        commandApdu[1] = (byte) 0xA4;  // INS
        commandApdu[2] = (byte) 0x04;  // P1
        commandApdu[3] = (byte) 0x00;  // P2
        commandApdu[4] = (byte) (aid.length & 0x0FF);       // Lc
        System.arraycopy(aid, 0, commandApdu, 5, aid.length);
        commandApdu[commandApdu.length - 1] = (byte) 0x00;  // Le
        return commandApdu;
    }

    public static List<byte[]> divideArray(byte[] source, int chunksize) {

        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    public static int byteArrayToInt(byte[] byteArray) {
        if (byteArray == null) {
            throw new IllegalArgumentException("Parameter \'byteArray\' cannot be null");
        } else {
            return byteArrayToInt(byteArray, 0, byteArray.length);
        }
    }

    public static int byteArrayToInt(byte[] byteArray, int startPos, int length) {
        if (byteArray == null) {
            throw new IllegalArgumentException("Parameter \'byteArray\' cannot be null");
        } else if (length > 0 && length <= 4) {
            if (startPos >= 0 && byteArray.length >= startPos + length) {
                int value = 0;

                for (int i = 0; i < length; ++i) {
                    value += (byteArray[startPos + i] & 255) << 8 * (length - i - 1);
                }

                return value;
            } else {
                throw new IllegalArgumentException("Length or startPos not valid");
            }
        } else {
            throw new IllegalArgumentException("Length must be between 1 and 4. Length = " + length);
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private String getDec(byte[] bytes) {
        long result = 0;
        long factor = 1;
        for (int i = 0; i < bytes.length; ++i) {
            long value = bytes[i] & 0xffl;
            result += value * factor;
            factor *= 256l;
        }
        return result + "";
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = textView.getText().toString() + "\n" + message;
            textView.setText(newString);
        });
    }

    private void writeToUiAppendReverse(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
        });
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private byte[] getFastTagDataRange(NfcA nfcA, int fromPage, int toPage) {
        byte[] response;
        byte[] command = new byte[]{
                (byte) 0x3A,  // FAST_READ
                (byte) (fromPage & 0x0ff),
                (byte) (toPage & 0x0ff),
        };
        try {
            response = nfcA.transceive(command); // response should be 16 bytes = 4 pages
            if (response == null) {
                // either communication to the tag was lost or a NACK was received
                writeToUiAppend(readResult, "ERROR on reading page");
                return null;
            } else if ((response.length == 1) && ((response[0] & 0x00A) != 0x00A)) {
                // NACK response according to Digital Protocol/T2TOP
                writeToUiAppend(readResult, "ERROR NACK received");
                // Log and return
                return null;
            } else {
                // success: response contains ACK or actual data
            }
        } catch (TagLostException e) {
            // Log and return
            writeToUiAppend(readResult, "ERROR Tag lost exception");
            return null;
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR IOException: " + e);
            e.printStackTrace();
            return null;
        }
        return response;
    }

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    private void exportDumpMail() {
        if (dumpExportString.isEmpty()) {
            writeToUiToast("Scan a tag first before sending emails :-)");
            return;
        }
        String subject = "Dump NFC-Tag " + tagTypeString + " UID: " + tagIdString;
        String body = dumpExportString;
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }

    private void exportDumpFile() {
        if (dumpExportString.isEmpty()) {
            writeToUiToast("Scan a tag first before writing files :-)");
            return;
        }
        verifyPermissionsWriteString();
    }

    // section external storage permission check
    private void verifyPermissionsWriteString() {
        String[] permissions = {Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE};
        if (ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[0]) == PackageManager.PERMISSION_GRANTED
                && ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[1]) == PackageManager.PERMISSION_GRANTED) {
            writeStringToExternalSharedStorage();
        } else {
            ActivityCompat.requestPermissions(this,
                    permissions,
                    REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE);
        }
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        //boolean pickerInitialUri = false;
        //intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = tagTypeString + "_" + tagIdString + ".txt";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writng the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        fileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> fileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = dumpExportString;
                                writeTextToUri(uri, fileContent);
                                String message = "file written to external shared storage: " + uri.toString();
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(contextSave.getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mExportMail = menu.findItem(R.id.action_export_mail);
        mExportMail.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportDumpMail();
                return false;
            }
        });

        MenuItem mExportFile = menu.findItem(R.id.action_export_file);
        mExportFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportDumpFile();
                return false;
            }
        });
        return super.onCreateOptionsMenu(menu);
    }
}
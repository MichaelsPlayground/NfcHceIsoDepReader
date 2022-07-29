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

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback{

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

                /*
                NdefMessage ndefMessageRead = null;
                try {
                    ndefMessageRead = new NdefMessage(ndefMessage);
                } catch (FormatException e) {
                    e.printStackTrace();
                }

                 */
                /*
                //NdefRecord[] record = ndefMessageRead.getRecords();
                NdefRecord[] record = new NdefRecord[1];
                try {
                    record[1] = new NdefRecord(responseSendBinaryNdefData);
                } catch (FormatException e) {
                    e.printStackTrace();
                }

                int ndefRecordsCount = record.length;
                writeToUiAppend(readResult, "ndefMessage with ndefRecords length: " + ndefRecordsCount);
                if (ndefRecordsCount > 0) {
                    String ndefText = "";
                    for (int i = 0; i < ndefRecordsCount; i++) {
                        short ndefTnf = record[i].getTnf();
                        switch (ndefTnf) {
                            case NdefRecord.TNF_EMPTY: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (0 TNF_EMPTY)");
                                break;
                            }
                            case NdefRecord.TNF_WELL_KNOWN: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (1 TNF_WELL_KNOWN)");
                                break;
                            }
                            case NdefRecord.TNF_MIME_MEDIA: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (2 TNF_MIME_MEDIA)");
                                break;
                            }
                            case NdefRecord.TNF_ABSOLUTE_URI: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (3 TNF_ABSOLUTE_URI)");
                                break;
                            }
                            case NdefRecord.TNF_EXTERNAL_TYPE: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (4 TNF_EXTERNAL_TYPE)");
                                break;
                            }
                            case NdefRecord.TNF_UNKNOWN: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (5 TNF_UNKNOWN)");
                                break;
                            }
                            case NdefRecord.TNF_UNCHANGED: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (6 TNF_UNCHANGED)");
                                break;
                            }
                            default: {
                                writeToUiAppend(readResult, "rec: " + i + " TNF + " + ndefTnf + " (undefined)");
                                break;
                            }
                        }
                    }
                }
*/

// <aid-filter android:name="F0394148148100" />


                /*
                byte[] historicalBytes = isoDep.getHistoricalBytes();
                writeToUiAppend(readResult, "historical bytes: " + bytesToHex(historicalBytes));

                byte[] PSE = "1PAY.SYS.DDF01".getBytes(); // PSE
                byte[] PPSE = "2PAY.SYS.DDF01".getBytes(); // PPSE

                writeToUiAppend(readResult, "selectApdu with PSE");
                // now we run the select command with PSE
                byte[] command = selectApdu(PSE);
                byte[] responsePse = isoDep.transceive(command);
                if (responsePse == null) {
                    writeToUiAppend(readResult, "selectApdu with PSE fails (null)");
                } else {
                    writeToUiAppend(readResult, "responsePse length: " + responsePse.length + " data: " + bytesToHex(responsePse));
                    System.out.println("pse: " + bytesToHex(responsePse));
                }

                writeToUiAppend(readResult, "selectApdu with PPSE");
                // now we run the select command with PPSE
                command = selectApdu(PPSE);
                byte[] responsePpse = isoDep.transceive(command);
                if (responsePpse == null) {
                    writeToUiAppend(readResult, "selectApdu with PPSE fails (null)");
                } else {
                    writeToUiAppend(readResult, "responsePpse length: " + responsePpse.length + " data: " + bytesToHex(responsePpse));
                    System.out.println("ppse: " + bytesToHex(responsePpse));
                }

                // parse ppse response

                // https://github.com/evsinev/ber-tlv
                //byte[][] responsePseParsed = SimpleTlvParser.readTLV  (responsePse, "PSE");
                BerTlvParser parser = new BerTlvParser(LOG);

                //byte[] bytes = HexUtil.parseHex("50045649534157131000023100000033D44122011003400000481F");
                //BerTlvs tlvs = parser.parse(bytes, 0, bytes.length);
                //BerTlvs tlvs = parser.parse(responsePse, 0, responsePse.length);
                BerTlvs tlvs = parser.parse(responsePpse, 0, responsePpse.length);
                //BerTlv tlv = parser.parseConstructed(responsePpse, 0, responsePpse.length);

                List<BerTlv> tlvList = tlvs.getList();
                int tlvListLength = tlvList.size();
                writeToUiAppend(readResult, "tlvListLength length: " + tlvListLength);
                for (int i = 0; i < tlvListLength; i++) {
                    BerTlv tlv = tlvList.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                }
                // mc output: 6F (File Control Information (FCI) Template) 90

                // we need to get tag 6F that is constructed
                BerTlv tag6f = tlvs.find(new BerTag(0x6F));
                //writeToUiAppend(readResult, "tag6f is constructed: " + tag6f.isConstructed());
                //byte[] tag6fValue = tag6f.getBytesValue(); // gives error, tag6f is constructed
                //writeToUiAppend(readResult, "tag6fValue length: " + tag6fValue.length + " data: " + bytesToHex(tag6fValue));
                List<BerTlv> tag6fVals = tag6f.getValues();
                int tag6fValLength = tag6fVals.size();
                writeToUiAppend(readResult, "tag6fValLength length: " + tag6fValLength);
                for (int i = 0; i < tag6fValLength; i++) {
                    BerTlv tlv = tag6fVals.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                }
                // MC output: 84 (Dedicated File (DF) Name) A5 (File Control Information (FCI) Proprietary Template)

                // tag 84 is primitive
                BerTlv tag84 = tlvs.find(new BerTag(0x84));
                byte[] tag84Bytes;
                if (tag84 == null) {
                    writeToUiAppend(readResult, "tag84 is null");
                    return;
                } else {
                    tag84Bytes = tag84.getBytesValue();
                    writeToUiAppend(readResult, "tag84Bytes length: " + tag84Bytes.length + " data: " + bytesToHex(tag84Bytes));
                }
                // MC output: 325041592E5359532E4444463031

                // tag a5 is constructed
                BerTlv taga5 = tlvs.find(new BerTag(0xA5));
                List<BerTlv> taga5Vals = taga5.getValues();
                int taga5ValLength = taga5Vals.size();
                writeToUiAppend(readResult, "taga5ValLength length: " + taga5ValLength);
                for (int i = 0; i < taga5ValLength; i++) {
                    BerTlv tlv = taga5Vals.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                }
                // MC output: BF0C (File Control Information (FCI) Issuer Discretionary Data)

                // tag bf0c is constructed
                BerTlv tagbf0c = tlvs.find(new BerTag(0xBF, 0x0C));
                List<BerTlv> tagbf0cVals = tagbf0c.getValues();
                int tagbf0cValLength = tagbf0cVals.size();
                writeToUiAppend(readResult, "tagbf0cValLength length: " + tagbf0cValLength);
                for (int i = 0; i < tagbf0cValLength; i++) {
                    BerTlv tlv = tagbf0cVals.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                }
                // MC output: 61 (Application template)

                // note: could be multiple tag 61 entries
                // tag 61 Application Template
                List<BerTlv> tag61s = tlvs.findAll(new BerTag(0x61));
                int tag61sLength = tag61s.size();
                writeToUiAppend(readResult, "multiple BerTag 61");
                writeToUiAppend(readResult, "tag61s length: " + tag61sLength);
                System.out.println("** Multiple BerTag 61 **");
                for (int i = 0; i < tag61sLength; i++) {
                    BerTlv tlv = tag61s.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                    System.out.println("BerTag " + i + " " + berTag.toString());
                }
                // tag 4F is primitive (Application Identifier (AID) – card)
                List<BerTlv> tag4fs = tlvs.findAll(new BerTag(0x4F));
                int tag4fsLength = tag4fs.size();
                writeToUiAppend(readResult, "multiple BerTag 4F");
                writeToUiAppend(readResult, "tag4fs length: " + tag4fsLength);
                System.out.println("** multiple BerTag 4F: " + tag4fsLength);
                for (int i = 0; i < tag4fsLength; i++) {
                    BerTlv tlv = tag4fs.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                    byte[] tag4fBytes;
                    if (berTag == null) {
                        writeToUiAppend(readResult, "tag4f is null");
                        return;
                    } else {
                        tag4fBytes = tlv.getBytesValue();
                        writeToUiAppend(readResult, "tag4fBytes length: " + tag4fBytes.length + " data: " + bytesToHex(tag4fBytes));
                        System.out.println("tag4fBytes length: " + tag4fBytes.length + " data: " + bytesToHex(tag4fBytes));
                    }
                }
                // tag 50 is primitive ()
                List<BerTlv> tag50s = tlvs.findAll(new BerTag(0x50));
                int tag50sLength = tag50s.size();
                writeToUiAppend(readResult, "multiple BerTag 50");
                writeToUiAppend(readResult, "tag50s length: " + tag50sLength);
                for (int i = 0; i < tag50sLength; i++) {
                    BerTlv tlv = tag50s.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                    byte[] tag50Bytes;
                    if (berTag == null) {
                        writeToUiAppend(readResult, "tag50 is null");
                        return;
                    } else {
                        tag50Bytes = tlv.getBytesValue();
                        writeToUiAppend(readResult, "tag50Bytes length: " + tag50Bytes.length + " data: " + bytesToHex(tag50Bytes));
                    }
                }


                // tag 61 Application Template
                writeToUiAppend(readResult, "single BerTag:");
                // tag 61 is constructed
                BerTlv tag61 = tlvs.find(new BerTag(0x61));
                List<BerTlv> tag61Vals = tag61.getValues();
                int tag61ValLength = tag61Vals.size();
                writeToUiAppend(readResult, "tag61ValLength length: " + tag61ValLength);
                for (int i = 0; i < tag61ValLength; i++) {
                    BerTlv tlv = tag61Vals.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                }
                // MC output - all are primitive:
                // 4F (Application Identifier (AID) – card)
                // 50 (Application Label) [optional ??]
                // 87 (Application Priority Indicator)
                // 9F0A (unknown) (Application Selection Registered Proprietary Data (ASRPD), see requirement 3.3.1.2))

                // tag 4F is primitive (Application Identifier (AID) – card)
                BerTlv tag4f = tlvs.find(new BerTag(0x4F));
                byte[] tag4fBytes;
                if (tag4f == null) {
                    writeToUiAppend(readResult, "tag4f is null");
                    return;
                } else {
                    tag4fBytes = tag4f.getBytesValue();
                    writeToUiAppend(readResult, "tag4fBytes length: " + tag4fBytes.length + " data: " + bytesToHex(tag4fBytes));
                }
                // MC output: A0000000041010

                // tag 50 is primitive
                BerTlv tag50 = tlvs.find(new BerTag(0x50));
                byte[] tag50Bytes;
                if (tag50 == null) {
                    writeToUiAppend(readResult, "tag50 is null");
                    //return;
                } else {
                    tag50Bytes = tag50.getBytesValue();
                    writeToUiAppend(readResult, "tag50Bytes length: " + tag50Bytes.length + " data: " + bytesToHex(tag50Bytes));
                }
                // MC output: D e b i t M a s t e r C a r d

                // tag 87 is primitive
                BerTlv tag87 = tlvs.find(new BerTag(0x87));
                byte[] tag87Bytes;
                if (tag87 == null) {
                    writeToUiAppend(readResult, "tag87 is null");
                    //return;
                } else {
                    tag87Bytes = tag87.getBytesValue();
                    writeToUiAppend(readResult, "tag87Bytes length: " + tag87Bytes.length + " data: " + bytesToHex(tag87Bytes));
                }
                // MC output: 01

                // tag 9f0a is primitive
                BerTlv tag9f0a = tlvs.find(new BerTag(0x9F, 0x0a));
                byte[] tag9f0aBytes;
                if (tag9f0a == null) {
                    writeToUiAppend(readResult, "tag9f0a is null");
                    //return;
                } else {
                    tag9f0aBytes = tag9f0a.getBytesValue();
                    writeToUiAppend(readResult, "tag9f0a0Bytes length: " + tag9f0aBytes.length + " data: " + bytesToHex(tag9f0aBytes));
                }
                // MC output: 00010101

                writeToUiAppend(readResult, "*** now processing the file system ***");
*/
                // tested: it is NOT neccessary to read the file system multiple times for
                // different AIDs - just use 1 for all
                // this is the processing for more than 1 aid
                // tag4fs holds the aid's
                /*
                writeToUiAppend(readResult, "## read all AIDs: " + tag4fsLength + " entries");
                for (int j = 0; j < tag4fsLength; j++) {
                    BerTlv multiAid = tag4fs.get(j);
                    byte[] multiAidBytes = multiAid.getBytesValue();
                    writeToUiAppend(readResult, "AID = multiAidBytes length: " + multiAidBytes.length + " data: " + bytesToHex(multiAidBytes));
                    byte[] selectResponse = isoDep.transceive(selectApdu(multiAidBytes));
*/

                /*
                // here we are processing only the first of possible multiple aids on the card
                // tag4fBytes has the aid
                writeToUiAppend(readResult, "AID = tag4fBytes length: " + tag4fBytes.length + " data: " + bytesToHex(tag4fBytes));
                byte[] selectResponse = isoDep.transceive(selectApdu(tag4fBytes));
                if (selectResponse == null) {
                    writeToUiAppend(readResult, "selectResponse is null");
                } else {
                    writeToUiAppend(readResult, "selectResponse length: " + selectResponse.length + " data: " + bytesToHex(selectResponse));
                    System.out.println("selectResponse length: " + selectResponse.length + " data: " + bytesToHex(selectResponse));
                }
                // MC output:
                // 6f528407a0000000041010a54750104465626974204d6173746572436172649f12104465626974204d6173746572436172648701019f1101015f2d046465656ebf0c119f0a04000101019f6e07028000003030009000

                // parse select response
                BerTlvs tlv6fs = parser.parse(selectResponse, 0, selectResponse.length);
                List<BerTlv> tlv6fList = tlv6fs.getList();
                int tlv6fListLength = tlv6fList.size();
                writeToUiAppend(readResult, "tlv6fListLength length: " + tlv6fListLength);
                for (int i = 0; i < tlv6fListLength; i++) {
                    BerTlv tlv = tlvList.get(i);
                    BerTag berTag = tlv.getTag();
                    writeToUiAppend(readResult, "BerTag: " + berTag.toString());
                }
                // mc output: 6F 90

                // check for 9f38 (Processing Options Data Object List (PDOL))
                // if present use this for gpo
                // tag 9f0a is primitive
                BerTlv tag9f38 = tlv6fs.find(new BerTag(0x9F, 0x38));
                byte[] tag9f38Bytes;
                if (tag9f38 == null) {
                    writeToUiAppend(readResult, "tag9f38 is null");
                    writeToUiAppend(readResult, "## NO PDOL returned ##");
                    System.out.println("## tag9f38 is null = NO PDOL returned ##");
                    //return;
                } else {
                    tag9f38Bytes = tag9f38.getBytesValue();
                    writeToUiAppend(readResult, "tag9f38Bytes length: " + tag9f38Bytes.length + " data: " + bytesToHex(tag9f38Bytes));
                    writeToUiAppend(readResult, "## PDOL returned ##");
                    System.out.println("tag9f38Bytes length: " + tag9f38Bytes.length + " data: " + bytesToHex(tag9f38Bytes));
                }
                // Lloyds MC output: 9f66049f02069f03069f1a0295055f2a029a039c019f3704

                // if we do not want to brute force the file system we need to use the PDOL to get the locations of the records
                // this is for a NO PDOL
                // The GPO command is “80 A8 00 00 02 83 00”. Since there is no PDOL, we will put
                // the tag 83 with the size 00 only. Lc is the size of the data field, which is 2 bytes.
                byte[] pdolCmd = hexStringToByteArray("80A80000028300");
                writeToUiAppend(readResult, "Sending GPO with null PDOL");
                writeToUiAppend(readResult, "pdolCmd length: " + pdolCmd.length + " data: " + bytesToHex(pdolCmd));
                byte[] resultGpo;
                resultGpo = isoDep.transceive(pdolCmd);
                // return 67 00 = SEND with PDOL
                if (resultGpo == null) {
                    writeToUiAppend(readResult, "resultGpo is null");
                    return;
                } else if ((resultGpo[resultGpo.length - 2] == (byte) 0x67) && (resultGpo[resultGpo.length - 1] == (byte) 0x00)) {
                    writeToUiAppend(readResult, "resultGpo is 0x6700, running brute force reading");
                    runBruteForceReadOnCard(isoDep, tlvList, readResult);
                    return;
                } else {
                    writeToUiAppend(readResult, "resultGpo length: " + resultGpo.length + " data: " + bytesToHex(resultGpo));
                    System.out.println("resultGpo length: " + resultGpo.length + " data: " + bytesToHex(resultGpo));
                }
                // Lloyds: tag 94: Application File Locator (AFL): 08010100100102011801020020010200
                // AA: tag94: 6700
*/


/*
barclays: resultGpo length: 26 data: 7716820219809410080101001001020118010200200102009000

77 Response Message Template Format 2
 	82 Application Interchange Profile
 	 	1980
 	94 Application File Locator (AFL)
 	 	08010100100102011801020020010200
90 Issuer Public Key Certificate
 */
/*
                // proceed with reading / parsing only when resultGpo is success
                byte[] tag94Bytes = new byte[0]; // 94 takes the afl, the application file locator
                if ((resultGpo[resultGpo.length - 2] == (byte) 0x90) && (resultGpo[resultGpo.length - 1] == (byte) 0x00)) {
                    BerTlvs tlvGpos = parser.parse(resultGpo, 0, resultGpo.length);
                    BerTlv tag94 = tlvGpos.find(new BerTag(0x94));
                    if (tag94 == null) {
                        writeToUiAppend(readResult, "tag94 is null");
                        //return;
                    } else {
                        tag94Bytes = tag94.getBytesValue();
                        writeToUiAppend(readResult, "tag94Bytes length: " + tag94Bytes.length + " data: " + bytesToHex(tag94Bytes));
                        System.out.println("tag94Bytes length: " + tag94Bytes.length + " data: " + bytesToHex(tag94Bytes));
                    }
                    // MC output: length: 16 data: 08010100100102011801020020010200
                    // 08010100 10010201 18010200 20010200
                    int tag94BytesLength = tag94Bytes.length;
                    // split array by 4 bytes
                    List<byte[]> tag94BytesList = divideArray(tag94Bytes, 4);
                    int tag94BytesListLength = tag94BytesList.size();
                    writeToUiAppend(readResult, "tag94Bytes divided into " + tag94BytesListLength + " arrays");
                    for (int i = 0; i < tag94BytesListLength; i++) {
                        writeToUiAppend(readResult, "get sfi + record for array " + i + " data: " + bytesToHex(tag94BytesList.get(i)));
                        // get sfi from first byte, 2nd byte is first record, 3rd byte is last record, 4th byte is offline transactions
                        byte[] tag94BytesListEntry = tag94BytesList.get(i);
                        byte sfiOrg = tag94BytesListEntry[0];
                        byte rec1 = tag94BytesListEntry[1];
                        byte recL = tag94BytesListEntry[2];
                        byte offl = tag94BytesListEntry[3]; // offline authorization
                        writeToUiAppend(readResult, "sfiOrg: " + sfiOrg + " rec1: " + ((int) rec1) + " recL: " + ((int) recL));
                        int sfiNew = (byte) sfiOrg | 0x04; // add 4 = set bit 3
                        writeToUiAppend(readResult, "sfiNew: " + sfiNew + " rec1: " + ((int) rec1) + " recL: " + ((int) recL));

                        // read records
                        byte[] resultReadRecord = new byte[0];

                        for (int iRecords = (int) rec1; iRecords <= (int) recL; iRecords++) {
                            byte[] cmd = hexStringToByteArray("00B2000400");
                            cmd[2] = (byte) (iRecords & 0x0FF);
                            cmd[3] |= (byte) (sfiNew & 0x0FF);
                            resultReadRecord = isoDep.transceive(cmd);
                            writeToUiAppend(readResult, "readRecordCommand length: " + cmd.length + " data: " + bytesToHex(cmd));
                            if ((resultReadRecord[resultReadRecord.length - 2] == (byte) 0x90) && (resultReadRecord[resultReadRecord.length - 1] == (byte) 0x00)) {
                                writeToUiAppend(readResult, "Success: read record result: " + bytesToHex(resultReadRecord));
                                writeToUiAppend(readResult, "* parse AFL for entry: " + bytesToHex(tag94BytesListEntry) + " record: " + iRecords);
                                parseAflDataToTextView(resultReadRecord, readResult);
                            } else {
                                writeToUiAppend(readResult, "ERROR: read record failed, result: " + bytesToHex(resultReadRecord));
                                resultReadRecord = new byte[0];
                            }
                        }
                    } // for (int i = 0; i < tag94BytesListLength; i++) { // = number of records belong to this afl


                } // if gpoResult = success

*/
                /*
                // brute force to read all data in file table
                writeToUiAppend(readResult, "*** starting brute force to read all records ***");
                //runBruteForceReadOnCard(isoDep, tlvList, readResult);
                writeToUiAppend(readResult, "*** ending brute force to read all records ***");
*/
                // END file processing

                //} // FOR multiAids
                // see this online decoder to get the content:
                // https://emvlab.org/tlvutils/
/*
HVB MC debit:

pse: 6f20840e315041592e5359532e4444463031a50e8801015f2d086465656e667269749000
https://emvlab.org/tlvutils/?data=6f20840e315041592e5359532e4444463031a50e8801015f2d086465656e667269749000
6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	315041592E5359532E4444463031
 	A5 File Control Information (FCI) Proprietary Template
 	 	88 Short File Identifier (SFI)
 	 	 	01
 	 	5F2D Language Preference
 	 	 	d e e n f r i t
90 Issuer Public Key Certificate

ppse: 6f45840e325041592e5359532e4444463031a533bf0c30612e4f07a0000000031010500e48564220566973612044656269748701019f0a080001050100000000bf6304df2001809000
https://emvlab.org/tlvutils/?data=6f45840e325041592e5359532e4444463031a533bf0c30612e4f07a0000000031010500e48564220566973612044656269748701019f0a080001050100000000bf6304df2001809000
6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	325041592E5359532E4444463031
 	A5 File Control Information (FCI) Proprietary Template
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	A0000000031010
 	 	 	 	50 Application Label
 	 	 	 	 	H V B V i s a D e b i t
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	01
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	0001050100000000
 	 	 	 	BF63 Unknown tag
 	 	 	 	 	DF20 Unknown tag
 	 	 	 	 	 	80
90 Issuer Public Key Certificate

AAB Mastercard:
https://emvlab.org/tlvutils/?data=6f20840e315041592e5359532e4444463031a50e8801015f2d046465656e9f1101019000

pse: 6f20840e315041592e5359532e4444463031a50e8801015f2d046465656e9f1101019000

6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	315041592E5359532E4444463031
 	A5 File Control Information (FCI) Proprietary Template
 	 	88 Short File Identifier (SFI)
 	 	 	01
 	 	5F2D Language Preference
 	 	 	d e e n
 	 	9F11 Issuer Code Table Index
 	 	 	01
90 Issuer Public Key Certificate

ppse: 6f3c840e325041592e5359532e4444463031a52abf0c2761254f07a000000004101050104465626974204d6173746572436172648701019f0a04000101019000
https://emvlab.org/tlvutils/?data=6f3c840e325041592e5359532e4444463031a52abf0c2761254f07a000000004101050104465626974204d6173746572436172648701019f0a04000101019000

6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	325041592E5359532E4444463031
 	A5 File Control Information (FCI) Proprietary Template
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	A0000000041010
 	 	 	 	50 Application Label
 	 	 	 	 	D e b i t M a s t e r C a r d
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	01
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	00010101
90 Issuer Public Key Certificate

response nach select aid:
6f528407a0000000041010a54750104465626974204d6173746572436172649f12104465626974204d6173746572436172648701019f1101015f2d046465656ebf0c119f0a04000101019f6e07028000003030009000

https://emvlab.org/tlvutils/?data=6f528407a0000000041010a54750104465626974204d6173746572436172649f12104465626974204d6173746572436172648701019f1101015f2d046465656ebf0c119f0a04000101019f6e07028000003030009000

6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	A0000000041010
 	A5 File Control Information (FCI) Proprietary Template
 	 	50 Application Label
 	 	 	D e b i t M a s t e r C a r d
 	 	9F12 Application Preferred Name
 	 	 	D e b i t M a s t e r C a r d
 	 	87 Application Priority Indicator
 	 	 	01
 	 	9F11 Issuer Code Table Index
 	 	 	01
 	 	5F2D Language Preference
 	 	 	d e e n
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	9F0A Unknown tag
 	 	 	 	00010101
 	 	 	9F6E Unknown tag
 	 	 	 	02800000303000
90 Issuer Public Key Certificate

Read file content with brute force:

sfi: 1 record: 1 length: 119 data: 70759f6c0200019f6206000000000f009f63060000000000fe563442353337353035303030303136303131305e202f5e323430333232313237393433323930303030303030303030303030303030309f6401029f65020f009f660200fe9f6b135375050000160110d24032210000000000000f9f670102
https://emvlab.org/tlvutils/?data=70759f6c0200019f6206000000000f009f63060000000000fe563442353337353035303030303136303131305e202f5e323430333232313237393433323930303030303030303030303030303030309f6401029f65020f009f660200fe9f6b135375050000160110d24032210000000000000f9f670102
70 EMV Proprietary Template
 	9F6C Unknown tag
 	 	0001
 	9F62 Unknown tag
 	 	000000000F00
 	9F63 Unknown tag
 	 	0000000000FE
 	56 Unknown tag
 	 	42353337353035303030303136303131305E202F5E32343033323231323739343332393030303030303030303030303030303030
 	9F64 Unknown tag
 	 	02
 	9F65 Unknown tag
 	 	0F00
 	9F66 Unknown tag
 	 	00FE
 	9F6B Unknown tag
 	 	5375050000160110D24032210000000000000F
 	9F67 Unknown tag
 	 	02

sfi: 2 record: 1 length: 169 data: 7081a69f420209785f25032203015f24032403315a0853750500001601105f3401009f0702ffc09f080200028c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d0c910a8a0295059f37049f4c088e0e000000000000000042031e031f039f0d05b4508400009f0e0500000000009f0f05b4708480005f280202809f4a018257135375050000160110d24032212794329000000f
https://emvlab.org/tlvutils/?data=7081a69f420209785f25032203015f24032403315a0853750500001601105f3401009f0702ffc09f080200028c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d0c910a8a0295059f37049f4c088e0e000000000000000042031e031f039f0d05b4508400009f0e0500000000009f0f05b4708480005f280202809f4a018257135375050000160110d24032212794329000000f
ACHTUNG: 5A Application Primary Account Number (PAN)

70 EMV Proprietary Template
 	9F42 Application Currency Code
 	 	0978
 	5F25 Application Effective Date
 	 	220301
 	5F24 Application Expiration Date
 	 	240331
 	5A Application Primary Account Number (PAN)
 	 	5375050000160110
 	5F34 Application Primary Account Number (PAN) Sequence Number
 	 	00
 	9F07 Application Usage Control
 	 	FFC0
 	9F08 Application Version Number
 	 	0002
 	8C Card Risk Management Data Object List 1 (CDOL1)
 	 	9F02069F03069F1A0295055F2A029A039C019F37049F35019F45029F4C089F34039F21039F7C14
 	8D Card Risk Management Data Object List 2 (CDOL2)
 	 	910A8A0295059F37049F4C08
 	8E Cardholder Verification Method (CVM) List
 	 	000000000000000042031E031F03
 	9F0D Issuer Action Code – Default
 	 	B450840000
 	9F0E Issuer Action Code – Denial
 	 	0000000000
 	9F0F Issuer Action Code – Online
 	 	B470848000
 	5F28 Issuer Country Code
 	 	0280
 	9F4A Static Data Authentication Tag List
 	 	82
 	57 Track 2 Equivalent Data
 	 	5375050000160110D24032212794329000000F

sfi: 3 record: 1 length: 147 data: 7081909f420209785f25032203015f24032403315a0853750500001601105f3401009f0702ffc08c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d0c910a8a0295059f37049f4c088e1200000000000000004203440341031e031f039f0d05bc50bc08009f0e0500000000009f0f05bc70bc98005f280202809f4a0182
https://emvlab.org/tlvutils/?data=7081909f420209785f25032203015f24032403315a0853750500001601105f3401009f0702ffc08c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d0c910a8a0295059f37049f4c088e1200000000000000004203440341031e031f039f0d05bc50bc08009f0e0500000000009f0f05bc70bc98005f280202809f4a0182

70 EMV Proprietary Template
 	9F42 Application Currency Code
 	 	0978
 	5F25 Application Effective Date
 	 	220301
 	5F24 Application Expiration Date
 	 	240331
 	5A Application Primary Account Number (PAN)
 	 	5375050000160110
 	5F34 Application Primary Account Number (PAN) Sequence Number
 	 	00
 	9F07 Application Usage Control
 	 	FFC0
 	8C Card Risk Management Data Object List 1 (CDOL1)
 	 	9F02069F03069F1A0295055F2A029A039C019F37049F35019F45029F4C089F34039F21039F7C14
 	8D Card Risk Management Data Object List 2 (CDOL2)
 	 	910A8A0295059F37049F4C08
 	8E Cardholder Verification Method (CVM) List
 	 	00000000000000004203440341031E031F03
 	9F0D Issuer Action Code – Default
 	 	BC50BC0800
 	9F0E Issuer Action Code – Denial
 	 	0000000000
 	9F0F Issuer Action Code – Online
 	 	BC70BC9800
 	5F28 Issuer Country Code
 	 	0280
 	9F4A Static Data Authentication Tag List
 	 	82

sfi: 4 record: 1 length: 187 data: 7081b89f4701039f4681b03cada902afb40289fbdfea01950c498191442c1b48234dcaff66bca63cbf821a3121fa808e4275a4e894b154c1874bddb00f16276e92c73c04468253b373f1e6a9a89e2705b4670682d0adff05617a21d7684031a1cdb438e66cd98d591dc376398c8aab4f137a2226122990d9b2b4c72ded6495d637338fefa893ae7fb4eb845f8ec2e260d2385a780f9fda64b3639a9547adad806f78c9bc9f17f9d4c5b26474b9ba03892a754ffdf24df04c702f86
https://emvlab.org/tlvutils/?data=7081b89f4701039f4681b03cada902afb40289fbdfea01950c498191442c1b48234dcaff66bca63cbf821a3121fa808e4275a4e894b154c1874bddb00f16276e92c73c04468253b373f1e6a9a89e2705b4670682d0adff05617a21d7684031a1cdb438e66cd98d591dc376398c8aab4f137a2226122990d9b2b4c72ded6495d637338fefa893ae7fb4eb845f8ec2e260d2385a780f9fda64b3639a9547adad806f78c9bc9f17f9d4c5b26474b9ba03892a754ffdf24df04c702f86

70 EMV Proprietary Template
 	9F47 Integrated Circuit Card (ICC) Public Key Exponent
 	 	03
 	9F46 Integrated Circuit Card (ICC) Public Key Certificate
 	 	3CADA902AFB40289FBDFEA01950C498191442C1B48234DCAFF66BCA63CBF821A3121FA808E4275A4E894B154C1874BDDB00F16276E92C73C04468253B373F1E6A9A89E2705B4670682D0ADFF05617A21D7684031A1CDB438E66CD98D591DC376398C8AAB4F137A2226122990D9B2B4C72DED6495D637338FEFA893AE7FB4EB845F8EC2E260D2385A780F9FDA64B3639A9547ADAD806F78C9BC9F17F9D4C5B26474B9BA03892A754FFDF24DF04C702F86

sfi: 4 record: 2 length: 227 data: 7081e08f01059f3201039224abfd2ebc115c3796e382be7e9863b92c266ccabc8bd014923024c80563234e8a11710a019081b004cc60769cabe557a9f2d83c7c73f8b177dbf69288e332f151fba10027301bb9a18203ba421bda9c2cc8186b975885523bf6707f287a5e88f0f6cd79a076319c1404fcdd1f4fa011f7219e1bf74e07b25e781d6af017a9404df9fd805b05b76874663ea88515018b2cb6140dc001a998016d28c4af8e49dfcc7d9cee314e72ae0d993b52cae91a5b5c76b0b33e7ac14a7294b59213ca0c50463cfb8b040bb8ac953631b80fa85a698b00228b5ff44223
https://emvlab.org/tlvutils/?data=7081e08f01059f3201039224abfd2ebc115c3796e382be7e9863b92c266ccabc8bd014923024c80563234e8a11710a019081b004cc60769cabe557a9f2d83c7c73f8b177dbf69288e332f151fba10027301bb9a18203ba421bda9c2cc8186b975885523bf6707f287a5e88f0f6cd79a076319c1404fcdd1f4fa011f7219e1bf74e07b25e781d6af017a9404df9fd805b05b76874663ea88515018b2cb6140dc001a998016d28c4af8e49dfcc7d9cee314e72ae0d993b52cae91a5b5c76b0b33e7ac14a7294b59213ca0c50463cfb8b040bb8ac953631b80fa85a698b00228b5ff44223

70 EMV Proprietary Template
 	8F Certification Authority Public Key Index
 	 	05
 	9F32 Issuer Public Key Exponent
 	 	03
 	92 Issuer Public Key Remainder
 	 	ABFD2EBC115C3796E382BE7E9863B92C266CCABC8BD014923024C80563234E8A11710A01
 	90 Issuer Public Key Certificate
 	 	04CC60769CABE557A9F2D83C7C73F8B177DBF69288E332F151FBA10027301BB9A18203BA421BDA9C2CC8186B975885523BF6707F287A5E88F0F6CD79A076319C1404FCDD1F4FA011F7219E1BF74E07B25E781D6AF017A9404DF9FD805B05B76874663EA88515018B2CB6140DC001A998016D28C4AF8E49DFCC7D9CEE314E72AE0D993B52CAE91A5B5C76B0B33E7AC14A7294B59213CA0C50463CFB8B040BB8AC953631B80FA85A698B00228B5FF44223

sfi: 4 record: 3 length: 187 data: 7081b89f4681b0aea2347a69e6d9544dfa891a761833e6e6d3a78d450142dd7c21c131e585448fbc8449fe777f1895cfb18f2983d60eed56466a688d9da6b3fb6593726251a83132b3f953a71098eeefcd388bb672ad5a3592d31ea145fdf6f763733bae482455c7987e96ae6cd8cf9d5ce562e5c80a7a6a083ba85c8eb86ddac0ca19186554dfe5ab4aeada5be92e30c0c16981c516c74203694fd04e2fe3a66bf590bd4bb3085fe80167e98c9745e7e4819e4bd55f2b9f470103
https://emvlab.org/tlvutils/?data=7081b89f4681b0aea2347a69e6d9544dfa891a761833e6e6d3a78d450142dd7c21c131e585448fbc8449fe777f1895cfb18f2983d60eed56466a688d9da6b3fb6593726251a83132b3f953a71098eeefcd388bb672ad5a3592d31ea145fdf6f763733bae482455c7987e96ae6cd8cf9d5ce562e5c80a7a6a083ba85c8eb86ddac0ca19186554dfe5ab4aeada5be92e30c0c16981c516c74203694fd04e2fe3a66bf590bd4bb3085fe80167e98c9745e7e4819e4bd55f2b9f470103

70 EMV Proprietary Template
 	9F46 Integrated Circuit Card (ICC) Public Key Certificate
 	 	AEA2347A69E6D9544DFA891A761833E6E6D3A78D450142DD7C21C131E585448FBC8449FE777F1895CFB18F2983D60EED56466A688D9DA6B3FB6593726251A83132B3F953A71098EEEFCD388BB672AD5A3592D31EA145FDF6F763733BAE482455C7987E96AE6CD8CF9D5CE562E5C80A7A6A083BA85C8EB86DDAC0CA19186554DFE5AB4AEADA5BE92E30C0C16981C516C74203694FD04E2FE3A66BF590BD4BB3085FE80167E98C9745E7E4819E4BD55F2B
 	9F47 Integrated Circuit Card (ICC) Public Key Exponent
 	 	03

DKB Giro VPay:

pse: 6f46840e315041592e5359532e4444463031a5348801055f2d046465656ebf0c275f540b42594c4144454d313030315f5316444530323132303330303030303030303030303030309000
https://emvlab.org/tlvutils/?data=6f46840e315041592e5359532e4444463031a5348801055f2d046465656ebf0c275f540b42594c4144454d313030315f5316444530323132303330303030303030303030303030309000

6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	315041592E5359532E4444463031
 	A5 File Control Information (FCI) Proprietary Template
 	 	88 Short File Identifier (SFI)
 	 	 	05
 	 	5F2D Language Preference
 	 	 	d e e n
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	5F54 Bank Identifier Code (BIC)
 	 	 	 	42594C4144454D31303031
 	 	 	5F53 International Bank Account Number (IBAN)
 	 	 	 	44453032313230333030303030303030303030303030
90 Issuer Public Key Certificate

ppse: 6f819b840e325041592e5359532e4444463031a58188bf0c818461194f09a000000059454301008701019f0a080001050100000000611a4f0aa00000035910100280018701019f0a08000105010000000061194f09d276000025474101008701019f0a08000105010000000061174f07a00000000320208701019f0a08000105010000000061174f07a00000000320108701029f0a0800010501000000009000

6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	325041592E5359532E4444463031
 	A5 File Control Information (FCI) Proprietary Template
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	A00000005945430100
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	01
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	0001050100000000
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	A0000003591010028001
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	01
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	0001050100000000
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	D27600002547410100
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	01
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	0001050100000000
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	A0000000032020
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	01
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	0001050100000000
 	 	 	61 Application Template
 	 	 	 	4F Application Identifier (AID) – card
 	 	 	 	 	A0000000032010
 	 	 	 	87 Application Priority Indicator
 	 	 	 	 	02
 	 	 	 	9F0A Unknown tag
 	 	 	 	 	0001050100000000
90 Issuer Public Key Certificate
https://emvlab.org/tlvutils/?data=6f819b840e325041592e5359532e4444463031a58188bf0c818461194f09a000000059454301008701019f0a080001050100000000611a4f0aa00000035910100280018701019f0a08000105010000000061194f09d276000025474101008701019f0a08000105010000000061174f07a00000000320208701019f0a08000105010000000061174f07a00000000320108701029f0a0800010501000000009000

Postbank Prepaid:

selectResponse: 6f5b8407a0000000031010a550500c5669736120507265706169648701019f38189f66049f02069f03069f1a0295055f2a029a039c019f37045f2d046465656ebf0c1a9f5a0531097802769f0a080001050400000000bf6304df2001809000
https://emvlab.org/tlvutils/?data=6f5b8407a0000000031010a550500c5669736120507265706169648701019f38189f66049f02069f03069f1a0295055f2a029a039c019f37045f2d046465656ebf0c1a9f5a0531097802769f0a080001050400000000bf6304df2001809000

 6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	A0000000031010
 	A5 File Control Information (FCI) Proprietary Template
 	 	50 Application Label
 	 	 	V i s a P r e p a i d
 	 	87 Application Priority Indicator
 	 	 	01
 	 	9F38 Processing Options Data Object List (PDOL)
 	 	 	9F66049F02069F03069F1A0295055F2A029A039C019F3704
 	 	5F2D Language Preference
 	 	 	d e e n
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	9F5A Unknown tag
 	 	 	 	3109780276
 	 	 	9F0A Unknown tag
 	 	 	 	0001050400000000
 	 	 	BF63 Unknown tag
 	 	 	 	DF20 Unknown tag
 	 	 	 	 	80
90 Issuer Public Key Certificate

search for 9f38:
9f66049f02069f03069f1a0295055f2a029a039c019f3704




 */


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
     * @param array The array whose start is tested.
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

    private static byte[] trim(byte[] bytes)
    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
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
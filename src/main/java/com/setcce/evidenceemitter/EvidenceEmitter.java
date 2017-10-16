package com.setcce.evidenceemitter;

import com.setcce.evidenceemitter.util.KeystoreManagement;
import no.difi.vefa.peppol.common.code.DigestMethod;
import no.difi.vefa.peppol.common.model.*;
import no.difi.vefa.peppol.evidence.jaxb.receipt.TransmissionRole;
import no.difi.vefa.peppol.evidence.rem.*;
import no.difi.vefa.peppol.sbdh.SbdReader;
import no.difi.vefa.peppol.sbdh.SbdWriter;
import org.holodeckb2b.common.util.Utils;
import org.holodeckb2b.common.workers.DirWatcher;
import org.holodeckb2b.common.workers.PathWatcher;

import org.holodeckb2b.interfaces.workerpool.TaskConfigurationException;

import java.io.*;
import java.security.cert.Certificate;
import java.security.*;
import java.util.*;

/**
 * Created by zelicj on 06/07/2017.
 */
public class EvidenceEmitter extends DirWatcher {
    // parameters
    private String scan_dir = null;
    private String output_dir = null;

    KeyStore.PrivateKeyEntry privateKeyEntry;

    //configuration
    private final static List<String> confirmDocumetInstanceIdList = Arrays.asList("http://uri.etsi.org/02640/soapbinding/v2#\":REMDispatch:2");
    private static final String scheme = "erds-gateway-id";
    private static final String issuerPolicyID = "http://ev_policyid.issuer.test/clause15";
    private static final String evidenceIssuer = "SETCCE";

    protected void onChange(File f, PathWatcher.Event event) {
        if (event != PathWatcher.Event.ADDED) {
            this.log.debug(event.toString().toLowerCase() + " " + f.getName() + " ignored");
            return;
        }

        String cFileName = f.getAbsolutePath();
        String proccesingFileName = cFileName + ".processingEvidence";
        String confirmedFileName = cFileName + ".confirmed";
        String outputFileName = output_dir + "/" + f.getName();

        try {
            renameFile(f, proccesingFileName);

            this.log.debug("Read meta data from " + f.getName());
            FileInputStream fi = new FileInputStream(proccesingFileName);
            SbdReader sr = SbdReader.newInstance(fi);
            Header header = sr.getHeader();

            String senderId =  header.getSender().getIdentifier();
            String receiverId =  header.getReceiver().getIdentifier();
            String documentType = header.getDocumentType().getIdentifier();
            String instanceId = null;

            this.log.debug("Sender Identifier: " + senderId);
            this.log.debug("Receiver Identifier: " + receiverId);
            this.log.debug("Document instance ID: " + instanceId);

            if (!confirmDocumetInstanceIdList.contains(documentType)) {
                renameFile(new File(proccesingFileName), confirmedFileName);
                return;
            }

            this.log.debug("Create REM Evidence");
            // create REM Evidence
            RemEvidenceService remEvidenceService = new RemEvidenceService();
            RemEvidenceBuilder builder = remEvidenceService.createDeliveryNonDeliveryToRecipientBuilder();
            builder.eventCode(EventCode.ACCEPTANCE)
                    .eventReason(EventReason.OTHER)
                    .eventTime(new Date())
                    .senderIdentifier(ParticipantIdentifier.of(senderId,Scheme.of(scheme)))
                    .recipientIdentifer(ParticipantIdentifier.of(receiverId,Scheme.of(scheme)))
                    .documentTypeId(DocumentTypeIdentifier.of(instanceId))
                    .instanceIdentifier(InstanceIdentifier.of("doc-type-instance-id"))
                    .documentTypeId(DocumentTypeIdentifier.of(documentType))
                    .instanceIdentifier(InstanceIdentifier.of(""))
                    .payloadDigest( "VGhpc0lzQVNIQTI1NkRpZ2VzdA==".getBytes())
                    .protocolSpecificEvidence(TransmissionRole.C_3,TransportProtocol.AS4,null)
            ;

            this.log.debug("Sign REM Evidence");
            SignedRemEvidence signedRemEvidence = builder.buildRemEvidenceInstance(privateKeyEntry);

            // transform Evidence to ByteArrayOutputStream
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            RemEvidenceTransformer remEvidenceTransformer = new RemEvidenceTransformer();
            remEvidenceTransformer.toFormattedXml(signedRemEvidence, byteArrayOutputStream);

            Header sbdHeader = getEvidenceHeader(header);
            this.log.debug("Write REM Evidence file to "+outputFileName);
//            OutputStream outputStream = new FileOutputStream(outputFileName);
//            byteArrayOutputStream.writeTo(outputStream);

            sbdhWrapAndWrite(sbdHeader);

            // rename input file
            renameFile(new File(proccesingFileName), confirmedFileName);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setParameters(Map<String, ?> parameters) throws TaskConfigurationException {
        super.setParameters(parameters);

        this.output_dir = ((String)parameters.get("outputPath"));
        if (Utils.isNullOrEmpty(this.output_dir)) {
            throw new TaskConfigurationException("You must provide the \"outputPath\" parameter!");
        }
        this.scan_dir = ((String)parameters.get("watchPath"));
        if (Utils.isNullOrEmpty(this.scan_dir)) {
            throw new TaskConfigurationException("You must provide the \"watchPath\" parameter!");
        }
        String keystore = ((String)parameters.get("keyStore"));
        if (Utils.isNullOrEmpty(keystore)) {
            throw new TaskConfigurationException("You must provide the \"keyStore\" parameter!");
        }
        String keyStorePassword = ((String)parameters.get("keyStorePassword"));
        if (Utils.isNullOrEmpty(keystore)) {
            throw new TaskConfigurationException("You must provide the \"keyStorePassword\" parameter!");
        }
        String keyPairAlias = ((String)parameters.get("keyPairAlias"));
        if (Utils.isNullOrEmpty(keystore)) {
            throw new TaskConfigurationException("You must provide the \"keyPairAlias\" parameter!");
        }

        try {
            KeyStore ks = KeystoreManagement.loadKeyStore(new File(keystore),
                    keyStorePassword,
                    "JKS");
            log.debug("Loaded keystore with aliases "+enumerationToString(ks.aliases()));
            KeyPair kp = KeystoreManagement.getKeyPair(ks,keyPairAlias,keyStorePassword);
            Certificate[] chain = new Certificate[1];
            chain[0] = ks.getCertificate(keyPairAlias);
            log.debug("Loaded keypair with certificate "+chain[0].toString());
            this.privateKeyEntry = new KeyStore.PrivateKeyEntry(kp.getPrivate(),chain);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


        this.log.info("Initialized SETCCE Evidence Emitter using parameters:\n\tWatched directory : " + this.scan_dir + "\n\tFile Extension: " + parameters.get("extension") + "\n\tOutput directory: " + this.output_dir);
    }

    private Header getEvidenceHeader(Header rh)  {

        // swap sender and receiver
        Header header = Header.of(
                ParticipantIdentifier.of("9908:987654321"), // sender
                ParticipantIdentifier.of("9908:123456789"),  // receiver
                ProcessIdentifier.of("urn:www.cenbii.eu:profile:bii04:ver1.0"),
                DocumentTypeIdentifier.of("aa"),
                InstanceIdentifier.generateUUID(),
                InstanceType.of("http://uri.etsi.org/02640/soapbinding/v2#","REMEvidence","2"),
                new Date()
        );

        return header;
    }

    /** Wraps the ASiC archive supplied in the "inputStream" into a SBD, with the supplied SBDH */
    private void sbdhWrapAndWrite(Header header) throws Exception {
        File outputFile = File.createTempFile("evidence", ".xml", new File(output_dir));
        FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

        SbdWriter sbdWriter = SbdWriter.newInstance(fileOutputStream, header);

        log.debug("Wrote sample StandardBusinessDocument into " + outputFile.toString());
    }

    private void renameFile(File f, String proccesingFileName) throws IOException{
        if (!f.renameTo(new File(proccesingFileName))) {
            this.log.error(f.getName() + " is not processed because it could be renamed");
            throw new IOException(f.getName() + " is not processed because it could be renamed");
        }
    }

    private String enumerationToString(Enumeration en) {
        String rv="[";
        while (en.hasMoreElements()) {
            String el = (String) en.nextElement();
            rv +=el+",";
        }
        if (rv.length()<1)
            return rv.replace((char) (rv.length()-2), ']');
        return rv + "]";
    }
}

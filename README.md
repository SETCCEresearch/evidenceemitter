Evidence emitter for noble project

Evidence emitter is a plugin for holodeckb2b

You can include evidence emitter into holodeckb2b by adding folowing to workers.xml:

    <worker name="EvidenceEmitterWorker" interval="10" activate="true"
        workerClass="com.setcce.evidenceemitter.EvidenceEmitter">
        <parameter name="watchPath">data/sbd_in</parameter>
        <parameter name="extension">xml</parameter>
        <parameter name="outputPath">data/sbd_out</parameter>
        <parameter name="keyStore">/opt/holodeck-b2b-2.1.2-wp54/repository/certs/privatekeys.jks</parameter>
        <parameter name="keyStorePassword">secrets</parameter>
        <parameter name="keyPairAlias">generalerds_ap_test_setcce</parameter>

    </worker>

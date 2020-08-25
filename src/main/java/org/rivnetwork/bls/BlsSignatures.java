package org.rivnetwork.bls;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import static org.rivnetwork.utils.HashUtils.hash;

import java.util.ArrayList;

import org.rivnetwork.bls.model.BlsModel;
import org.rivnetwork.bls.model.Signature;
/**
 * Created by Ilya Gazman on 2/3/2018.
 */
public class BlsSignatures {

    private Pairing pairing = BlsModel.instance.pairing;
    private Element systemParameters = BlsModel.instance.systemParameters;
    private ArrayList<Signature> signatures = new ArrayList<>();

    public Signature sign(byte[] message, byte[] privateKey) {
        Element secretKey = pairing.getZr().newElementFromBytes(privateKey);
        Element publicKey = systemParameters.duplicate().powZn(secretKey);


        byte[] hash = hash(message, publicKey);
        Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);

        Element signatureElement = h.powZn(secretKey);

        Signature signature = new Signature();
        signature.message = message;
        signature.publicKey = publicKey;
        signature.signature = signatureElement;
        return signature;
    }

    public void addSignature(Signature signature) {
        signatures.add(signature);
    }

    public boolean validate() {
        Element compactSignature = signatures.get(0).signature.duplicate();
        for (int i = 1; i < signatures.size(); i++) {
            compactSignature = compactSignature.mul(signatures.get(i).signature);
        }
        Element compactPairing = pairing.pairing(compactSignature, systemParameters.duplicate());

        byte[] hash0 = hash(signatures.get(0).message, signatures.get(0).publicKey);
        Element hashElement0 = pairing.getG1().newElementFromHash(hash0, 0, hash0.length);
        Element fullPairing = pairing.pairing(hashElement0, signatures.get(0).publicKey);
        for (int i = 1; i < signatures.size(); i++) {
            byte[] messageHash = hash(signatures.get(i).message, signatures.get(i).publicKey);

            Element hashElement = pairing.getG1().newElementFromHash(messageHash, 0, messageHash.length);
            Element publicKey = signatures.get(i).publicKey;
            Element p = pairing.pairing(hashElement, publicKey);
            fullPairing.mul(p);
        }

        return compactPairing.isEqual(fullPairing);
    }
}

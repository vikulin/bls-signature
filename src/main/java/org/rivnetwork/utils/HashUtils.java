package org.rivnetwork.utils;

import it.unisa.dia.gas.jpbc.Element;

import java.nio.ByteBuffer;

import org.rivnetwork.bls.utils.Sha256Hash;

public class HashUtils {

    public static byte[] hash(byte[] message, Element publicKey) {
        byte[] bytes1 = Sha256Hash.hash(message);
        byte[] bytes2 = publicKey.toBytes();
        ByteBuffer buffer = ByteBuffer.allocate(bytes1.length + bytes2.length);
        buffer.put(bytes1);
        buffer.put(bytes2);

        return Sha256Hash.hash(buffer.array());
    }

}

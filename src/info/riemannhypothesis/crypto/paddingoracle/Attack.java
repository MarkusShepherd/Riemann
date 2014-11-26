package info.riemannhypothesis.crypto.paddingoracle;

import info.riemannhypothesis.crypto.paddingoracle.Connection.Response;
import info.riemannhypothesis.crypto.tools.BlockSequence;
import info.riemannhypothesis.crypto.tools.ByteSequence;

import java.io.IOException;
import java.io.PrintStream;

public class Attack {

    public static final String baseURL = "http://crypto-class.appspot.com/po?er=";

    private final Connection   connection;

    public Attack(Connection connection) {
        this.connection = connection;
    }

    public ByteSequence decrypt(ByteSequence cipher, int blockLength) {
        return decrypt(cipher, blockLength, null);
    }

    public ByteSequence decrypt(ByteSequence cipher, int blockLength,
            PrintStream ps) {
        ByteSequence bytes = cipher;
        ByteSequence plain = ByteSequence.EMPTY_SEQUENCE;
        BlockSequence blocks = new BlockSequence(blockLength, bytes);

        for (int i = 1; i < blocks.length(); i++) {
            ByteSequence iv = blocks.blockAt(i - 1);
            ByteSequence block = blocks.blockAt(i);
            boolean lastBlock = (i == blocks.length() - 1);
            try {
                ByteSequence plainBlock = decryptBlock(iv, block, ps);
                if (lastBlock) {
                    byte paddingLength = plainBlock
                            .byteAt(plainBlock.length() - 1);
                    if (paddingLength < 1 || paddingLength > blockLength) {
                        throw new Exception("Incorrect padding");
                    }
                    for (int pos = 1; pos < paddingLength; pos++) {
                        if (plainBlock.byteAt(plainBlock.length() - 1 - pos) != paddingLength) {
                            throw new Exception("Incorrect padding");
                        }
                    }
                    plainBlock = plainBlock.range(0, plainBlock.length()
                            - paddingLength);
                }
                if (ps != null) {
                    ps.println("The decryption of block " + i + " is: "
                            + plainBlock.toString());
                }
                plain = plain.append(plainBlock);
            } catch (Exception e) {
                if (ps != null) {
                    ps.print("There was an error: " + e.getMessage());
                    e.printStackTrace(ps);
                } else {
                    e.printStackTrace();
                }
            }
        }
        return plain;
    }

    public static void main(String[] args) throws IOException {

        int c = 0;

        String cipherStr = args[c];
        ByteSequence cipher = ByteSequence.fromHexString(cipherStr);
        int blockLength = Integer.parseInt(args[++c], 10);

        Connection connection = null;
        if ("http".equals(args[++c])) {
            connection = new HttpConnection(args[++c]);
        } else if ("socket".equals(args[c])) {
            connection = new SocketConnection(args[++c], Integer.parseInt(
                    args[++c], 10), blockLength);
        } else {
            System.out.println("Unknown connection type: " + args[c]);
            return;
        }

        PrintStream ps = System.out;
        if (args.length > ++c && !"-".equals(args[c])) {
            ps = new PrintStream(args[c]);
        }

        Attack attack = new Attack(connection);
        ByteSequence plain = attack.decrypt(cipher, blockLength, ps);

        System.out.println("Plaintext: " + plain.toString());
        System.out.println("Plaintext (hex): " + plain.toHexString());

        connection.close();
    }

    private ByteSequence decryptBlock(ByteSequence iv, ByteSequence cipher,
            PrintStream ps) throws IOException {
        ByteSequence plain = new ByteSequence(new byte[cipher.length()]);
        boolean wrongGuess = false;
        byte avoidGuess = 0;
        for (int pos = cipher.length() - 1, pad = 1; pos >= 0; pos--, pad++) {
            ByteSequence attack = iv.append(cipher);
            boolean foundGuess = false;
            for (int guess = 0; guess < 256; guess++) {
                if (wrongGuess && guess == avoidGuess) {
                    if (ps != null) {
                        ps.println("Skipped; pos: " + pos + "; pad: " + pad
                                + "; guess: " + guess);
                    }
                    continue;
                }
                byte subs = (byte) (iv.byteAt(pos) ^ guess ^ pad);
                attack.setByteAt(pos, subs);
                for (int i = 1; i < pad; i++) {
                    subs = (byte) (iv.byteAt(pos + i) ^ plain.byteAt(pos + i) ^ pad);
                    attack.setByteAt(pos + i, subs);
                }
                Response response = connection.send(attack);

                if (ps != null) {
                    ps.println("pos: " + pos + "; pad: " + pad + "; guess: "
                            + guess + "; attack: " + attack.toHexString()
                            + "; reponse: " + response);
                }
                if (response != Response.SUCCESS) {

                    if (ps != null) {
                        ps.println("Character at position " + pos + ": "
                                + guess);
                    }
                    plain.setByteAt(pos, (byte) guess);
                    wrongGuess = false;
                    foundGuess = true;
                    break;
                }
            }
            if (!foundGuess) {

                if (ps != null) {
                    ps.println("Found no matching guess, will go back one step; pos: "
                            + pos + "; pad: " + pad);
                }
                wrongGuess = true;
                avoidGuess = plain.byteAt(pos + 1);
                pos += 2;
                pad -= 2;
            }
        }
        return plain;
    }
}

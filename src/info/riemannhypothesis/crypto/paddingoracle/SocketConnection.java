package info.riemannhypothesis.crypto.paddingoracle;

import info.riemannhypothesis.crypto.tools.ByteSequence;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 * @author Markus Schepke
 * @date 25 Nov 2014
 */
public class SocketConnection extends Connection {

    private final int            blockLength;

    private final Socket         socket;
    private final OutputStream   out;
    private final BufferedReader in;

    /**
     * @throws IOException
     * @throws UnknownHostException
     * 
     */
    public SocketConnection(String hostname, int port, int blockLength)
            throws UnknownHostException, IOException {
        socket = new Socket(hostname, port);
        out = socket.getOutputStream();
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.blockLength = blockLength;
    }

    @Override
    public Response send(ByteSequence message) {
        if (message.length() % blockLength != 0) {
            throw new IllegalArgumentException();
        }
        byte num_blocks = (byte) (message.length() / blockLength);
        message = message.prepend(num_blocks).append((byte) 0);

        char recvbit[] = new char[2];
        try {
            out.write(message.getByteArray());
            out.flush();
            in.read(recvbit, 0, 2);
            int response = Integer.valueOf(new String(recvbit).replaceAll("\0",
                    ""));
            return response == 0 ? Response.SUCCESS : Response.FAIL;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Response.FAIL;
    }

    private int disconnect() {
        try {
            socket.close();
            return 0;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return -1;
    }

    @Override
    protected void finalize() throws Throwable {
        disconnect();
        super.finalize();
    }

    @Override
    public boolean close() {
        return disconnect() == 0;
    }

}

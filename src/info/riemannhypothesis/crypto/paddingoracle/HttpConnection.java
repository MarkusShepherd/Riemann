package info.riemannhypothesis.crypto.paddingoracle;

import info.riemannhypothesis.crypto.tools.ByteSequence;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * @author Markus Schepke
 * @date 25 Nov 2014
 */
public class HttpConnection extends Connection {

    private final String baseURL;

    public HttpConnection(String baseURL) {
        this.baseURL = baseURL;
    }

    @Override
    public Response send(ByteSequence message) {
        try {
            URL url = new URL(baseURL + message.toHexString());
            HttpURLConnection connection = (HttpURLConnection) url
                    .openConnection();
            connection.setRequestMethod("GET");
            connection.connect();
            int response = connection.getResponseCode();
            connection.disconnect();
            return response == 403 ? Response.SUCCESS : Response.FAIL;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Response.FAIL;
    }

    @Override
    public boolean close() {
        return true;
    }
}

package net.i2p.i2ptunnel.util;

import java.io.IOException;
import java.io.InputStream;

import net.i2p.data.DataHelper;

/**
 * Read the first line unbuffered.
 * After that, switch to a BufferedReader, unless the method is "POST".
 * We can't use BufferedReader for POST because we can't have readahead,
 * since we are passing the stream on to I2PTunnelRunner for the POST data.
 *
 * Warning - BufferedReader removes \r, DataHelper does not
 * Warning - DataHelper limits line length, BufferedReader does not
 * Todo: Limit line length for buffered reads, or go back to unbuffered for all
 */
public class InputReader {
    InputStream _s;

    public InputReader(InputStream s) {
        _s = s;
    }

    public String readLine(String method) throws IOException {
        // Use unbuffered until we can find a BufferedReader that limits line length
        // if (method == null || "POST".equals(method))
        return DataHelper.readLine(_s);
        // if (_br == null)
        // _br = new BufferedReader(new InputStreamReader(_s, "ISO-8859-1"));
        // return _br.readLine();
    }

    /**
     * Read the rest of the headers, which keeps firefox
     * from complaining about connection reset after
     * an error on the first line.
     *
     * @since 0.9.14
     */
    public void drain() {
        try {
            String line;
            do {
                line = DataHelper.readLine(_s);
                // \r not stripped so length == 1 is empty
            } while (line != null && line.length() > 1);
        } catch (IOException ioe) {
        }
    }
}

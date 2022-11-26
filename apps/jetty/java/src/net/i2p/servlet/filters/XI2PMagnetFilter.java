package net.i2p.servlet.filters;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.i2p.I2PAppContext;
import net.i2p.I2PException;
import net.i2p.data.DataHelper;
import net.i2p.data.Destination;
import net.i2p.data.PrivateKeyFile;
import net.i2p.util.Log;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.HandlerWrapper;

public class XI2PMagnetFilter extends XI2PHeaderFilter {
  private static final long failTimeout = 600000;

  public XI2PMagnetFilter() {
    super(failTimeout);
    headerKey = "X-I2P-Magnet";
    applyToI2P = true;
  }

  /**
   * getCachableHeader creates a torrent from a file to be served, generates a
   * magnet link, and caches it.
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return the data to cache
   *
   */
  public synchronized String getCachableHeader(
      final HttpServletRequest httpRequest, final Request request) {
    if (isFromI2P(httpRequest)) {
      return null;
    }
    return null;
  }

  /**
   * headerContents computes the magnet link and appends the webseed, which is
   * the value to the X-I2P-Magnet key.
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return the full header
   *
   */
  public synchronized String
  headerContents(final HttpServletRequest httpRequest, final Request request) {
    if (cachedHeader != null) {
      return null;
    }
    return null;
  }
}

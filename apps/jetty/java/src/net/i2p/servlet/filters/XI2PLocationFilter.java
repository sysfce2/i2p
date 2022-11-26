package net.i2p.servlet.filters;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.i2p.I2PAppContext;
import net.i2p.util.Log;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.HandlerWrapper;

/**
 * Adds a header, X-I2P-Location, to requests when they do **not** come in on an
 * I2P hostname. This header contains a URL that looks like:
 * [scheme://][i2phostname.i2p][/path][?query] and expresses the I2P-Equivalent
 * URL of the clearnet query. Clients can use this to prompt users to switch
 * from a non-I2P host to an I2P host or to redirect them automatically. It
 * automatically enabled on the default I2P site located on port 7658 by
 * default.
 *
 *  @since 0.9.51
 */
public class XI2PLocationFilter extends XI2PHeaderFilter {
  private static final long failTimeout = 600000;

  public XI2PLocationFilter() {
    super(failTimeout);
    headerKey = "X-I2P-Location";
    applyToClearnet = true;
  }

  private synchronized String getXI2PLocation(String host, String port) {
    String sh = getSpoofedHostname(host, port);
    if (sh != null) {
      return sh;
    }
    Destination destination = getTunnelDestination(host, port);
    if (destination != null) {
      return destination.toBase32();
    }
    return null;
  }

  public synchronized String getCachableHeader(
      final HttpServletRequest httpRequest, final Request request) {
    return getXI2PLocation(request.getLocalAddr(),
                           String.valueOf(request.getLocalPort()));
  }

  public synchronized String
  headerContents(final HttpServletRequest httpRequest, final Request request) {
    if (cachedHeader != null) {
      String scheme = httpRequest.getScheme();
      if (scheme == null) {
        scheme = "";
      }
      String path = httpRequest.getPathInfo();
      if (path == null) {
        path = "";
      }
      String query = httpRequest.getQueryString();
      if (query == null) {
        query = "";
      }
      try {
        if (query.equals("")) {
          URI uri = new URI(scheme, cachedHeader, path, null);
          String encodedURL = uri.toASCIIString();
          return encodedURL;
        } else {
          URI uri = new URI(scheme, cachedHeader, path, query, null);
          String encodedURL = uri.toASCIIString();
          return encodedURL;
        }
      } catch (URISyntaxException use) {
        return null;
      }
    }
    return null;
  }
}

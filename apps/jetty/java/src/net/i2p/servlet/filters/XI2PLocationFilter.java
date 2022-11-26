package net.i2p.servlet.filters;

import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.i2p.data.Destination;
import org.eclipse.jetty.server.Request;

/**
 * Adds a header, X-I2P-Location, to requests when they do **not** come in on an
 * I2P hostname. This header contains a URL that looks like:
 * 
 * [scheme://][i2phostname.i2p][/path][?query]
 *
 * This expresses the I2P-Equivalent URL of the clearnet query. Clients can use
 * this to prompt users to switch from a non-I2P host to an I2P host or to
 * redirect them automatically. It automatically enabled on the default I2P site
 * located on port 7658 by default.
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

  /**
   * getCachableHeader obtains the spoofed hostname or the base32 from
   * the tunnel configuration and caches it.
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return the data to cache
   *
   */
  public synchronized String getCachableHeader(
      final HttpServletRequest httpRequest, final Request request) {
    return getXI2PLocation(request.getLocalAddr(),
                           String.valueOf(request.getLocalPort()));
  }

  /**
   * headerContents computes the addresshelper which is the value to the
   * X-I2P-Hostname key.
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return the full header
   *
   */
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

package net.i2p.servlet.filters;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.i2p.data.Destination;
import org.eclipse.jetty.server.Request;

/**
 * Adds a header, X-I2P-Hostname, to requests when they come from inside of
 * I2P. This header contains a valid addresshelper and can be used to indicate
 * the preferred human-readable hostname for the site without resorting to a
 * jump service or adding the hostname to a subscription feed. Uses the
 * spoofed hostname to configure the hostname, and the base64 destination as
 * the bases of the addresshelper.
 *
 *  @since 0.9.57
 */
public class XI2PHostnameFilter extends XI2PHeaderFilter {
  private static final long failTimeout = 600000;

  public XI2PHostnameFilter() {
    super(failTimeout);
    headerKey = "X-I2P-Hostname";
    applyToI2P = true;
  }

  /**
   * getCachableHeader obtains the base64 of the tunnel by loading the keys from
   * the tunnel config file, and stores it in the cachedHeader
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return the data to cache
   *
   */
  public synchronized String getCachableHeader(
      final HttpServletRequest httpRequest, final Request request) {
    if (isFromI2P(httpRequest)) {
      Destination destination = getTunnelDestination(
          request.getLocalAddr(), String.valueOf(request.getLocalPort()));
      if (destination != null) {
        return destination.toBase64();
      }
    }
    return null;
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
      String spoofedHostname = getSpoofedHostname(
          request.getLocalAddr(), String.valueOf(request.getLocalPort()));
      if (spoofedHostname == null) {
        return null;
      }
      String scheme = httpRequest.getScheme();
      if (scheme == null) {
        scheme = "http://";
      }
      return scheme + spoofedHostname + "?i2paddresshelper=" + cachedHeader;
    }
    return null;
  }
}

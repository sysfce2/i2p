package net.i2p.servlet.filters;

// import java.net.URI;
// import java.net.URISyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.i2p.data.Destination;
import org.eclipse.jetty.server.Request;

/**
 * Adds a header, X-I2P-Magnet, to requests when they come in on an I2P
 * hostname. This header contains a link that looks like:
 *
 *   [magnet:]?[xt=urn:btih:[BT_INFO_HASH]]&[tr=[BT_TRACKER_URL]]&[ws=[WEBSEED_PAYLOAD_URL]]
 *
 * This corresponds to a torrent where the content is exactly the file being
 * served, and the webseed URL corresponds exactly to the I2P URL of the
 * request. The torrent is structured thus:
 *
 *   [hostname || base32]/[path/to/url]
 *
 * This can be useful for 2 things in particular:
 *
 * 1. A user who wishes to mirror the I2P site can use the header to keep the
 * mirror up-to-date infohash changes, file has changed, delete the old one and
 * participate in the new swarm
 * 2. A user who uses an HTTP client which has insight into the torrent
 * client(Such as I2P in Private Browsing) can optionally replace in-I2P
 * resources with locally-cached resources from the corresponding I2P torrent.
 *
 * This allows sites to be more "Permanent" by spreading their files across
 * the users, making the files themselves resistant to takedown, and if widely
 * adopted, would reduce the bandwidth used for serving files over I2P. It may
 * also cause the downloads to appear differently than HTTP downloads, being
 * more loosely clustered and out-of-order.
 *
 *  @since 0.9.57
 */
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

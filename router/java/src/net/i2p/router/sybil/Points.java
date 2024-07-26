package net.i2p.router.sybil;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.i2p.data.DataHelper;

/**
 * A total score and a List of reason Strings
 *
 * @since 0.9.38 moved from SybilRenderer
 */
public class Points implements Comparable<Points> {
    private final Map<String, Double> reasons;

    public static final String REASON_NON_FLOODFILL = "Non-floodfill: ";
    public static final String REASON_TOO_CLOSE = "Very close: ";
    public static final String REASON_ALWAYS_FAIL_LOOKUP = "Lookup fail rate: ";
    public static final String REASON_UNREACHABLE = "Unreachable: ";

    public static final String REASON_BAD_VERSION = "Strange Version: ";
    public static final String REASON_OLD_VERSION = "Old Version: ";

    public static final String REASON_MY_FAMILY = "Our family: ";
    public static final String REASON_SPOOFED_MY_FAMILY = "Spoofed my family: ";
    public static final String REASON_KNOWN_FAMILY = "Verified family: ";
    public static final String REASON_INVALID_FAMILY = "Invalid family: ";
    public static final String REASON_VALID_FAMILY = "Valid Unverified family: ";

    public static final String REASON_SAME_IP4 = "Same IPv4: ";
    public static final String REASON_SAME_IP4_16 = "Same IPv4/16: ";
    public static final String REASON_SAME_IP4_24 = "Same IPv4/24: ";

    public static final String REASON_SAME_IP6 = "Same IPv6: ";
    public static final String REASON_SAME_IP6_48 = "Same IPv6/48: ";
    public static final String REASON_SAME_IP6_64 = "Same IPv6/64: ";

    public static final String REASON_BANLISTED = "Banlisted: ";
    public static final String REASON_CONTACT = "First Heard About: ";

    /**
     * @since 0.9.38
     */
    private Points() {
        reasons = new ConcurrentHashMap<String, Double>(4);
    }

    /**
     * @param reason may not contain '%' or '\t'
     */
    public Points(double d, String reason) {
        this();
        addPoints(d, reason);
    }

    /**
     * Compare 2 reason strings by comparing them to the list of static constants above.
     * Ignores anything following the `:` when comparing the strings.
     *
     * @param comparator
     * @param base
     * @return
     */
    public static boolean compareReason(String comparator, String base) {
        String[] comparatorPrefix = DataHelper.split(comparator, ":");
        String[] basePrefix = DataHelper.split(base, ":");
        if (comparatorPrefix == null)
            return false;
        if (basePrefix == null)
            return false;
        return basePrefix[0].toLowerCase().equals(comparatorPrefix[0].toLowerCase());
    }

    private double points() {
        double rv = 0;
        for (String reason : reasons.keySet()) {
            rv += reasons.get(reason);
        }
        return rv;
    }

    /**
     * @since 0.9.38
     */
    public double getPoints() {
        return points();
    }

    /**
     * @since 0.9.38
     */
    public Map<String, Double> getReasons() {
        return reasons;
    }

    /**
     * @param reason may not contain '%' or '\t'
     * @since 0.9.38
     */
    public void addPoints(double d, String reason) {
        DecimalFormat format = new DecimalFormat("#0.00");
        String rsn = format.format(d) + ": " + reason;
        Double rp = reasons.get(rsn);
        if (rp == null) {
            // reason was not yet present in the map, create a new entry for it.
            reasons.put(rsn, d);
        } else {
            // reason was present in the map, add the points to it.
            rp += d;
        }
    }

    public int compareTo(Points r) {
        return Double.compare(points(), r.points());
    }

    /**
     * @since 0.9.38
     */
    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder(128);
        toString(buf);
        return buf.toString();
    }

    /**
     * For persistence.
     * points and reasons, '%' separated, new line between pairs.
     * The separation character is chosen to not conflict with
     * decimal point in various locales, or chars in reasons, including HTML links,
     * or special chars in Pattern.
     *
     * Format changed in 0.9.64
     *
     * @since 0.9.38
     */
    public void toString(StringBuilder buf) {
        for (String r : reasons.keySet()) {
            buf.append(reasons.get(r)).append('%').append(r.replace("%", "&#x25;")).append("\t");
        }
    }

    /**
     * For persistence.
     *
     * @return null on failure
     * @since 0.9.38
     */
    public static Points fromString(String s) {
        Points rv = new Points();
        for (String lineString : DataHelper.split(s, "\t")) {
            String[] ss = DataHelper.split(lineString, "%");
            if (ss.length != 2)
                return null;
            double d;
            try {
                d = Double.parseDouble(ss[0]);
            } catch (NumberFormatException nfe) {
                return null;
            }
            rv.reasons.put(ss[1], d);
        }
        return rv;
    }
}

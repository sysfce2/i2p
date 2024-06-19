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

    /**
     * @since 0.9.38
     */
    private Points() {
        reasons = new ConcurrentHashMap<String, Double>(4);
    }

    /**
     * @param reason may not contain '%'
     */
    public Points(double d, String reason) {
        this();
        addPoints(d, reason);
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
     * @param reason may not contain '%'
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
            buf.append(reasons.get(r)).append('%').append(r.replace("%", "&#x25;")).append("\n");
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
        for (String lineString : DataHelper.split(s, "\n")) {
            String[] ss = DataHelper.split(s, "%");
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

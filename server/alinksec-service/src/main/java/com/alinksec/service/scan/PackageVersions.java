package com.alinksec.service.scan;

/** Package-manager ordering of complete versions, without an upstream-version fallback. */
public final class PackageVersions {
    private PackageVersions() {}

    private record Version(String epoch, String upstream, String revision) {}

    public static int compare(String source, String left, String right) {
        Version a = parse(source, left), b = parse(source, right);
        int epoch = numeric(a.epoch(), b.epoch());
        if (epoch != 0) return epoch;
        int version = component(source, a.upstream(), b.upstream());
        return version != 0 ? version : component(source, a.revision(), b.revision());
    }

    public static boolean inRange(String source, String version, String range) {
        parse(source, version);
        if (range == null || range.isBlank() || "*".equals(range)) return true;
        String expression = range.trim();
        String op = expression.startsWith(">=") ? ">=" : expression.startsWith("<=") ? "<="
                : expression.startsWith(">") ? ">" : expression.startsWith("<") ? "<"
                : expression.startsWith("=") ? "=" : "";
        int comparison = compare(source, version, expression.substring(op.length()).trim());
        return switch (op) {
            case ">=" -> comparison >= 0;
            case "<=" -> comparison <= 0;
            case ">" -> comparison > 0;
            case "<" -> comparison < 0;
            default -> comparison == 0;
        };
    }

    private static Version parse(String source, String value) {
        if (!"rpm".equals(source) && !"dpkg".equals(source)) throw invalid();
        if (value == null || value.isEmpty() || value.length() > 255) throw invalid();
        String epoch = "0", body = value;
        int colon = value.indexOf(':');
        if (colon >= 0) {
            epoch = value.substring(0, colon);
            if (epoch.isEmpty() || !epoch.chars().allMatch(c -> c >= '0' && c <= '9')) throw invalid();
            body = value.substring(colon + 1);
            if ("dpkg".equals(source) && numeric(epoch, "2147483647") > 0) throw invalid();
        }
        int dash = body.lastIndexOf('-');
        String upstream = dash < 0 ? body : body.substring(0, dash);
        String revision = dash < 0 ? ("dpkg".equals(source) ? "0" : "") : body.substring(dash + 1);
        if (upstream.isEmpty() || (dash >= 0 && revision.isEmpty())) throw invalid();
        if ("dpkg".equals(source)) {
            if (!digit(upstream.charAt(0)) || !upstream.matches("[A-Za-z0-9.+~:-]+")
                    || !revision.matches("[A-Za-z0-9.+~]+")) throw invalid();
        } else if (!upstream.matches("[A-Za-z0-9._+~^]+")
                || (dash >= 0 && !revision.matches("[A-Za-z0-9._+~^]+"))) {
            throw invalid();
        }
        return new Version(epoch, upstream, revision);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Unsupported package version or source");
    }

    private static int component(String source, String a, String b) {
        return "dpkg".equals(source) ? debian(a, b) : rpm(a, b);
    }

    private static int numeric(String a, String b) {
        int ia = 0, ib = 0;
        while (ia < a.length() && a.charAt(ia) == '0') ia++;
        while (ib < b.length() && b.charAt(ib) == '0') ib++;
        int length = Integer.compare(a.length() - ia, b.length() - ib);
        return length != 0 ? length : Integer.signum(a.substring(ia).compareTo(b.substring(ib)));
    }

    private static boolean digit(char c) { return c >= '0' && c <= '9'; }
    private static boolean alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
    private static char at(String s, int i) { return i < s.length() ? s.charAt(i) : 0; }

    private static int debianOrder(char c) {
        if (c == '~') return -1;
        if (c == 0 || digit(c)) return 0;
        return alpha(c) ? c : c + 256;
    }

    private static int debian(String a, String b) {
        int ia = 0, ib = 0;
        while (ia < a.length() || ib < b.length()) {
            while ((at(a, ia) != 0 && !digit(at(a, ia))) || (at(b, ib) != 0 && !digit(at(b, ib)))) {
                int order = Integer.compare(debianOrder(at(a, ia)), debianOrder(at(b, ib)));
                if (order != 0) return order;
                if (ia < a.length()) ia++;
                if (ib < b.length()) ib++;
            }
            int startA = ia, startB = ib;
            while (digit(at(a, ia))) ia++;
            while (digit(at(b, ib))) ib++;
            int number = numeric(a.substring(startA, ia), b.substring(startB, ib));
            if (number != 0) return number;
        }
        return 0;
    }

    private static int rpm(String a, String b) {
        int ia = 0, ib = 0;
        while (ia < a.length() || ib < b.length()) {
            while (at(a, ia) != 0 && !alpha(at(a, ia)) && !digit(at(a, ia)) && at(a, ia) != '~' && at(a, ia) != '^') ia++;
            while (at(b, ib) != 0 && !alpha(at(b, ib)) && !digit(at(b, ib)) && at(b, ib) != '~' && at(b, ib) != '^') ib++;
            char ca = at(a, ia), cb = at(b, ib);
            if (ca == '~' || cb == '~') {
                if (ca != '~') return 1;
                if (cb != '~') return -1;
                ia++; ib++; continue;
            }
            if (ca == '^' || cb == '^') {
                if (ca == 0) return -1;
                if (cb == 0) return 1;
                if (ca != '^') return 1;
                if (cb != '^') return -1;
                ia++; ib++; continue;
            }
            if (ca == 0 || cb == 0) return Integer.compare(ca == 0 ? 0 : 1, cb == 0 ? 0 : 1);
            boolean digits = digit(ca);
            if (digits != digit(cb)) return digits ? 1 : -1;
            int startA = ia, startB = ib;
            while (digits ? digit(at(a, ia)) : alpha(at(a, ia))) ia++;
            while (digits ? digit(at(b, ib)) : alpha(at(b, ib))) ib++;
            String segmentA = a.substring(startA, ia), segmentB = b.substring(startB, ib);
            int order = digits ? numeric(segmentA, segmentB) : Integer.signum(segmentA.compareTo(segmentB));
            if (order != 0) return order;
        }
        return 0;
    }
}

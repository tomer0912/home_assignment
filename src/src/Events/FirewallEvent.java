package src.Events;

public class FirewallEvent {
    String src;
    String dst;
    String domain;
    String user;

    public FirewallEvent(String line) {
        String[] parts = line.split(" ");

        for (String part : parts) {
            if (part.startsWith("SRC")) {
                String[] src = part.split("=");
                this.src = src[1];
            }
            if (part.startsWith("DST")) {
                String[] dst = part.split("=");
                this.dst = dst[1];
            }
            if (part.startsWith("DOMAIN")) {
                String[] domain = part.split("=");
                this.domain = domain[1];
            }
            if (part.startsWith("USER")) {
                String[] user = part.split("=");
                this.user = user[1];
            }
        }

    }

    public String getDomain() {
        return domain;
    }

    public String getDst() {
        return dst;
    }

    public String getSrc() {
        return src;
    }

    public String getUser() {
        return user;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String toString() {
        return src + " " + dst + " " + domain + " " + user;
    }
}

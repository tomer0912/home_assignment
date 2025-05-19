package src.CloudServices;

public class CloudService {
    String name;
    String domain;
    String risk;
    String country;
    boolean GDPR;

    public CloudService(String name, String domain, String risk, String country, boolean GDPR) {
        this.name = name;
        this.domain = domain;
        this.risk = risk;
        this.country = country;
        this.GDPR = GDPR;
    }

    public String toString() {
        return name + " " + domain + " " + risk + " " + country + " " + GDPR;
    }
}

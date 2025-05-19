package src.Enrich;

import Events.FirewallEvent;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class EventEnricher {
    LRUCache<String, String> cache;

    public EventEnricher() {
        this.cache = new LRUCache<>(10000);
    }

    public void enrich(FirewallEvent event){
        if (event.getDomain() == null){
            String dst = event.getDst();
            if(cache.get(dst) == null){
                String domain = EventEnricher.ReverseDNSLookup(dst);
                cache.put(dst, domain);
            }
            event.setDomain(cache.get(dst));
        }
    }

    public static String ReverseDNSLookup(String ipAddress) {
        try {
            InetAddress inetAddress = InetAddress.getByName(ipAddress);
            String hostName = inetAddress.getCanonicalHostName(); // or getHostName()
            return hostName;
        } catch (UnknownHostException e) {
            System.out.println("Unable to resolve hostname for IP: " + ipAddress);
        }

        return null;
    }
}

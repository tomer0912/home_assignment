package src.Filter;

import Events.FirewallEvent;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class EventFilter {
    IpIncludeFilter includeFilter;
    ExcludeIpsFilter excludeIpsFilter;
    UsersIncludeFilter usersIncludeFilter;
    UsersExcludeFilter usersExcludeFilter;

    public EventFilter(String[] includeIps, String[] excludeIps, String includeUsers, String excludeUsers) {
        this.includeFilter = new IpIncludeFilter(includeIps);
        this.excludeIpsFilter = new ExcludeIpsFilter(excludeIps);
        this.usersIncludeFilter = new UsersIncludeFilter(includeUsers);
        this.usersExcludeFilter = new UsersExcludeFilter(excludeUsers);
    }

    public boolean shouldProcess(FirewallEvent event) throws UnknownHostException {
        return includeFilter.filter(event) &&
                excludeIpsFilter.filter(event) &&
                usersIncludeFilter.filter(event) &&
                usersExcludeFilter.filter(event);
    }
}

interface Filter<FirewallEvent> {
    boolean filter(FirewallEvent event) throws UnknownHostException;
}

class IpIncludeFilter implements Filter<FirewallEvent> {
    List<String> includeIpsRanges;
    List<String> includeIpSpesific;

    public IpIncludeFilter(String[] includeIps) {
        includeIpsRanges = new ArrayList<>();
        includeIpSpesific  = new ArrayList<>();
        if (includeIps == null) {
            return;
        }

        for (String ip : includeIps) {
            if (ip.contains("/")) {
                includeIpsRanges.add(ip);
            } else {
                includeIpSpesific.add(ip);
            }
        }
    }

    @Override
    public boolean filter(FirewallEvent firewallEvent) throws UnknownHostException {
        if(includeIpSpesific.isEmpty() && includeIpsRanges.isEmpty()) {
            return true;
        }
        for(String ip : includeIpSpesific) {
            if (ip.equals(firewallEvent.getSrc())) {
                return true;
            }
        }

        long ipNumber = IPUtils.ipToInt(firewallEvent.getSrc());
        for (String ipRange : includeIpsRanges) {
            String[] firstAndLast = IPUtils.getIpRange(ipRange);

            int firstIpVal = IPUtils.ipToInt(firstAndLast[0]);
            int lastIpVal = IPUtils.ipToInt(firstAndLast[1]);

            if (firstIpVal <= ipNumber && lastIpVal >= ipNumber) {
                return true;
            }
        }

        return false;
    }
}

class ExcludeIpsFilter implements Filter<FirewallEvent> {
    List<String> excludeIpsRanges;
    List<String> excludeIpSpesific;

    public ExcludeIpsFilter(String[] excludeIps) {
        excludeIpsRanges = new ArrayList<>();
        excludeIpSpesific  = new ArrayList<>();

        if (excludeIps == null) {
            return;
        }

        for (String ip : excludeIps) {
            if (ip.contains("/")) {
                excludeIpsRanges.add(ip);
            } else {
                excludeIpSpesific.add(ip);
            }
        }
    }

    @Override
    public boolean filter(FirewallEvent firewallEvent) throws UnknownHostException {
        if(excludeIpSpesific.isEmpty() && excludeIpsRanges.isEmpty()) {
            return true;
        }

        for(String ip : excludeIpSpesific) {
            if (ip.equals(firewallEvent.getSrc())) {
                return false;
            }
        }

        long ipNumber = IPUtils.ipToInt(firewallEvent.getSrc());
        for (String ipRange : excludeIpsRanges) {
            String[] firstAndLast = IPUtils.getIpRange(ipRange);

            int firstIpVal = IPUtils.ipToInt(firstAndLast[0]);
            int lastIpVal = IPUtils.ipToInt(firstAndLast[1]);

            if (firstIpVal <= ipNumber && lastIpVal >= ipNumber) {
                return false;
            }
        }

        return true;
    }
}

class UsersIncludeFilter implements Filter<FirewallEvent> {
    String includeUsersRegex;

    public UsersIncludeFilter(String includeUsersRegex) {
        this.includeUsersRegex = includeUsersRegex;
    }

    @Override
    public boolean filter(FirewallEvent firewallEvent) {
        if (includeUsersRegex.isEmpty()) {
            return true;
        }
        return firewallEvent.getUser().contains(includeUsersRegex);
    }
}

class UsersExcludeFilter implements Filter<FirewallEvent> {
    String excludeUsersRegex;

    public UsersExcludeFilter(String excludeUsersRegex) {
        this.excludeUsersRegex = excludeUsersRegex;
    }

    @Override
    public boolean filter(FirewallEvent firewallEvent) {
        if (excludeUsersRegex.isEmpty()) {
            return true;
        }
        return !firewallEvent.getUser().contains(excludeUsersRegex);
    }
}

class IPUtils {
    public static int ipToInt(String ip) throws UnknownHostException {
        byte[] bytes = InetAddress.getByName(ip).getAddress();
        int result = 0;
        for (byte b : bytes) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }

    public static String intToIp(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }

    public static String[] getIpRange(String cidr) throws UnknownHostException {
        String[] parts = cidr.split("/");
        String ip = parts[0];
        int prefix = Integer.parseInt(parts[1]);

        int ipInt = ipToInt(ip);
        int mask = ~((1 << (32 - prefix)) - 1);

        int network = ipInt & mask;
        int broadcast = network | ~mask;

        return new String[] {
                intToIp(network),
                intToIp(broadcast)
        };
    }
}

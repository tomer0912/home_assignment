package src;

import CloudServices.CloudServicesRepo;
import Enrich.EventEnricher;
import Events.Config;
import Events.EventRetriever;
import Events.FirewallEvent;
import Filter.EventFilter;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        CloudServicesRepo repo = new CloudServicesRepo();
        EventEnricher enricher = new EventEnricher();
        EventFilter filter = new EventFilter(new String[] {"211.168.230.0/24", "8.8.8.0/24"},
                new String[] {"1.1.2.0/24", "8.8.8.8"},
                "", "sys");

        Map<String, Set<String>> cloudServicesToIps = new HashMap<>();

        try (EventRetriever iterator = new EventRetriever()) {
            while (iterator.hasNext()) {
                FirewallEvent event = iterator.next();

                //filtering events that doesn't comply with filters
                if (!filter.shouldProcess(event)) {
                    continue;
                }

                // comment out for better performance
                //if(event.getDomain() == null) {
                //    continue;
                //}
                //enriching event - reverse DNS lookup in case the log doesn't contain domain
                enricher.enrich(event);

                // adding internal IP to result.
                String cloudServiceName = repo.getNameByDomain(event.getDomain());
                if (cloudServicesToIps.get(cloudServiceName) == null) {
                    Set<String> ips = new HashSet<>();
                    cloudServicesToIps.put(cloudServiceName, ips);
                }
                cloudServicesToIps.get(cloudServiceName).add(event.getSrc());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        /* printing the results */
        for (Map.Entry<String, Set<String>> entry : cloudServicesToIps.entrySet()) {
            String cloudServiceName = entry.getKey();
            Set<String> ips = entry.getValue();

            System.out.println(cloudServiceName + ": " + ips.toString());
        }


        /* deleting the unzipped file*/
        File file = new File(Config.EVENTS_FILE_PATH);
        if (file.delete()) {
            System.out.println("File deleted successfully.");
        } else {
            System.out.println("Failed to delete the file.");
        }


    }
}
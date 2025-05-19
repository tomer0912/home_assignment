package src.CloudServices;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CloudServicesRepo {
    List<CloudService> cloudServices = new ArrayList<CloudService>();
    public CloudServicesRepo() {
        String filePath = Config.DB_FILE_PATH;

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Split CSV by comma
                String[] values = line.split(",");
                if (values[0].startsWith("Service")) {
                    continue;
                }

                CloudService cs = new CloudService(values[0], values[1], values[2], values[3], values[4].equals("Yes"));
                cloudServices.add(cs);
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public String getNameByDomain(String domain) {
        for (CloudService cs : cloudServices) {
            if (cs.domain.equals(domain)) {
                return cs.name;
            }
        }

        return null;
    }
}

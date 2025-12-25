package ch.zhaw.securitylab.marketplace.test;

import ch.zhaw.securitylab.marketplace.model.Product;
import ch.zhaw.securitylab.marketplace.model.Purchase;
import ch.zhaw.securitylab.marketplace.model.Credentials;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class Test {
    private final static String CREDENTIALS_SALES = "alice:rabbit";
    private final static String CREDENTIALS_MARKETING = "robin:arrow";
    private final static String CREDENTIALS_PRODUCTMANAGER = "luke:force";
    private final static String CREDENTIALS_BURGERMAN = "bob:patrick";
    private final static String CREDENTIALS_WRONG_PASSWORD_SALES = "alice:wrongpassword";
    private final static String CREDENTIALS_WRONG_PASSWORD_BURGERMAN = "bob:wrongpassword";
    private final static String CREDENTIALS_WRONG_USER = "wronguser:wrongpassword";
    private final static String BASE_URL = "https://localhost:8443/rest/";
    private static HttpClient httpClient;
    private static String jwtSales;
    private static String jwtMarketing;
    private static String jwtProductManager;
    private final static String JWT_INVALID_SIGNATURE = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJNYXJrZXRwbGFjZSIsInN1YiI6ImFsaWNlIiwiZXhwIjoxNjcxNTU1NzQ0fQ.p6q9Uhi7Af7T03URMIUbE7MAhMeUcx-f4uPFZc6cz34";
    private final static String JWT_EXPIRED_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJNYXJrZXRwbGFjZSIsInN1YiI6ImFsaWNlIiwiZXhwIjoxNzQwMjI5MzMzfQ.-WnfqQkougMdswoLJBOiLTWLBPCDsIPFfCj3syZ-Zbw";
    private final static boolean VERBOSE = true;
    private final static SummaryPrinter SUMMARY_PRINTER = new SummaryPrinter();

    public static void main(String[] args) throws Exception {
        String category;
        HttpResponse<String> response;
        BooleanString result;
               
        // Create HttpClient
        httpClient = createHttpClient();

        // Authenticate
        category = "POST auth/authenticate tests";
        System.out.println(category + ":\n");
        response = postAuthenticate(CREDENTIALS_WRONG_PASSWORD_SALES);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_USER);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_SALES);
        result = printResults(response, 200, "jwt", null, VERBOSE, category);
        if (result.bool) {
            jwtSales = getJWT(result.string);
        }
        response = postAuthenticate(CREDENTIALS_MARKETING);
        result = printResults(response, 200, "jwt", null, VERBOSE, category);
        if (result.bool) {
            jwtMarketing = getJWT(result.string);
        }
        response = postAuthenticate(CREDENTIALS_PRODUCTMANAGER);
        result = printResults(response, 200, "jwt", null, VERBOSE, category);
        if (result.bool) {
            jwtProductManager = getJWT(result.string);
        }

        // Print authentication tokens
        if (VERBOSE) {
            System.out.println("JWTs:");
            System.out.println(JWT_INVALID_SIGNATURE);
            System.out.println(JWT_EXPIRED_TOKEN);
            System.out.println(jwtSales);
            System.out.println(jwtMarketing);
            System.out.println(jwtProductManager);
            System.out.println();
        }

        // GET products
        category = "GET public/products tests";
        System.out.println(category + ":\n");
        response = getProducts("", false, "");
        printResults(response, 200, "Ferrari", null, VERBOSE, category);
        response = getProducts("DVD", false, "");
        printResults(response, 200, "DVD", null, VERBOSE, category);
        response = getProducts("nomatch", false, "");
        printResults(response, 200, null, "0001", VERBOSE, category);
        response = getProducts("", true, jwtSales);
        printResults(response, 200, "Ferrari", null, VERBOSE, category);
        response = getProducts("looooooooooooooooooooooooooooooooooooooooooooooooooo", false, "");
        printResults(response, 400, "valid search", null, VERBOSE, category);

        // POST purchases
        category = "POST public/purchases tests";
        System.out.println(category + ":\n");
        List<Integer> articles = new ArrayList<>();
        articles.add(1);
        articles.add(3);
        response = postPurchase("Max", "Meier", "1111 2222 3333 4444", articles, false, "");
        printResults(response, 204, null, null, VERBOSE, category);
        articles.add(5);
        response = postPurchase("Max", "Meier", "1111 2222 3333 4444", articles, false, "");
        printResults(response, 204, null, null, VERBOSE, category);
        response = postPurchase("M", "M", "1111 2222 3333 4444", articles, false, "");
        printResults(response, 400, "valid first", null, VERBOSE, category);
        response = postPurchase("Max", "Meier", "1111 2222 3333 4445", articles, false, "");
        printResults(response, 400, "valid credit", null, VERBOSE, category);
        articles.clear();
        articles.add(101);
        articles.add(303);
        response = postPurchase("Moritz", "Mueller", "1111 2222 3333 4444", articles, false, "");
        printResults(response, 400, "no valid product", null, VERBOSE, category);
        articles.clear();
        response = postPurchase("Moritz", "Mueller", "1111 2222 3333 4444", articles, false, "");
        printResults(response, 400, "no valid product", null, VERBOSE, category);
        
        // GET admin/purchases
        category = "GET admin/purchases tests";
        System.out.println(category + ":\n");
        response = getAdminPurchases(false, "");
        printResults(response, 401, "required", null, VERBOSE, category);
        response = getAdminPurchases(true, JWT_INVALID_SIGNATURE);
        printResults(response, 401, "required", null, VERBOSE, category);
        response = getAdminPurchases(true, JWT_EXPIRED_TOKEN);
        printResults(response, 401, "required", null, VERBOSE, category);
        response = getAdminPurchases(true, jwtSales);
        printResults(response, 200, "totalPrice", null, VERBOSE, category);
        response = getAdminPurchases(true, jwtMarketing);
        printResults(response, 200, "totalPrice", null, VERBOSE, category);

        // DELETE admin/purchases
        category = "DELETE admin/purchases tests";
        System.out.println(category + ":\n");
        response = deleteAdminPurchase("1", false, "");
        printResults(response, 401, "required", null, VERBOSE, category);
        response = deleteAdminPurchase("1", true, JWT_INVALID_SIGNATURE);
        printResults(response, 401, "required", null, VERBOSE, category);
        response = deleteAdminPurchase("1", true, jwtSales);
        printResults(response, 204, null, null, VERBOSE, category);
        response = deleteAdminPurchase("1", true, jwtMarketing);
        printResults(response, 403, "denied", null, VERBOSE, category);
        response = deleteAdminPurchase("99999", true, jwtSales);
        printResults(response, 400, "not exist", null, VERBOSE, category);
        response = deleteAdminPurchase("9999999", true, jwtSales);
        printResults(response, 400, "between", null, VERBOSE, category);
        response = deleteAdminPurchase("9999999999999", true, jwtSales);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = deleteAdminPurchase("foo", true, jwtSales);
        printResults(response, 400, "Invalid", null, VERBOSE, category);

        // GET admin/products
        category = "GET admin/products tests";
        System.out.println(category + ":\n");
        response = getAdminProducts(true, JWT_INVALID_SIGNATURE);
        printResults(response, 401, "required", null, VERBOSE, category);
        response = getAdminProducts(true, jwtMarketing);
        printResults(response, 403, null, null, VERBOSE, category);
        response = getAdminProducts(true, jwtProductManager);
        printResults(response, 200, "username", null, VERBOSE, category);

        // POST admin/products
        category = "POST admin/products tests";
        System.out.println(category + ":\n");
        response = postAdminProducts("description", new BigDecimal("5.55"), false, "");
        printResults(response, 401, "required", null, VERBOSE, category);
        response = postAdminProducts("description", new BigDecimal("5.55"), true, JWT_INVALID_SIGNATURE);
        printResults(response, 401, "required", null, VERBOSE, category);
        response = postAdminProducts("description", new BigDecimal("5.55"), true, jwtSales);
        printResults(response, 403, "denied", null, VERBOSE, category);
        response = postAdminProducts("shorty", new BigDecimal("5.555"), true, jwtProductManager);
        printResults(response, 400, "valid description", null, VERBOSE, category);
        response = postAdminProducts("description", new BigDecimal("-1"), true, jwtProductManager);
        printResults(response, 400, "valid price", null, VERBOSE, category);
        response = postAdminProducts("description", new BigDecimal("1000000"), true, jwtProductManager);
        printResults(response, 400, "valid price", null, VERBOSE, category);
        response = postAdminProducts("description", new BigDecimal("5.55"), true, jwtProductManager);
        printResults(response, 204, null, null, VERBOSE, category);

        // DELETE admin/products
        category = "DELETE admin/products tests";
        System.out.println(category + ":\n");
        response = deleteAdminProduct("4", false, "");
        printResults(response, 401, "required", null, VERBOSE, category);
        response = deleteAdminProduct("4", true, JWT_INVALID_SIGNATURE);
        printResults(response, 401, "required", null, VERBOSE, category);
        response = deleteAdminProduct("4", true, jwtSales);
        printResults(response, 403, "denied", null, VERBOSE, category);
        response = deleteAdminProduct("4", true, jwtProductManager);
        printResults(response, 403, "own products", null, VERBOSE, category);
        response = deleteAdminProduct("3", true, jwtProductManager);
        printResults(response, 204, null, null, VERBOSE, category);
        response = deleteAdminProduct("99999", true, jwtProductManager);
        printResults(response, 400, "not exist", null, VERBOSE, category);
        response = deleteAdminProduct("9999999", true, jwtProductManager);
        printResults(response, 400, "between", null, VERBOSE, category);
        response = deleteAdminProduct("9999999999999", true, jwtProductManager);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = deleteAdminProduct("foo", true, jwtProductManager);
        printResults(response, 400, "Invalid", null, VERBOSE, category);

        // Login Throttling
        category = "Login Throttling tests";
        System.out.println(category + ":\n");
        response = postAuthenticate(CREDENTIALS_BURGERMAN);
        printResults(response, 200, "jwt", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_PASSWORD_BURGERMAN);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_PASSWORD_BURGERMAN);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_PASSWORD_BURGERMAN);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_PASSWORD_BURGERMAN);
        printResults(response, 400, "minute", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_BURGERMAN);
        printResults(response, 400, "minute", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_USER);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_USER);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_USER);
        printResults(response, 400, "Invalid", null, VERBOSE, category);
        response = postAuthenticate(CREDENTIALS_WRONG_USER);
        printResults(response, 400, "Invalid", null, VERBOSE, category);

        // Print summary
        System.out.print(SUMMARY_PRINTER.toString());
    }

    private static HttpResponse<String> postAuthenticate(String credential) throws Exception {
        String[] credentialArray = credential.split(":");
        String username = credentialArray[0];
        String password = credentialArray[1];
        System.out.println("POST auth/authenticate " + username + "|" + password);
        Credentials credentialDto = new Credentials();
        credentialDto.setUsername(username);
        credentialDto.setPassword(password);
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = ow.writeValueAsString(credentialDto);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "auth/authenticate"))
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(json))
                .build();
        return httpClient.send(request, BodyHandlers.ofString());    
    }
    
    private static HttpResponse<String> getProducts(String description, boolean auth, String credentials) throws Exception {
        System.out.println("GET public/products, description = '" + description + "', auth = " + auth
                + ", credentials = '" + credentials + "'");
        String uriString = BASE_URL + "public/products";
        if (!description.equals("")) {
            uriString = uriString + "?description=" + description;
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(uriString))
                .header("Content-Type", "application/json")
                .GET();
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());  
    }

    private static HttpResponse<String> postPurchase(String firstname, String lastname, String creditCardNumber,
            List<Integer> productIDs, boolean auth, String credentials) throws Exception {
        String productIDsString = "";
        for (int id : productIDs) {
            if (!productIDsString.equals("")) {
                productIDsString += ",";
            }
            productIDsString += id;
        }
        System.out.println("POST public/purchases " + firstname + "|" + lastname + "|" + creditCardNumber + "|"
                + productIDsString + ", auth = " + auth + ", credentials = '" + credentials + "'");
        Purchase purchaseDto = new Purchase();
        purchaseDto.setFirstname(firstname);
        purchaseDto.setLastname(lastname);
        purchaseDto.setCreditCardNumber(creditCardNumber);
        purchaseDto.setProductIDs(productIDs);
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = ow.writeValueAsString(purchaseDto);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "public/purchases"))
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(json));
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());  
    }

    private static HttpResponse<String> getAdminPurchases(boolean auth, String credentials) throws Exception {
        System.out.println("GET admin/purchases, auth = " + auth + ", credentials = '" + credentials + "'");
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "admin/purchases"))
                .header("Content-Type", "application/json")
                .GET();
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());  
    }

    private static HttpResponse<String> deleteAdminPurchase(String purchaseId, boolean auth, String credentials) throws Exception {
        System.out.println("DELETE admin/purchases, id = " + purchaseId + ", auth = " + auth
                + ", credentials = '" + credentials + "'");
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "admin/purchases/" + purchaseId))
                .header("Content-Type", "application/json")
                .DELETE();
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());  
    }

    private static HttpResponse<String> getAdminProducts(boolean auth, String credentials) throws Exception {
        System.out.println("GET admin/products, auth = " + auth + ", credentials = '" + credentials + "'");
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "admin/products"))
                .header("Content-Type", "application/json")
                .GET();
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());
    }

    private static HttpResponse<String> postAdminProducts(String description, BigDecimal price,
                                                          boolean auth, String credentials) throws Exception {
        System.out.println("POST admin/products " + description + "|" + price
                + ", auth = " + auth + ", credentials = '" + credentials + "'");
        Product productDto = new Product();
        productDto.setDescription(description);
        productDto.setPrice(price);
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = ow.writeValueAsString(productDto);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "admin/products"))
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(json));
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());
    }

    private static HttpResponse<String> deleteAdminProduct(String productId, boolean auth, String credentials) throws Exception {
        System.out.println("DELETE admin/products, id = " + productId + ", auth = " + auth
                + ", credentials = '" + credentials + "'");
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "admin/products/" + productId))
                .header("Content-Type", "application/json")
                .DELETE();
        if (auth) {
            builder.header("Authorization", createAuthHeader(credentials));
        }
        return httpClient.send(builder.build(), BodyHandlers.ofString());
    }

    private static HttpClient createHttpClient() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new CustomX509TrustManager()}, null);
        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .sslContext(sslContext).build();
        /*HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .sslContext(sslContext).proxy(ProxySelector.of(new InetSocketAddress("localhost", 8008))).build();*/
        return client;
    }  
    
    private static String createAuthHeader(String credentials) {
        return "Bearer " + credentials;
    }

    private static BooleanString printResults(HttpResponse<String> response, int statusCode,
            String included, String notIncluded, boolean verbose, String category) {
        if (verbose) {
            printHeadersAndBody(response);
        }
        String body = response.body();
        boolean passed = true;
        if ((response.statusCode() != statusCode)
                || (included != null && !body.contains(included))
                || (notIncluded != null && body.contains(notIncluded))) {
            passed = false;
        }
        if (passed) {
            SUMMARY_PRINTER.Passed(category);
            System.out.println("=> PASSED");
        } else {
            SUMMARY_PRINTER.Failed(category);
            System.out.println("=> FAILED");
        }
        System.out.println();
        return new BooleanString(passed, body);
    }

    private static void printHeadersAndBody(HttpResponse<String> response) {
        System.out.println("Status code: " + response.statusCode());
        Optional<String> headerContentType = response.headers().firstValue("Content-Type");
        if (headerContentType.isPresent()) {
            System.out.println("Media type: " + headerContentType.get());
        } else {
            System.out.println("Media type: ");
        }
        System.out.println("Body: " + response.body());
    }

    private static String getJWT(String token) {
        return token.substring(8, token.indexOf("\",\"role\":"));
    }
}

class BooleanString {
    boolean bool;
    String string;

    public BooleanString(boolean bool, String string) {
        this.bool = bool;
        this.string = string;
    }
}

class SummaryPrinter {
    private final LinkedHashMap<String, Results> summaryMap = new LinkedHashMap<>();

    public void Passed(String category) {
        this.getResults(category).Passed();
    }

    public void Failed(String category) {
        this.getResults(category).Failed();
    }

    private Results getResults(String category) {
        if (!summaryMap.containsKey(category)) {
            summaryMap.put(category, new Results());
        }
        return summaryMap.get(category);
    }

    @Override
    public String toString() {
        int passed = 0, failed = 0;
        StringBuilder summary = new StringBuilder();
        Formatter formatter = new Formatter(summary, Locale.US);

        summary.append("SUMMARY\n");
        summary.append(new String(new char[76]).replace("\0", "="));
        summary.append("\n");

        for (HashMap.Entry<String, Results> entry : summaryMap.entrySet()) {
            formatter.format("%-50s%10s%3d%10s%3d", entry.getKey(), "Passed:", + entry.getValue().getPassed(), "Failed:", entry.getValue().getFailed());
            summary.append("\n");
            passed += entry.getValue().getPassed();
            failed += entry.getValue().getFailed();
        }

        summary.append(new String(new char[76]).replace("\0", "="));
        summary.append("\n");
        formatter.format("%-50s%10s%3d%10s%3d", "TOTAL", "Passed:", +passed, "Failed:", failed);

        return summary.toString();
    }

    private class Results {
        private int passed = 0;
        private int failed = 0;

        public int getPassed() {
            return passed;
        }

        public int getFailed() {
            return failed;
        }

        public void Passed() {
            this.passed++;
        }

        public void Failed() {
            this.failed++;
        }
    }
}

class CustomX509TrustManager implements X509TrustManager {

    @Override
    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    @Override
    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        // Empty as returning without throwing an exception means the  check succeeded
    }

    @Override
    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        // Empty as returning without throwing an exception means the  check succeeded
    }
}
package burp.extension.models;

import java.awt.Dimension;
import java.awt.List;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse.*;
import burp.api.montoya.http.message.params.*;
import burp.api.montoya.http.message.requests.HttpRequest;
public class MarkdownWriter {
    public static void createPageMd(String dirPath, PlainTextRequestResponse entry) {
        try (FileWriter writer = new FileWriter(dirPath + entry.getFileName() + " - " + entry.getMethod() + ".md", true)) {
            writer.write("#### Link:" + entry.getUrl() + "\r\n\r\n---\r\n\r\n");
            writer.write("#### Description: \r\n\r\nNEEDS MANUAL UPDATE\r\n\r\n---\r\n\r\n");
            writer.write("#### Inputs: \r\n\r\n");
            for (ParsedHttpParameter param : entry.getParameters()) {
                writer.write("- " + param.name() + "\r\n");
            }
            writer.write("\r\n#### Sample Request: \r\n\r\n");
            writer.write("```HTTP\r\n" + entry.getFullRequest());
            writer.write("\r\n\r\n```\r\n\r\n");
            writer.write("---\r\n\r\n");
            writer.write("#### Sample Response: \r\n\r\n");
            writer.write("```HTTP\r\n" + entry.getResponseToHead() + "\r\n\r\n[TRUNCATED]\r\n\r\n```\r\n\r\n---\r\n\r\n");
            if (entry.getComments() != null && !entry.getComments().isEmpty()) {
                writer.write("#### Found Comments: \r\n\r\n");
                for(String comment : entry.getComments()) {
                    writer.write("```HTML\r\n\r\n" + comment + "\r\n```\r\n\r\n");
                }
                writer.write("\r\n---\r\n\r\n");
            }
            if (entry.getHiddenElements() != null && !entry.getHiddenElements().isEmpty()) {
                writer.write("#### Found Hidden Elements: \r\n\r\n");
                for(String hiddenEl : entry.getHiddenElements()) {
                    writer.write("```HTML\r\n\r\n" + hiddenEl + "\r\n```\r\n\r\n");
                }
                writer.write("\r\n---\r\n\r\n");
            }
            if (entry.getInlineJS() != null && !entry.getInlineJS().isEmpty()) {
                writer.write("#### Found Inline JS: \r\n\r\n");
                for(String inlineJS : entry.getInlineJS()) {
                    writer.write("```HTML\r\n\r\n" + inlineJS + "\r\n```\r\n\r\n");
                }
                writer.write("\r\n---\r\n\r\n");
            }
            if (entry.getForms() != null && !entry.getForms().isEmpty()) {
                writer.write("#### Found Forms: \r\n\r\n");
                for(String form : entry.getForms()) {
                    writer.write("```HTML\r\n\r\n" + form + "\r\n```\r\n\r\n");
                }
                writer.write("\r\n---\r\n\r\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void appendToResourcesLog(String path, String content) {
        try (FileWriter writer = new FileWriter(path, true)) {  // append = true
            writer.write("- " + content);
            writer.write(System.lineSeparator());  // newline
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void appendToSiteLog(String url, HttpRequestResponse reqRes, boolean isResource, String path) {
        System.out.println("Hi from appendToSiteLog");
        System.out.println(isResource);
        System.out.println(url);
        if (isResource) return;
        System.out.println("Adding " + url + " to sitemap.md");
        HttpRequest request = reqRes.request();
        String urlPath = request.path();                  // /product/stock
        String method = request.method().toString();      // GET, POST, etc.
        String fullUrl = request.url();                   // https://example.com/product/stock?productId=1

        // Separate path and query
        String[] urlParts = fullUrl.split("\\?");
        String basePath = urlParts[0];  // https://example.com/product/stock
        String query = urlParts.length > 1 ? urlParts[1] : null;

        String[] segments = basePath.replace("https://", "")
                                    .replace("http://", "")
                                    .split("/");

        Set<String> existingLines = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                existingLines.add(line.trim());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        StringBuilder currentPath = new StringBuilder();
        String domain = segments[0]; // e.g., ginandjuice.shop

        // Start from root after domain
        try (FileWriter writer = new FileWriter(path, true)) {
            if (!existingLines.contains("### /" + domain)) {
                writer.write("### /" + domain + System.lineSeparator());
                existingLines.add("### /" + domain);
            }

            for (int i = 1; i < segments.length; i++) {
                String part = segments[i];
                if (part.isEmpty()) continue;

                currentPath.append("/").append(part);
                int indentLevel = i;
                String indent = "\t".repeat(indentLevel);
                String line = indent + "/" + part;

                if (!existingLines.contains(line)) {
                    writer.write(line + System.lineSeparator());
                    existingLines.add(line);
                }
            }

            // Add query parameters under path if present
            if (query != null && !query.isEmpty()) {
                int indentLevel = segments.length;
                String indent = "\t".repeat(indentLevel);
                String queryLine = indent + "?" + query;

                if (!existingLines.contains(queryLine)) {
                    writer.write(queryLine + System.lineSeparator());
                    existingLines.add(queryLine);
                }
            }

            // Add method indicator
            String methodLine = "\t".repeat(segments.length) + method;
            if (!existingLines.contains(methodLine)) {
                writer.write(methodLine + System.lineSeparator());
                existingLines.add(methodLine);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

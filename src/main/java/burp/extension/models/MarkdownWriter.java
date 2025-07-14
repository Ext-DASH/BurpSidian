package burp.extension.models;

import java.io.FileWriter;
import java.io.IOException;

import burp.api.montoya.http.message.params.*;
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
            writer.write("```\r\n\r\n");
            writer.write("---\r\n\r\n");
            writer.write("#### Sample Response: \r\n\r\n");
            writer.write("```HTTP\r\n" + entry.getResponseToHead() + "\r\n[TRUNCATED]\r\n```\r\n\r\n---\r\n\r\n");
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
}
